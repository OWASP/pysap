# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# Copyright (C) 2015 by Martin Gallo, Core Security
#
# The library was designed and developed by Martin Gallo from the Security
# Consulting Services team of Core Security.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# ==============

# Standard imports
import stat
from zlib import crc32
from struct import pack
from datetime import datetime
from os import stat as os_stat
from cStringIO import StringIO
# External imports
from scapy.packet import Packet
from scapy.fields import (ByteField, ByteEnumField, LEIntField, FieldLenField,
                          PacketField, StrFixedLenField, PacketListField,
                          ConditionalField, LESignedIntField)
# Custom imports
from pysap.utils import (PacketNoPadded, StrNullFixedLenField)
from pysapcompress import (decompress, compress, ALG_LZH, CompressError)


# Filemode code obtained from Python 3 stat.py
_filemode_table = (
    ((stat.S_IFLNK,         "l"),
     (stat.S_IFREG,         "-"),
     (stat.S_IFBLK,         "b"),
     (stat.S_IFDIR,         "d"),
     (stat.S_IFCHR,         "c"),
     (stat.S_IFIFO,         "p")),

    ((stat.S_IRUSR,         "r"),),
    ((stat.S_IWUSR,         "w"),),
    ((stat.S_IXUSR|stat.S_ISUID, "s"),
     (stat.S_ISUID,         "S"),
     (stat.S_IXUSR,         "x")),

    ((stat.S_IRGRP,         "r"),),
    ((stat.S_IWGRP,         "w"),),
    ((stat.S_IXGRP|stat.S_ISGID, "s"),
     (stat.S_ISGID,         "S"),
     (stat.S_IXGRP,         "x")),

    ((stat.S_IROTH,         "r"),),
    ((stat.S_IWOTH,         "w"),),
    ((stat.S_IXOTH|stat.S_ISVTX, "t"),
     (stat.S_ISVTX,         "T"),
     (stat.S_IXOTH,         "x"))
)


def filemode(mode):
    """Convert a file's mode to a string of the form '-rwxrwxrwx'."""
    perm = []
    for table in _filemode_table:
        for bit, char in table:
            if mode & bit == bit:
                perm.append(char)
                break
        else:
            perm.append("-")
    return "".join(perm)


class SAPCARCompressedFileFormat(PacketNoPadded):
    """SAP CAR compressed blob

    This is used for decompressing blobs inside the file info
    packets.
    """
    name = "SAP CAR Archive Compressed file"

    fields_desc = [
        LEIntField("compressed_length", None),
        LEIntField("uncompress_length", None),
        ByteEnumField("algorithm", 0x12, {0x12: "LZH", 0x10: "LZC"}),
        StrFixedLenField("magic_bytes", "\x1f\x9d", 2),
        ByteField("special", 2),
        StrFixedLenField("blob", None, length_from=lambda x: x.compressed_length - 8),
    ]


class SAPCARArchiveFilev200Format(PacketNoPadded):
    """SAP CAR file information format

    This is ued to parse files inside a SAP CAR archive.
    """
    name = "SAP CAR Archive File 2.00"

    fields_desc = [
        StrFixedLenField("type", "RG", 2),
        LEIntField("perm_mode", 0),
        LEIntField("file_length", 0),
        LEIntField("unknown1", 0),
        LEIntField("unknown2", 0),
        LEIntField("timestamp", 0),
        StrFixedLenField("unknown3", None, 10),
        FieldLenField("filename_length", None, length_of="filename", fmt="<H"),
        StrFixedLenField("filename", None, length_from=lambda x: x.filename_length),
        ConditionalField(ByteField("unknown4", 0), lambda x: x.type == "RG"),
        ConditionalField(ByteField("unknown5", 0), lambda x: x.type == "RG"),
        ConditionalField(PacketField("compressed", None, SAPCARCompressedFileFormat), lambda x: x.type == "RG"),
        ConditionalField(LESignedIntField("checksum", 0), lambda x: x.type == "RG"),
    ]


class SAPCARArchiveFilev201Format(PacketNoPadded):
    """SAP CAR file information format

    This is ued to parse files inside a SAP CAR archive.
    """
    name = "SAP CAR Archive File 2.01"

    fields_desc = [
        StrFixedLenField("type", "RG", 2),
        LEIntField("perm_mode", 0),
        LEIntField("file_length", 0),
        LEIntField("unknown1", 0),
        LEIntField("unknown2", 0),
        LEIntField("timestamp", 0),
        StrFixedLenField("unknown3", None, 10),
        FieldLenField("filename_length", None, length_of="filename", fmt="<H"),
        StrNullFixedLenField("filename", None, length_from=lambda x: x.filename_length - 1),
        ConditionalField(ByteField("unknown4", 0), lambda x: x.type == "RG"),
        ConditionalField(ByteField("unknown5", 0), lambda x: x.type == "RG"),
        ConditionalField(PacketField("compressed", None, SAPCARCompressedFileFormat), lambda x: x.type == "RG"),
        ConditionalField(LESignedIntField("checksum", 0), lambda x: x.type == "RG"),
    ]


SAPCAR_VERSION_200 = "2.00"
"""SAP CAR file format version 2.00 string"""

SAPCAR_VERSION_201 = "2.01"
"""SAP CAR file format version 2.01 string"""

sapcar_archive_file_versions = {
    SAPCAR_VERSION_200: SAPCARArchiveFilev200Format,
    SAPCAR_VERSION_201: SAPCARArchiveFilev201Format,
}
"""SAP CAR file format versions"""


class SAPCARArchiveFormat(Packet):
    """SAP CAR file format

    This is used to parse SAP CAR archive files.
    """
    name = "SAP CAR Archive"

    fields_desc = [
        StrFixedLenField("eyecatcher", "CAR ", 4),
        StrFixedLenField("version", SAPCAR_VERSION_201, 4),
        ConditionalField(PacketListField("files0", None, SAPCARArchiveFilev200Format), lambda x: x.version == SAPCAR_VERSION_200),
        ConditionalField(PacketListField("files1", None, SAPCARArchiveFilev201Format), lambda x: x.version == SAPCAR_VERSION_201),
    ]


class SAPCARArchiveFile(object):
    """Proxy class that can be used to access a file inside a SAP CAR
    archive and obtain its properties.
    """

    # Instance attributes
    _file_format = None

    def __init__(self, file_format=None):
        """Construct the file proxy object from a L{SAPCARArchiveFilev200Format}
        or L{SAPCARArchiveFilev201Format} object.

        :param file_format: file format object
        :type file_format: Packet
        """
        self._file_format = file_format

    @property
    def filename(self):
        """The name of the file.

        :return: name of the file
        :rtype: basestring
        """
        return self._file_format.filename

    @filename.setter
    def filename(self, filename):
        self._file_format.filename = filename

    @property
    def size(self):
        """The size of the file.

        :return: size of the file
        :rtype: int
        """
        return self._file_format.file_length

    @size.setter
    def size(self, file_length):
        self._file_format.file_length = file_length

    @property
    def permissions(self):
        """The permissions of the file.

        :return: permissions in human-readable format
        :rtype: string
        """
        return filemode(self._file_format.perm_mode)

    @permissions.setter
    def permissions(self, perm_mode):
        self._file_format.perm_mode = perm_mode

    @property
    def timestamp(self):
        """The timestamp of the file.

        :return: timestamp in human-readable format
        :rtype: string
        """
        return datetime.fromtimestamp(self._file_format.timestamp).strftime('%d %b %Y %H:%M')

    @timestamp.setter
    def timestamp(self, timestamp):
        self._file_format.timestamp = timestamp

    @property
    def checksum(self):
        """The checksum of the file.

        :return: checksum
        :rtype: int
        """
        return self._file_format.checksum

    @checksum.setter
    def checksum(self, checksum):
        self._file_format.checksum = checksum

    @classmethod
    def calculate_checksum(cls, data):
        """Calculates the CRC32 checksum of a given data string.
        """
        return -crc32(data, -1) - 1

    @classmethod
    def from_file(cls, filename, version=SAPCAR_VERSION_201, archive_filename=None):
        """Populates the file format object from an actual file on the
        local file system.

        :param filename: filename to build the file format object from
        :type filename: string

        :param version: version of the file to construct
        :type version: string

        :param archive_filename: filename to use inside the archive file
        :type archive_filename: string
        """

        # Read the file properties and its content
        stat = os_stat(filename)
        with open(filename, "rb") as fd:
            data = fd.read()

        # Compress the file content and build the compressed string
        try:
            (_, _, out_buffer) = compress(data, ALG_LZH)
        except CompressError:
            return None
        out_buffer = pack("<I", len(out_buffer)) + out_buffer

        # Check the version and grab the file format class
        if version not in sapcar_archive_file_versions:
            raise ValueError("Invalid version")
        ff = sapcar_archive_file_versions[version]

        # If an archive filename was not provided, use the actual filename
        if archive_filename is None:
            archive_filename = filename

        # Build the object and fill the fields
        archive_file = cls()
        archive_file._file_format = ff()
        archive_file._file_format.perm_mode = stat.st_mode
        archive_file._file_format.timestamp = stat.st_atime
        archive_file._file_format.file_length = stat.st_size
        archive_file._file_format.filename = archive_filename
        archive_file._file_format.filename_length = len(archive_filename)
        if ff == SAPCARArchiveFilev201Format:
            archive_file._file_format.filename_length += 1
        archive_file._file_format.compressed = SAPCARCompressedFileFormat(out_buffer)
        archive_file._file_format.checksum = cls.calculate_checksum(data)

        return archive_file

    @classmethod
    def from_archive_file(cls, archive_file, version=SAPCAR_VERSION_201):
        """Populates the file format object from another archive file object.

        :param archive_file: archive file object to build the file format object from
        :type archive_file: L{SAPCARArchiveFile}

        :param version: version of the file to construct
        :type version: string
        """

        if version not in sapcar_archive_file_versions:
            raise ValueError("Invalid version")
        ff = sapcar_archive_file_versions[version]

        new_archive_file = cls()
        new_archive_file._file_format = ff()
        new_archive_file._file_format.type = archive_file._file_format.type
        new_archive_file._file_format.perm_mode = archive_file._file_format.perm_mode
        new_archive_file._file_format.timestamp = archive_file._file_format.timestamp
        new_archive_file._file_format.file_length = archive_file._file_format.file_length
        new_archive_file._file_format.filename = archive_file._file_format.filename
        new_archive_file._file_format.filename_length = archive_file._file_format.filename_length
        new_archive_file._file_format.compressed = archive_file._file_format.compressed
        new_archive_file._file_format.checksum = archive_file._file_format.checksum
        return new_archive_file

    def open(self):
        """Opens the compressed file and returns a file-like object that
        can be used to access its uncompressed content.

        :return: file-like object with the uncompressed file content
        :rtype: file
        """
        compressed = self._file_format.compressed
        (_, _, out_buffer) = decompress(str(compressed)[4:], compressed.uncompress_length)
        return StringIO(out_buffer)

    def check_checksum(self):
        """Checks if the checksum of the file is valid.

        :return: if the checksum matches
        :rtype: bool
        """
        crc = self.calculate_checksum(self.open().read())
        return crc == self.checksum


class SAPCARArchive(object):
    """Proxy class that can be used to read SAP CAR archive files.
    """

    files = None
    filename = None

    # Instance attributes
    fd = None
    _files = None
    _sapcar = None

    def __init__(self, fil, mode="rb+", version=SAPCAR_VERSION_201):
        """Opens an archive file and allow access to it.

        :param fil: filename or file descriptor to open
        :type fil: string or file

        :param mode: mode to open the file
        :type mode: string

        :param version: archive file version to use when creating
        :type version: string
        """

        # Ensure version is withing supported versions
        if version not in sapcar_archive_file_versions:
            raise ValueError("Invalid version")

        # Ensure mode is within supported modes
        if mode not in ["r", "r+", "w", "w+", "rb", "rb+", "wb", "wb+"]:
            raise ValueError("Invalid mode")

        # Ensure file is open in binary mode
        if "b" not in mode:
            mode += "b"

        if isinstance(fil, (basestring, unicode)):
            self.filename = fil
            self.fd = open(fil, mode)
        else:
            self.filename = getattr(fil, "name", None)
            self.fd = fil

        if "r" in mode:
            self.read()
        else:
            self.create()
            self.version = version

    @property
    def files(self):
        """The list of file objects inside this archive file.

        :return: list of file objects
        :rtype: L{dict} of L{SAPCARArchiveFile}
        """
        fils = {}
        if self._files:
            for fil in self._files:
                fils[fil.filename] = SAPCARArchiveFile(fil)
        return fils

    @property
    def files_names(self):
        """The list of file names inside this archive file.

        :return: list of file names
        :rtype: L{list} of L{string}
        """
        return self.files.keys()

    @property
    def version(self):
        """The version of the archive file.

        :return: version
        :rtype: string
        """
        return self._sapcar.version

    @version.setter
    def version(self, version):
        if version not in sapcar_archive_file_versions:
            raise ValueError("Invalid version")
        # If version is different, we should convert each file
        if version != self._sapcar.version:
            fils = []
            for fil in self.files.values():
                new_file = SAPCARArchiveFile.from_archive_file(fil, version=version)
                fils.append(new_file._file_format)
                self._files.remove(fil._file_format)
            self._sapcar.version = version
            if self._files is None:
                self._files = []
            self._files.extend(fils)

    def read(self):
        """Reads the SAP CAR archive file and populates the files list.
        """
        self.fd.seek(0)
        self._sapcar = SAPCARArchiveFormat(self.fd.read())

    @property
    def _files(self):
        """The file format objects according to the version.

        :return: files format objects according to the version
        """
        if self.version == SAPCAR_VERSION_200:
            return self._sapcar.files0
        else:
            return self._sapcar.files1

    @_files.setter
    def _files(self, files):
        if self.version == SAPCAR_VERSION_200:
            self._sapcar.files0 = files
        else:
            self._sapcar.files1 = files

    def create(self):
        """Creates the structure for holding a new SAP CAR archive file.
        """
        self._sapcar = SAPCARArchiveFormat()

    def write(self):
        """Writes the SAP CAR archive file to the file descriptor.
        """
        self.fd.seek(0)
        self.fd.write(str(self._sapcar))
        self.fd.flush()

    def add_file(self, filename, archive_filename=None):
        """Adds a new file to the SAP CAR archive file.

        :param filename: name of the file to add
        :type filename: string

        :param archive_filename: name of the file to use in the archive
        :type archive_filename: string
        """
        fil = SAPCARArchiveFile.from_file(filename, self.version, archive_filename)
        self._files.append(fil._file_format)

    def open(self, filename):
        """Returns a file-like object that can be used to access a file
        inside the SAP CAR archive.

        :param filename: name of the file to open
        :return: a file-like object that can be used to access the decompressed file.
        """
        if filename not in self.files:
            raise Exception("Invalid filename")
        return self.files[filename].open()

    def close(self):
        """Close the file descriptor object associated to the archive file.
        """
        self.fd.close()
