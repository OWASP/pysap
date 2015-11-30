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
from datetime import datetime
from os import stat as os_stat
from cStringIO import StringIO
# External imports
from scapy.packet import Packet
from scapy.fields import (ByteField, ByteEnumField, LEIntField, FieldLenField,
                          PacketField, StrFixedLenField, PacketListField,
                          ConditionalField)
# Custom imports
from pysap.utils import (PacketNoPadded, StrNullFixedLenField)
from pysapcompress import decompress, compress, ALG_LZH, CompressError


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
    name = "SAP CAR Archive File"

    fields_desc = [
        StrFixedLenField("unknown0", None, 2),
        LEIntField("perm_mode", 0),
        LEIntField("unknown1", 0),  # some kind of length
        LEIntField("unknown2", 0),
        LEIntField("unknown3", 0),
        LEIntField("timestamp", 0),
        StrFixedLenField("unknown4", None, 10),
        FieldLenField("filename_length", None, length_of="filename", fmt="<H"),
        StrFixedLenField("filename", None, length_from=lambda x: x.filename_length),
        ByteField("unknown5", 0),
        ByteField("unknown6", 0),
        PacketField("compressed", None, SAPCARCompressedFileFormat),
        StrFixedLenField("checksum", None, 4),
    ]


class SAPCARArchiveFilev201Format(PacketNoPadded):
    """SAP CAR file information format

    This is ued to parse files inside a SAP CAR archive.
    """
    name = "SAP CAR Archive File"

    fields_desc = [
        StrFixedLenField("unknown0", None, 2),
        LEIntField("perm_mode", 0),
        LEIntField("unknown1", 0),  # some kind of length
        LEIntField("unknown2", 0),
        LEIntField("unknown3", 0),
        LEIntField("timestamp", 0),
        StrFixedLenField("unknown4", None, 10),
        FieldLenField("filename_length", None, length_of="filename", fmt="<H"),
        StrNullFixedLenField("filename", None, length_from=lambda x: x.filename_length - 1),
        ByteField("unknown5", 0),
        ByteField("unknown6", 0),
        PacketField("compressed", None, SAPCARCompressedFileFormat),
        StrFixedLenField("checksum", None, 4),
    ]


class SAPCARArchiveFormat(Packet):
    """SAP CAR file format

    This is used to parse SAP CAR archive files.
    """
    name = "SAP CAR Archive"

    fields_desc = [
        StrFixedLenField("eyecatcher", "CAR ", 4),
        StrFixedLenField("version", "2.01", 4),
        ConditionalField(PacketListField("files0", None, SAPCARArchiveFilev200Format), lambda x: x.version == "2.00"),
        ConditionalField(PacketListField("files1", None, SAPCARArchiveFilev201Format), lambda x: x.version == "2.01"),
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

        @param file_format: file format object
        @type file_format: Packet
        """
        self._file_format = file_format

    @property
    def filename(self):
        """The name of the file.

        @return: name of the file
        @rtype: basestring
        """
        return self._file_format.filename

    @property
    def size(self):
        """The size of the file.

        @return: size of the file
        @rtype: int
        """
        if self._file_format.compressed:
            return self._file_format.compressed.uncompress_length
        else:
            return 0

    @property
    def permissions(self):
        """The permissions of the file.

        @return: permissions in human-readable format
        @rtype: basestring
        """
        return filemode(self._file_format.perm_mode)

    @property
    def timestamp(self):
        """The timestamp of the file.

        @return: timestamp in human-readable format
        @rtype: basestring
        """
        return datetime.fromtimestamp(self._file_format.timestamp).strftime('%d %b %Y %H:%M')

    @classmethod
    def from_file(cls, filename, version="2.0"):
        """Populates the file format object from an actual file on the
        local file system.
        """

        stat = os_stat(filename)
        with open(filename, "r") as fd:
            data = fd.read()

        try:
            (_, _, outbuffer) = compress(data, ALG_LZH)
        except CompressError:
            return None

        if version == "2.0":
            ff = SAPCARArchiveFilev200Format
        else:
            ff = SAPCARArchiveFilev201Format

        archive_file = cls()
        archive_file._file_format = ff()
        archive_file._file_format.perm_mode = stat.st_mode
        archive_file._file_format.timestamp = stat.st_atime
        archive_file._file_format.filename = filename
        archive_file._file_format.filename_length = len(filename)
        archive_file._file_format.compressed = SAPCARCompressedFileFormat(outbuffer)
        return archive_file

    def open(self):
        """Opens the compressed file and returns a file-like object that
        can be used to access its uncompressed content.

        @return: file-like object with the uncompressed file content
        @rtype: file
        """
        compressed = self._file_format.compressed
        (_, _, outbuffer) = decompress(str(compressed)[4:], compressed.uncompress_length)
        return StringIO(outbuffer)


class SAPCARArchive(object):
    """Proxy class that can be used to read SAP CAR archive files.
    """

    files = None
    filename = None

    # Instance attributes
    fd = None
    _files = None
    _sapcar = None

    def __init__(self, fil, mode="r"):
        """Opens an archive file and allow access to it.

        @param fil: filename or file descriptor to open
        @type fil: string or file
        """
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

    @property
    def files(self):
        """The list of file objects inside this archive file.

        @return: list of file objects
        @rtype: L{dict} of L{SAPCARArchiveFile}
        """
        fils = {}
        for fil in self._files:
            fils[fil.filename] = SAPCARArchiveFile(fil)
        return fils

    @property
    def files_names(self):
        """The list of file names inside this archive file.

        @return: list of file names
        @rtype: L{list} of L{string}
        """
        return self.files.keys()

    @property
    def version(self):
        """The version of the archive file.

        @return: version
        @rtype: string
        """
        return self._sapcar.version

    def read(self):
        """Reads the SAP CAR archive file and populates the files list.
        """
        self._sapcar = SAPCARArchiveFormat(self.fd.read())

    @property
    def _files(self):
        """The file format objects according to the version.

        @return: files format objects according to the version
        """
        if self.version == "2.00":
            return self._sapcar.files0
        else:
            return self._sapcar.files1

    def create(self):
        """Creates the structure for holding a new SAP CAR archive file.
        """
        self._sapcar = SAPCARArchiveFormat()

    def write(self):
        """Writes the SAP CAR archive file to the file descriptor.
        """
        self.fd.write(str(self._sapcar))

    def add_file(self, filename):
        """Adds a new file to the SAP CAR archive file.

        @param filename: name of the file to add
        """
        fil = SAPCARArchiveFile.from_file(filename, self.version)
        self._files.append(fil._file_format)

    def open(self, filename):
        """Returns a file-like object that can be used to access a file
        inside the SAP CAR archive.

        @param filename: name of the file to open

        @return: a file-like object that can be used to access the decompressed file.
        """
        if filename not in self.files:
            raise Exception("Invalid filename")
        return self.files[filename].open()

    def close(self):
        """Close the file descriptor object associated to the archive file.
        """
        self.fd.close()
