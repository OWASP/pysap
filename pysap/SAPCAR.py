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
from cStringIO import StringIO
# External imports
from scapy.packet import Packet
from scapy.fields import (ByteField, ByteEnumField, LEIntField, FieldLenField,
                          PacketField, StrFixedLenField, PacketListField,
                          BitField, FlagsField, ConditionalField)
# Custom imports
from pysapcompress import decompress
from pysap.utils import (PacketNoPadded, StrNullFixedLenField)


permissions_names = ["read", "write", "execute"]
special_names = ["setuid", "setgid", "sticky"]


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
        BitField("other_read", 0, 1),
        BitField("other_write", 0, 1),
        BitField("other_execute", 0, 1),
        BitField("group_read", 0, 1),
        BitField("group_write", 0, 1),
        BitField("group_execute", 0, 1),
        BitField("owner_read", 0, 1),
        BitField("owner_write", 0, 1),
        BitField("owner_execute", 0, 1),
        BitField("padding", 0, 4),
        BitField("setuid", 0, 1),
        BitField("setgid", 0, 1),
        BitField("sticky", 0, 1),
        StrFixedLenField("unknown1", None, 28),
        FieldLenField("filename_length", None, length_of="filename", fmt="<H"),
        StrFixedLenField("filename", None, length_from=lambda x: x.filename_length),
        ByteField("unknown3", 0),
        ByteField("unknown4", 0),
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
        BitField("other_read", 0, 1),
        BitField("other_write", 0, 1),
        BitField("other_execute", 0, 1),
        BitField("group_read", 0, 1),
        BitField("group_write", 0, 1),
        BitField("group_execute", 0, 1),
        BitField("owner_read", 0, 1),
        BitField("owner_write", 0, 1),
        BitField("owner_execute", 0, 1),
        BitField("padding", 0, 4),
        BitField("setuid", 0, 1),
        BitField("setgid", 0, 1),
        BitField("sticky", 0, 1),
        StrFixedLenField("unknown1", None, 28),
        FieldLenField("filename_length", None, length_of="filename", fmt="<H"),
        StrNullFixedLenField("filename", None, length_from=lambda x: x.filename_length - 1),
        ByteField("unknown3", 0),
        ByteField("unknown4", 0),
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
    """Interface that can be used to access a file inside a SAP CAR
    archive and obtain its properties.
    """

    def __init__(self, file_format):
        self._file_format = file_format

    @property
    def filename(self):
        return self._file_format.filename

    @property
    def size(self):
        if self._file_format.compressed:
            return self._file_format.compressed.uncompress_length
        else:
            return 0

    @property
    def permissions(self):
        ff = self._file_format
        perms = ""
        perms += "r" if ff.owner_read else "-"
        perms += "w" if ff.owner_write else "-"
        perms += "x" if ff.owner_execute else "-"
        perms += "r" if ff.group_read else "-"
        perms += "w" if ff.group_write else "-"
        perms += "x" if ff.group_execute else "-"
        perms += "r" if ff.other_read else "-"
        perms += "w" if ff.other_write else "-"
        perms += "x" if ff.other_execute else "-"
        return perms

    def open(self):
        compressed = self._file_format.compressed
        (_, _, outbuffer) = decompress(str(compressed)[4:], compressed.uncompress_length)
        return StringIO(outbuffer)


class SAPCARArchive(object):
    """Interface that can be used to read SAP CAR archive files.
    """

    files = None
    filename = None

    # Instance attributes
    _sapcar = None

    def __init__(self, file, mode="r"):
        if isinstance(file, (basestring, unicode)):
            self.filename = file
            fd = open(file, mode)
        else:
            self.filename = getattr(file, "name", None)
            fd = file
        self.read(fd)

    @property
    def files(self):
        fils = {}
        for fil in self._files:
            fils[fil.filename] = SAPCARArchiveFile(fil)
        return fils

    @property
    def files_names(self):
        return self.files.keys()

    @property
    def version(self):
        return self._sapcar.version

    def read(self, fd):
        """Reads the SAP CAR archive file and populates the files list.
        """
        self._sapcar = SAPCARArchiveFormat(fd.read())

        if self._sapcar.version == "2.00":
            self._files = self._sapcar.files0
        else:
            self._files = self._sapcar.files1

    def open(self, filename):
        """Returns a file-like object that can be used to access a file
        inside the SAP CAR archive.
        """
        if filename not in self.files:
            raise Exception("Invalid filename")
        return self.files[filename].open()

