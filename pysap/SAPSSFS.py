# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# SECUREAUTH LABS. Copyright (C) 2019 SecureAuth Corporation. All rights reserved.
#
# The library was designed and developed by Martin Gallo from
# the SecureAuth Labs team.
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
import logging
# External imports
from scapy.packet import Packet
from scapy.fields import (ByteField, YesNoByteField, LenField, StrFixedLenField, PacketListField)
# Custom imports
from pysap.utils.fields import PacketNoPadded


# Create a logger for the SSFS layer
log_cred = logging.getLogger("pysap.ssfs")


class SAPSSFSLock(Packet):
    """SAP SSFS Lock file format packet.

    """
    name = "SAP SSFS Lock"
    fields_desc = [
        StrFixedLenField("preamble", "RSecSSFsLock", 12),
        ByteField("file_type", 0),
        ByteField("type", 0),
        StrFixedLenField("timestamp", None, 8),
        StrFixedLenField("user", None, 24),
        StrFixedLenField("host", None, 24),
    ]


class SAPSSFSKey(Packet):
    """SAP SSFS Key file format packet.

    Key file length is 0x5c
    """
    name = "SAP SSFS Key"
    fields_desc = [
        StrFixedLenField("preamble", "RSecSSFsKey", 11),
        ByteField("type", 1),
        StrFixedLenField("key", None, 24),
        StrFixedLenField("timestamp", None, 8),
        StrFixedLenField("user", None, 24),
        StrFixedLenField("host", None, 24),
    ]


class SAPSSFSDataRecord(PacketNoPadded):
    """SAP SSFS Data Record.

    The Data Record is comprised of a record header of 24 bytes and a data header of 152 bytes followed by the
    actual data.
    """
    name = "SAP SSFS Data Record"

    fields_desc = [
        # Record Header
        StrFixedLenField("preamble", "RSecSSFsData", 12),
        LenField("length", 0, fmt="I"),  # Max record length supported is 0x18150
        ByteField("type", 1),   # Record type "1" supported
        StrFixedLenField("filler1", None, 7),
        # Data Header
        StrFixedLenField("key_name", None, 64),
        StrFixedLenField("timestamp", None, 8),
        StrFixedLenField("user", None, 24),
        StrFixedLenField("host", None, 24),
        YesNoByteField("is_deleted", 0),
        YesNoByteField("is_stored_as_plaintext", 0),
        YesNoByteField("is_binary_data", 0),
        StrFixedLenField("filler2", None, 9),
        StrFixedLenField("hmac", None, 20),  # HMAC-SHA1 of the data header and payload
        # Data
        StrFixedLenField("data", None, length_from=lambda pkt: pkt.length - 176),
    ]


class SAPSSFSData(Packet):
    """SAP SSFS Data file format packet.

    """
    name = "SAP SSFS Data File"

    fields_desc = [
        PacketListField("records", None, SAPSSFSDataRecord),
    ]
