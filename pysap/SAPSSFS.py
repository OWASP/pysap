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
from scapy.fields import (ByteField, ByteEnumField, ShortField, StrField, StrFixedLenField)


# Create a logger for the SSFS layer
log_cred = logging.getLogger("pysap.ssfs")


class SAPSSFSKey(Packet):
    """SAP SSFS Key file format packet.

    """
    name = "SAP SSFS Key"

    fields_desc = [
        StrFixedLenField("eyecatcher", "RSecSSFsKey", 11),
        ByteField("unknown", 0),
    ]


class SAPSSFSData(Packet):
    """SAP SSFS Data file format packet.

    """
    name = "SAP SSFS Data"

    fields_desc = [
        StrFixedLenField("eyecatcher", "RSecSSFsData", 12),
        ByteField("unknown", 0),
    ]
