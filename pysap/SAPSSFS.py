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
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.backends import default_backend
# Custom imports
from pysap.utils.fields import PacketNoPadded, StrFixedLenPaddedField, TimestampField


# Create a logger for the SSFS layer
log_ssfs = logging.getLogger("pysap.ssfs")


ssfs_hmac_key_unobscured = "\xe3\xa0\x61\x11\x85\x41\x68\x99\xf3\x0e\xda\x87\x7a\x80\xcc\x69"
"""Fixed key embedded in rsecssfx binaries for validating integrity of records"""


class RSecSSFsLKY(Packet):
    """SAP SSFS LKY file format packet.

    """
    name = "SAP SSFS LKY"
    fields_desc = [
        StrFixedLenField("preamble", "RSecSSFsLKY", 11),
    ]


class SAPSSFSLock(Packet):
    """SAP SSFS Lock file format packet.

    """
    name = "SAP SSFS Lock"
    fields_desc = [
        StrFixedLenField("preamble", "RSecSSFsLock", 12),
        ByteField("file_type", 0),
        ByteField("type", 0),
        TimestampField("timestamp", None),
        StrFixedLenPaddedField("user", None, 24, padd=" "),
        StrFixedLenPaddedField("host", None, 24, padd=" "),
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
        TimestampField("timestamp", None),
        StrFixedLenPaddedField("user", None, 24, padd=" "),
        StrFixedLenPaddedField("host", None, 24, padd=" "),
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
        StrFixedLenPaddedField("key_name", None, 64, padd=" "),
        TimestampField("timestamp", None),
        StrFixedLenPaddedField("user", None, 24, padd=" "),
        StrFixedLenPaddedField("host", None, 24, padd=" "),
        YesNoByteField("is_deleted", 0),
        YesNoByteField("is_stored_as_plaintext", 0),
        YesNoByteField("is_binary_data", 0),
        StrFixedLenField("filler2", None, 9),
        StrFixedLenField("hmac", None, 20),  # HMAC-SHA1 of the data header and payload
        # Data
        StrFixedLenField("data", None, length_from=lambda pkt: pkt.length - 176),
    ]

    @property
    def plain_data(self):
        if self.is_stored_as_plaintext:
            return self.data
        raise NotImplementedError("Decryption not yet implemented")

    @property
    def is_valid(self):
        """Returns whether the HMAC-SHA1 value is valid for the given payload"""

        # Calculate the HMAC-SHA1
        h = HMAC(ssfs_hmac_key_unobscured, SHA1(), backend=default_backend())
        h.update(str(self)[24:156])  # Entire Data header without the HMAC field
        h.update(self.data)

        # Validate the signature
        try:
            h.verify(self.hmac)
            return True
        except InvalidSignature:
            return False


class SAPSSFSData(Packet):
    """SAP SSFS Data file format packet.

    """
    name = "SAP SSFS Data File"

    fields_desc = [
        PacketListField("records", None, SAPSSFSDataRecord),
    ]

    def has_record(self, key_name):
        """Returns if the data file contains a record with a given key name.

        :param key_name: the name of the key to look for
        :type key_name: string

        :return: if the data file contains the record with key_name
        :rtype: bool
        """
        for record in self.records:
            if record.key_name.rstrip(" ") == key_name:
                return True
        return False

    def get_record(self, key_name):
        """Returns the record with the given key name.

        :param key_name: the name of the key to look for
        :type key_name: string

        :return: the record with key_name
        :rtype: SAPSSFSDataRecord
        """
        for record in self.records:
            if record.key_name.rstrip(" ") == key_name:
                return record
        return None

    def get_value(self, key_name):
        """Returns the record with the given key name.

        :param key_name: the name of the key to look for
        :type key_name: string

        :return: the record with key_name
        :rtype: SAPSSFSDataRecord
        """
        try:
            return self.get_record(key_name).plain_data
        except AttributeError:
            return None