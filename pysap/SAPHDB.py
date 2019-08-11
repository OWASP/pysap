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

# External imports
from scapy.layers.inet import TCP
from scapy.packet import Packet, bind_layers
from scapy.fields import (ByteField, ConditionalField, EnumField, FieldLenField,
                          IntField, PacketListField, SignedByteField, LongField,
                          LEIntField, LESignedIntField)
# Custom imports
from pysap.utils.fields import LESignedByteField, LESignedShortField, LESignedLongField


hdb_segmentkind_values = {
    0: "invalid",
    1: "request",
    2: "reply",
    5: "error",
}
"""Segment Kind Values"""


hdb_message_type_values = {
    0: "NIL",
    2: "EXECUTEDIRECT",
    3: "PREPARE",
    4: "ABAPSTREAM",
    5: "XA_START",
    6: "XA_JOIN",
    7: "XA_COMMIT",
    13: "EXECUTE",
    16: "READLOB",
    17: "WRITELOB",
    18: "FINDLOB",
    25: "PING",
    65: "AUTHENTICATE",
    66: "CONNECT",
    67: "COMMIT",
    68: "ROLLBACK",
    69: "CLOSERESULTSET",
    70: "DROPSTATEMENTID",
    71: "FETCHNEXT",
    72: "FETCHABSOLUTE",
    73: "FETCHRELATIVE",
    74: "FETCHFIRST",
    75: "FETCHLAST",
    77: "DISCONNECT",
    78: "EXECUTEITAB",
    79: "FETCHNEXTITAB",
    80: "INSERTNEXTITAB",
    81: "BATCHPREPARE",
    82: "DBCONNECTINFO",
    83: "XOPEN_XASTART",
    84: "XOPEN_XAEND",
    85: "XOPEN_XAPREPARE",
    86: "XOPEN_XACOMMIT",
    87: "XOPEN_XAROLLBACK",
    88: "XOPEN_XARECOVER",
    89: "XOPEN_XAFORGET",
}
"""Message Type Values"""


def hdb_segment_is_reply(segment):
    """Returns if the segment is a reply

    :param segment: segment to look at
    :type segment: :class:`SAPHDBSegment`

    :return: if the segment is a reply
    :rtype: ``bool``
    """
    return segment.segmentkind == 2


class SAPHDBSegment(Packet):
    """SAP HANA SQL Command Network Protocol Segment

    This packet represents a segment within a HDB packet.
    """
    name = "SAP HANA SQL Command Network Protocol Segment"
    fields_desc = [
        LESignedIntField("segmentlength", 0),
        LESignedIntField("segmentofs", 0),
        LESignedShortField("noofparts", 0),
        LESignedShortField("segmentno", 0),
        EnumField("segmentkind", 1, hdb_segmentkind_values, fmt="<b"),
        ConditionalField(EnumField("messagetype", 0, hdb_message_type_values, fmt="<b"), hdb_segment_is_reply),
        ConditionalField(LESignedByteField("commit", 0), hdb_segment_is_reply),
        ConditionalField(LESignedByteField("commandoptions", 0), hdb_segment_is_reply),
        ConditionalField(LongField("reserved1", 0), hdb_segment_is_reply),
        ConditionalField(ByteField("reserved2", 0), hdb_segment_is_reply),
        ConditionalField(LESignedShortField("functioncode", 0), hdb_segment_is_reply),
        ConditionalField(LongField("reserved3", 0), hdb_segment_is_reply),
    ]


class SAPHDB(Packet):
    """SAP HANA SQL Command Network Protocol packet

    This packet is used for the HANA SQL Command Network Protocol
    """
    name = "SAP HANA SQL Command Network Protocol"
    fields_desc = [
        LESignedLongField("sessionid", 0),
        LESignedIntField("packetcount", 0),
        FieldLenField("varpartlength", None, length_of="segments", fmt="<I"),
        LEIntField("varpartsize", 0),
        FieldLenField("noofsegm", None, count_of="segments", fmt="h"),
        SignedByteField("packetoptions", 0),
        ByteField("reserved1", None),
        LEIntField("compressionvarpartlength", 0),
        IntField("reserved2", None),
        PacketListField("segments", None, SAPHDBSegment, count_from=lambda x: x.noofsegm),
    ]


# Bind SAP NI with the HDB ports
bind_layers(TCP, SAPHDB, dport=30013)
bind_layers(TCP, SAPHDB, dport=30015)
