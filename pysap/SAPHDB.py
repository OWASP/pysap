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
from pysap.utils.fields import (PacketNoPadded, LESignedByteField, LESignedShortField,
                                LESignedLongField)


hdb_segmentkind_values = {
    0: "Invalid",
    1: "Request",
    2: "Reply",
    5: "Error",
}
"""SAP HDB Segment Kind Values"""


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
"""SAP HDB Segment Message Type Values"""


hdb_function_code_values = {
    0: "NIL",
    1: "DDL",
    2: "INSERT",
    3: "UPDATE",
    4: "DELETE",
    5: "SELECT",
    6: "SELECTFORUPDATE",
    7: "EXPLAIN",
    8: "DBPROCEDURECALL",
    9: "DBPROCEDURECALLWITHRESULT",
    10: "FETCH",
    11: "COMMIT",
    12: "ROLLBACK",
    13: "SAVEPOINT",
    14: "CONNECT",
    15: "WRITELOB",
    16: "READLOB",
    17: "PING",
    18: "DISCONNECT",
    19: "CLOSECURSOR",
    20: "FINDLOB",
    21: "ABAPSTREAM",
    22: "XASTART",
    23: "XAJOIN",
    24: "ITABWRITE",
    25: "XOPEN_XACONTROL",
    26: "XOPEN_XAPREPARE",
    27: "XOPEN_XARECOVER",
}
"""SAP HDB Segment Function Code Values"""


hdb_partkind_values = {
    0: "NIL",
    3: "COMMAND",
    5: "RESULTSET",
    6: "ERROR",
    10: "STATEMENTID",
    11: "TRANSACTIONID",
    12: "ROWSAFFECTED",
    13: "RESULTSETID",
    15: "TOPOLOGYINFORMATION",
    16: "TABLELOCATION",
    17: "READLOBREQUEST",
    18: "READLOBREPLY",
    25: "ABAPISTREAM",
    26: "ABAPOSTREAM",
    27: "COMMANDINFO",
    28: "WRITELOBREQUEST",
    29: "CLIENTCONTEXT",
    30: "WRITELOBREPLY",
    32: "PARAMETERS",
    33: "AUTHENTICATION",
    34: "SESSIONCONTEXT",
    35: "CLIENTID",
    38: "PROFILE",
    39: "STATEMENTCONTEXT",
    40: "PARTITIONINFORMATION",
    41: "OUTPUTPARAMETERS",
    42: "CONNECTOPTIONS",
    43: "COMMITOPTIONS",
    44: "FETCHOPTIONS",
    45: "FETCHSIZE",
    47: "PARAMETERMETADATA",
    48: "RESULTSETMETADATA",
    49: "FINDLOBREQUEST",
    50: "FINDLOBREPLY",
    51: "ITABSHM",
    53: "ITABCHUNKMETADATA",
    55: "ITABMETADATA",
    56: "ITABRESULTCHUNK",
    57: "CLIENTINFO",
    58: "STREAMDATA",
    59: "OSTREAMRESULT",
    60: "FDAREQUESTMETADATA",
    61: "FDAREPLYMETADATA",
    62: "BATCHPREPARE",
    63: "BATCHEXECUTE",
    64: "TRANSACTIONFLAGS",
    65: "ROWSLOTIMAGEPARAMMETADATA",
    66: "ROWSLOTIMAGERESULTSET",
    67: "DBCONNECTINFO",
    68: "LOBFLAGS",
    69: "RESULTSETOPTIONS",
    70: "XATRANSACTIONINFO",
    71: "SESSIONVARIABLE",
    72: "WORKLOADREPLAYCONTEXT",
    73: "SQLREPLYOTIONS",
}
"""SAP HDB Part Kind Values"""


def hdb_segment_is_request(segment):
    """Returns if the segment is a request

    :param segment: segment to look at
    :type segment: :class:`SAPHDBSegment`

    :return: if the segment is a request
    :rtype: ``bool``
    """
    return segment.segmentkind == 1


def hdb_segment_is_reply(segment):
    """Returns if the segment is a reply

    :param segment: segment to look at
    :type segment: :class:`SAPHDBSegment`

    :return: if the segment is a reply
    :rtype: ``bool``
    """
    return segment.segmentkind == 2


class SAPHDBPart(PacketNoPadded):
    """SAP HANA SQL Command Network Protocol Part

    This packet represents a part within a HDB packet.
    """
    name = "SAP HANA SQL Command Network Protocol Part"
    fields_desc = [
        EnumField("partkind", 0, hdb_partkind_values, fmt="<b"),
        LESignedByteField("partattributes", 0),
        LESignedShortField("argumentcount", 0),
        LESignedIntField("bigargumentcount", 0),
        LESignedIntField("bufferlength", 0),
        LESignedIntField("buffersize", 0),
    ]


class SAPHDBSegment(PacketNoPadded):
    """SAP HANA SQL Command Network Protocol Segment

    This packet represents a segment within a HDB packet.
    """
    name = "SAP HANA SQL Command Network Protocol Segment"
    fields_desc = [
        LESignedIntField("segmentlength", 0),
        LESignedIntField("segmentofs", 0),
        FieldLenField("noofparts", 0, count_of=lambda x: x.parts, fmt="<h"),
        LESignedShortField("segmentno", 0),
        EnumField("segmentkind", 1, hdb_segmentkind_values, fmt="<b"),
        ConditionalField(EnumField("messagetype", 0, hdb_message_type_values, fmt="<b"), hdb_segment_is_request),
        ConditionalField(LESignedByteField("commit", 0), hdb_segment_is_request),
        ConditionalField(LESignedByteField("commandoptions", 0), hdb_segment_is_request),
        ConditionalField(LongField("reserved1", 0), hdb_segment_is_request),
        ConditionalField(ByteField("reserved2", 0), hdb_segment_is_reply),
        ConditionalField(EnumField("functioncode", 0, hdb_function_code_values, fmt="<h"), hdb_segment_is_reply),
        ConditionalField(LongField("reserved3", 0), hdb_segment_is_reply),
        PacketListField("parts", None, SAPHDBPart, count_from=lambda x: x.noofparts),
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
