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
                          IntField, PacketListField, SignedByteField, LongField, PadField,
                          LEIntField, LESignedIntField, StrFixedLenField, ShortField)
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


class SAPHDBPartAuthenticationField(PacketNoPadded):
    """SAP HANA SQL Command Network Protocol Authentication Part Field

    This packet represents a field in the Authentication Part
    """
    name = "SAP HANA SQL Command Network Protocol Authentication Field"
    fields_desc = [
        FieldLenField("length", None, length_of="value", fmt="B"),
        StrFixedLenField("value", None, length_from=lambda x:x.length)
    ]


class SAPHDBPartAuthentication(PacketNoPadded):
    """SAP HANA SQL Command Network Protocol Authentication Part

    This packet represents an Authentication Part. The Authentication part consists of a count value and then
    a number of key/value pairs expressed with field values.

    Authentication methods documented are:
        - "GSS" - Provides GSS/Kerberos authentication.
        - "PLAINPASSWORD" - Reserved. Do not use.
        - "SAML" - Provides SAML authentication.
        - "SCRAMMD5" - Reserved. Do not use.
        - "SCRAMSHA256" - Provides password-based authentication.

    Non-documented methods are:
        - "JWT"
        - "SAPLogon"
        - "SCRAMPBKDF2SHA256"
        - "SessionCookie"
        - "X509Internal"

    Known authentication key values are:

    - GSS Authentication:
        - USERNAME - User name
        - METHODNAME - Method name
        - CLIENTCHALLENGE - Client challenge
            - KRB5OID - KRB5 object ID
            - TYPEOID - Type object ID
            - CLIENTGSSNAME - Client GSS Name
        - SERVERTOKEN - Server-specific Kerberos tokens
        - CLIENTOKEN - Client-specific Kerberos tokens
    - LDAP Authentication:
        - USERNAME - User name
        - METHODNAME - Method name ("LDAP")
        - CLIENTCHALLENGE - Client challenge
        - SERVERCHALLENGE - Server Challenge
            - CLIENTNONCE - Specifies the client nonce that was sent in the initial request.
            - SERVERNONCE - Specifies the server nonce.
            - SERVERPUBLICKEY - Specifies the server public key.
            - CAPABILITYRESULT - Specifies the capability, chosen by the server, from the client request.
        - CLIENTPROOF - Specifies the client proof.
            - ENCRYPTEDSESSKEY - Specifies the encrypted session key. This is specified as: RSAEncrypt(public key, SESSIONKEY + SERVERNONCE).
            - ENCRYPTEDPASSWORD - Specifies the encrypted password. This is specified as: AES256Encrypt(SESSIONKEY, PASSWORD + SERVERNONCE).
        - SERVERPROOF - Specifies the authentication result from the LDAP server. This is specified as either SUCCESS or FAIL.
    - SAML Authentication:
        - USERNAME - Specifies the user name (always empty user name).
        - METHODNAME - Specifies the method name.
        - SAMLASSERTION - Specifies the SAML assertion.
        - SAMLUSER - Specifies the user name associated with the SAML assertion.
        - FINALDATA - Specifies the final data (this is empty).
        - SESSIONCOOKIE - Specifies the session cookie used for the reconnect.
    - SCRAMSHA256 Authentication:
        - USERNAME - Specifies the user name.
        - METHODNAME - Specifies the method name.
        - CLIENTCHALLENGE - Specifies the client challenge. (64 bytes)
        - SERVERCHALLENGEDATA - Specifies the server challenge.
            - SALT - Specifies the password salt.
            - SERVERCHALLENGE - Specifies the server challenge.
        - CLIENTPROOF - Specifies the client proof. (35 bytes)
            - SCRAMMESSAGE - Specifies the SCRAM HMAC message, the actual Client Proof that is sent to the server. (32 bytes)
        - SERVERPROOF - Specifies the server proof.
    - Session Cookie Authentication:
        - USERNAME - Specifies the user name.
        - METHODNAME - Specifies the method name.
        - SESSIONCOOKIE - Specifies the session cookie, process ID, and hostname.
        - SERVERREPLY - Specifies the server reply (this is empty).
        - FINALDATA - Specifies the final data (this is empty).
    """
    name = "SAP HANA SQL Command Network Protocol Authentication Part"
    fields_desc = [
        FieldLenField("count", None, count_of="fields", fmt="<H"),
        PacketListField("fields", None, SAPHDBPartAuthenticationField, count_from=lambda x: x.count),
    ]


class SAPHDBPart(PacketNoPadded):
    """SAP HANA SQL Command Network Protocol Part

    This packet represents a part within a HDB packet.

    The part header is comprised of 16 bytes.
    """
    name = "SAP HANA SQL Command Network Protocol Part"
    fields_desc = [
        EnumField("partkind", 0, hdb_partkind_values, fmt="<b"),
        LESignedByteField("partattributes", 0),
        LESignedShortField("argumentcount", 0),
        LESignedIntField("bigargumentcount", 0),
        FieldLenField("bufferlength", None, length_of="buffer", fmt="<i"),
        LESignedIntField("buffersize", 2**17 - 32 - 24),
        PadField(PacketListField("buffer", None), 8),
    ]


class SAPHDBSegment(PacketNoPadded):
    """SAP HANA SQL Command Network Protocol Segment

    This packet represents a segment within a HDB packet.

    The segment header is comprised of 24 byte, being the first 13 bytes always the same fields and the remaining 11
    bytes depend on the segment kind field.
    """
    name = "SAP HANA SQL Command Network Protocol Segment"
    fields_desc = [
        # Segment length needs to be calculated counting the segment header
        FieldLenField("segmentlength", None, length_of="parts", fmt="<i", adjust=lambda x, l:l+24),
        LESignedIntField("segmentofs", 0),
        FieldLenField("noofparts", None, count_of="parts", fmt="<h"),
        LESignedShortField("segmentno", 1),
        EnumField("segmentkind", 1, hdb_segmentkind_values, fmt="<b"),
        ConditionalField(EnumField("messagetype", 0, hdb_message_type_values, fmt="<b"), hdb_segment_is_request),
        ConditionalField(LESignedByteField("commit", 0), hdb_segment_is_request),
        ConditionalField(LESignedByteField("commandoptions", 0), hdb_segment_is_request),
        ConditionalField(LongField("reserved1", 0), hdb_segment_is_request),
        ConditionalField(ByteField("reserved2", 0), hdb_segment_is_reply),
        ConditionalField(EnumField("functioncode", 0, hdb_function_code_values, fmt="<h"), hdb_segment_is_reply),
        ConditionalField(LongField("reserved3", 0), hdb_segment_is_reply),
        ConditionalField(StrFixedLenField("reserved4", None, 11), lambda pkt: not (hdb_segment_is_reply(pkt) or hdb_segment_is_request(pkt))),
        PacketListField("parts", None, SAPHDBPart, count_from=lambda x: x.noofparts),
    ]


class SAPHDB(Packet):
    """SAP HANA SQL Command Network Protocol packet

    This packet is used for the HANA SQL Command Network Protocol.

    The message header is comprised of 32 bytes.
    """
    name = "SAP HANA SQL Command Network Protocol"
    fields_desc = [
        LESignedLongField("sessionid", -1),
        LESignedIntField("packetcount", 0),
        FieldLenField("varpartlength", None, length_of="segments", fmt="<I"),
        LEIntField("varpartsize", 2**17 - 32),
        FieldLenField("noofsegm", None, count_of="segments", fmt="<h"),
        SignedByteField("packetoptions", 0),
        ByteField("reserved1", None),
        LEIntField("compressionvarpartlength", 0),
        IntField("reserved2", None),
        PacketListField("segments", None, SAPHDBSegment, count_from=lambda x: x.noofsegm),
    ]


class SAPHDBInitializationRequest(Packet):
    """SAP HANA SQL Command Network Protocol Initialization Request packet

    This packet is used for the HANA SQL Command Network Protocol during initialization.
    """
    name = "SAP HANA SQL Command Network Protocol Initialization Request"
    fields_desc = [
        StrFixedLenField("initialization", "\xff\xff\xff\xff\x04\x20\x00\x04\x01\x00\x00\x01\x01\x01", 14),
    ]


class SAPHDBInitializationReply(Packet):
    """SAP HANA SQL Command Network Protocol Initialization Reply packet

    This packet is used for the HANA SQL Command Network Protocol during initialization.
    """
    name = "SAP HANA SQL Command Network Protocol Initialization Reply"
    fields_desc = [
        LESignedByteField("product_major", 0),
        ShortField("product_minor", 0),
        LESignedByteField("protocol_major", 0),
        ShortField("protocol_minor", 0),
        ShortField("padding", 0),
    ]


# Bind SAP NI with the HDB ports
bind_layers(TCP, SAPHDB, dport=30013)
bind_layers(TCP, SAPHDB, dport=30015)
