# encoding: utf-8
# pysap - Python library for crafting SAP's network protocols packets
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
#
# Author:
#   Martin Gallo (@martingalloar)
#

"""SAP Extended Passport (EPP) wire structures.

Extended Passports are carried as binary values by SAP protocols.  HTTP uses
the same bytes encoded as hexadecimal in the ``SAP-PASSPORT`` header.  EPP
version 3 consists of a fixed core, zero or more variable parts, and a final
``*TH*`` marker.
"""

from binascii import hexlify, unhexlify

from scapy.fields import (ByteEnumField, ByteField, ConditionalField,
                          FieldLenField, IntField, PacketListField,
                          ShortField, StrFixedLenField, StrLenField,
                          XIntField)

from pysap.utils.fields import PacketNoPadded, StrFixedLenPaddedField


EPP_MAGIC = 0x2a54482a  # b"*TH*" on the wire

epp_versions = {1: "EPP version 1", 2: "EPP version 2", 3: "EPP version 3"}
epp_item_types = {
    1: "byte string",
    2: "integer",
    3: "UUID",
    4: "string",
}


def _epp_item_value_length(pkt):
    return max((pkt.length or 7) - 7, 0)


def _epp_core_adjust(pkt, variable_parts_length):
    if pkt.version <= 1:
        return variable_parts_length + 0x99
    if pkt.version == 2:
        return variable_parts_length + 0xb9
    return variable_parts_length + 0xe6


class SAPEPPItem(PacketNoPadded):
    """One item in an EPP variable part.

    ``length`` includes the seven-byte item header and the value.  String
    values use UTF-8 on the wire; this class deliberately exposes the raw
    bytes so malformed and unknown values round-trip without normalization.
    """

    name = "SAP Extended Passport Item"
    fields_desc = [
        ShortField("key", 0),
        ShortField("application", 0),
        ByteEnumField("item_type", 1, epp_item_types),
        FieldLenField("length", None, length_of="value", adjust=lambda pkt, x: x + 7, fmt="!H"),
        StrLenField("value", b"", length_from=_epp_item_value_length),
    ]


class SAPEPPVariablePart(PacketNoPadded):
    """EPP variable-part header followed by ``item_count`` items."""

    name = "SAP Extended Passport Variable Part"
    fields_desc = [
        XIntField("magic", EPP_MAGIC),
        ByteField("version", 1),
        FieldLenField("length", None, length_of="items", adjust=lambda pkt, x: x + 12, fmt="!H"),
        ByteField("last", 0),
        ShortField("part_id", 0),
        FieldLenField("item_count", None, count_of="items", fmt="!H"),
        PacketListField("items", [], SAPEPPItem, count_from=lambda pkt: pkt.item_count),
    ]


class SAPEPP(PacketNoPadded):
    """SAP Extended Passport versions 1 through 3.

    The total ``length`` includes the complete core, all variable parts, and
    the trailing magic.  Version 3 starts variable parts at offset ``0xe2``.
    """

    name = "SAP Extended Passport"
    fields_desc = [
        XIntField("magic", EPP_MAGIC),
        ByteEnumField("version", 3, epp_versions),
        FieldLenField("length", None, length_of="variable_parts", adjust=_epp_core_adjust, fmt="!H"),
        ByteField("trace_flag_1", 0),
        ByteField("trace_flag_2", 0),
        StrFixedLenPaddedField("component", b"", length=32),
        ShortField("service", 0),
        StrFixedLenPaddedField("user", b"", length=32),
        StrFixedLenPaddedField("action", b"", length=40),
        ShortField("action_type", 0),
        StrFixedLenPaddedField("previous_component", b"", length=32),
        ConditionalField(StrFixedLenPaddedField("transaction_id", b"", length=32), lambda pkt: pkt.version > 1),
        ConditionalField(StrFixedLenPaddedField("client", b"", length=3), lambda pkt: pkt.version > 2),
        ConditionalField(ShortField("component_type", 0), lambda pkt: pkt.version > 2),
        ConditionalField(StrFixedLenField("root_context_id", b"\x00" * 16, 16), lambda pkt: pkt.version > 2),
        ConditionalField(StrFixedLenField("connection_id", b"\x00" * 16, 16), lambda pkt: pkt.version > 2),
        ConditionalField(IntField("connection_counter", 0), lambda pkt: pkt.version > 2),
        ConditionalField(FieldLenField("variable_part_count", None, count_of="variable_parts", fmt="!H"),
                         lambda pkt: pkt.version > 2),
        ConditionalField(ShortField("variable_part_offset", 0xe2), lambda pkt: pkt.version > 2),
        PacketListField("variable_parts", [], SAPEPPVariablePart,
                        count_from=lambda pkt: pkt.variable_part_count if pkt.version > 2 else 0),
        XIntField("trailer", EPP_MAGIC),
    ]


def epp_from_http_header(value):
    """Decode a hexadecimal ``SAP-PASSPORT`` HTTP header into :class:`SAPEPP`."""
    if isinstance(value, str):
        value = value.encode("ascii")
    return SAPEPP(unhexlify(value.strip()))


def epp_to_http_header(passport):
    """Encode EPP bytes for use as an ``SAP-PASSPORT`` HTTP header value."""
    return hexlify(bytes(passport)).decode("ascii")
