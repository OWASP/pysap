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

# Standard imports
import unittest
from datetime import datetime
# External imports
from scapy.asn1.asn1 import ASN1_Error
from scapy.fields import StrFixedLenField
from scapy.packet import Packet
# Custom imports
from pysap.utils.fields import (saptimestamp_to_datetime, StrNullFixedLenField,
                                StrFixedLenPaddedField, StrNullFixedLenPaddedField,
                                StrEncodedPaddedField, PacketListStopField,
                                AdjustableFieldLenField, ASN1F_CHOICE_SAFE,
                                ASN1F_RAW_TLV, asn1_read_tlv, asn1_first_tlv,
                                asn1_child_tlvs, asn1_decode_oid)


class DummyLengthPacket(object):

    def __init__(self, size):
        self.size = size


class DummyLengthField(object):

    def i2len(self, pkt, value):
        return len(value)


class DummyLengthSourcePacket(object):

    def __init__(self, payload):
        self.payload = payload

    def getfield_and_val(self, field_name):
        return DummyLengthField(), self.payload


class RejectingChoice(object):
    ASN1_tag = 1

    def __init__(self, s, _underlayer=None):
        raise ASN1_Error("rejecting choice")


class FixedLengthTestPacket(Packet):
    fields_desc = [
        StrFixedLenField("value", b"", length=2),
    ]


class PySAPUtilsFieldsTest(unittest.TestCase):

    def test_saptimestamp_to_datetime(self):
        self.assertEqual(
            saptimestamp_to_datetime(0),
            datetime(2001, 9, 9, 1, 46, 40)
        )

    def test_str_null_fixed_len_field_addfield_and_getfield(self):
        pkt = DummyLengthPacket(4)
        field = StrNullFixedLenField("value", b"", length_from=lambda pkt: pkt.size)

        raw = field.addfield(pkt, b"", b"ab")
        self.assertEqual(raw, b"ab\x00\x00")

        remaining, value = field.getfield(pkt, raw)
        self.assertEqual(remaining, b"")
        self.assertEqual(value, b"ab\x00")

    def test_str_null_fixed_len_field_without_null_termination(self):
        pkt = DummyLengthPacket(4)
        field = StrNullFixedLenField(
            "value",
            b"",
            length=4,
            null_terminated=lambda pkt: False,
        )

        remaining, value = field.getfield(pkt, b"ab\x00x")
        self.assertEqual(remaining, b"")
        self.assertEqual(value, b"ab\x00x")

    def test_str_fixed_len_padded_field_roundtrip(self):
        pkt = DummyLengthPacket(4)
        field = StrFixedLenPaddedField("value", b"", length_from=lambda pkt: pkt.size, padd=" ")

        raw = field.addfield(pkt, b"", b"ab")
        self.assertEqual(raw, b"ab  ")

        remaining, value = field.getfield(pkt, raw)
        self.assertEqual(remaining, b"")
        self.assertEqual(value, b"ab  ")

    def test_str_fixed_len_padded_field_utf16le_roundtrip(self):
        pkt = DummyLengthPacket(8)
        field = StrFixedLenPaddedField("value", b"", length_from=lambda pkt: pkt.size,
                                       encoding="utf-16-le")

        raw = field.addfield(pkt, b"", "AB")
        self.assertEqual(raw, b"A\x00B\x00\x00\x00\x00\x00")

        remaining, value = field.getfield(pkt, raw)
        self.assertEqual(remaining, b"")
        self.assertEqual(value, "AB")

    def test_str_fixed_len_padded_field_utf16le_non_ascii(self):
        pkt = DummyLengthPacket(8)
        field = StrFixedLenPaddedField("value", b"", length_from=lambda pkt: pkt.size,
                                       encoding="utf-16-le")

        raw = field.addfield(pkt, b"", "Ä1")
        self.assertEqual(raw, "Ä1".encode("utf-16-le") + b"\x00\x00\x00\x00")

        remaining, value = field.getfield(pkt, raw)
        self.assertEqual(remaining, b"")
        self.assertEqual(value, "Ä1")

    def test_str_null_fixed_len_padded_field_getfield(self):
        pkt = DummyLengthPacket(4)
        field = StrNullFixedLenPaddedField("value", b"", length_from=lambda pkt: pkt.size, padd=" ")

        remaining, value = field.getfield(pkt, b"ab\x00xyrest")
        self.assertEqual(remaining, b"rest")
        self.assertEqual(value, b"ab")

    def test_str_encoded_padded_field_accepts_text_padding(self):
        field = StrEncodedPaddedField("value", None, encoding="utf-8", padd="\x0c")

        raw = field.addfield(None, b"", "abc")
        remaining, value = field.getfield(None, raw + b"rest")

        self.assertEqual(raw, b"abc\x0c")
        self.assertEqual(remaining, b"rest")
        self.assertEqual(value, b"abc")

    def test_packet_list_stop_field_returns_bytes_remainder(self):
        field = PacketListStopField("items", None, FixedLengthTestPacket, length_from=lambda pkt: 2)

        remaining, value = field.getfield(None, b"abrest")

        self.assertEqual(remaining, b"rest")
        self.assertEqual(len(value), 1)
        self.assertEqual(value[0].value, b"ab")

    def test_adjustable_field_len_field_short_and_extended(self):
        field = AdjustableFieldLenField("length", None, length_of="payload")

        short_pkt = DummyLengthSourcePacket(b"abc")
        self.assertEqual(field.addfield(short_pkt, b"", None), b"\x03")
        remaining, value = field.getfield(short_pkt, b"\x03rest")
        self.assertEqual(remaining, b"rest")
        self.assertEqual(value, 3)

        long_payload = b"a" * 241
        long_pkt = DummyLengthSourcePacket(long_payload)
        self.assertEqual(field.addfield(long_pkt, b"", None), b"\xff\x00\xf1")
        remaining, value = field.getfield(long_pkt, b"\xff\x00\xf1rest")
        self.assertEqual(remaining, b"rest")
        self.assertEqual(value, 241)

    def test_asn1f_choice_safe_rejects_implicit_tag(self):
        with self.assertRaises(ASN1_Error):
            ASN1F_CHOICE_SAFE("choice", None, RejectingChoice, implicit_tag=1)

    def test_asn1f_choice_safe_empty_and_rejected_choice(self):
        field = ASN1F_CHOICE_SAFE("choice", None, RejectingChoice)

        with self.assertRaises(ASN1_Error):
            field.m2i(None, b"")

        with self.assertRaises(ASN1_Error):
            field.m2i(None, b"\x01")

    def test_asn1_read_tlv_short_length_and_children(self):
        data = b"\x30\x06\x02\x01\x01\x04\x01a"

        self.assertEqual(asn1_read_tlv(data), (0x30, 0, 2, 8, 8))
        self.assertEqual(asn1_first_tlv(data + b"tail"), data)
        self.assertEqual(asn1_child_tlvs(data), [b"\x02\x01\x01", b"\x04\x01a"])

    def test_asn1_read_tlv_long_length(self):
        data = b"\x04\x81\x80" + (b"a" * 128) + b"tail"

        self.assertEqual(asn1_read_tlv(data), (0x04, 0, 3, 131, 131))
        self.assertEqual(asn1_first_tlv(data), data[:-4])

    def test_asn1_decode_oid(self):
        self.assertEqual(asn1_decode_oid(b"\x06\x05\x2b\x24\x02\x01\x03"), "1.3.36.2.1.3")

    def test_asn1f_raw_tlv_preserves_single_tlv(self):
        field = ASN1F_RAW_TLV("value", b"")

        value, remaining = field.m2i(None, b"\x04\x03abc\x02\x01\x01")

        self.assertEqual(value, b"\x04\x03abc")
        self.assertEqual(remaining, b"\x02\x01\x01")

    def test_asn1f_raw_tlv_builds_empty_value(self):
        field = ASN1F_RAW_TLV("value", b"")

        self.assertEqual(field.i2m(None, b""), b"")
        self.assertEqual(field.i2m(None, field.default), b"")
        self.assertEqual(field.m2i(None, b""), (b"", b""))


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(PySAPUtilsFieldsTest))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite())
