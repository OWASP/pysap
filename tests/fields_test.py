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
#   Code contributed by SecureAuth to the OWASP CBAS project
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
                                AdjustableFieldLenField, ASN1F_CHOICE_SAFE)


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


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(PySAPUtilsFieldsTest))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite())
