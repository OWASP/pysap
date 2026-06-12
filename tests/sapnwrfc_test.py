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

# Standard imports
import struct
import unittest

# Custom imports
from pysap.SAPNWRFC import (NWRFC_MAGIC, SAPRFC_MAGIC, NWRFC_TAGS,
                             NWRFC_TAG_CONSTRAINTS, NWRFC_USERNAME_TAGS,
                             NWRFC_SID_RE, parse_tlv, decode_string, decode_value,
                             find_tlv_field_by_marker, find_tlv_field_by_padd,
                             extract_rfc_params, extract_xml_data)
from pysap.utils.crypto.rfc import ab_scramble, ab_descramble


def build_tlv(tag, value):
    return struct.pack(">HH", tag, len(value)) + value


class PySAPNWRFCTest(unittest.TestCase):

    def test_magic_bytes(self):
        self.assertEqual(NWRFC_MAGIC, b"\x06\xcb\x02\x00")
        self.assertEqual(SAPRFC_MAGIC, b"\x06\x03\x02\x00")
        self.assertNotEqual(NWRFC_MAGIC, SAPRFC_MAGIC)

    def test_parse_tlv_single_field(self):
        value = "100".encode("utf-16-le")
        data = build_tlv(0x0114, value)

        tags = list(parse_tlv(data))

        self.assertEqual(tags, [(0x0114, value)])
        self.assertEqual(decode_string(tags[0][1]), "100")

    def test_parse_tlv_multiple_fields(self):
        client = build_tlv(0x0114, "001".encode("utf-16-le"))
        user = build_tlv(0x0111, "DEVELOPER".encode("utf-16-le"))
        lang = build_tlv(0x0152, "E".encode("utf-16-le"))
        data = client + user + lang

        tags = dict(parse_tlv(data))

        self.assertEqual(decode_string(tags[0x0114]), "001")
        self.assertEqual(decode_string(tags[0x0111]), "DEVELOPER")
        self.assertEqual(decode_string(tags[0x0152]), "E")

    def test_parse_tlv_filters_by_tags(self):
        client = build_tlv(0x0114, "001".encode("utf-16-le"))
        user = build_tlv(0x0111, "DEVELOPER".encode("utf-16-le"))
        data = client + user

        tags = dict(parse_tlv(data, tags=[0x0111]))

        self.assertNotIn(0x0114, tags)
        self.assertEqual(decode_string(tags[0x0111]), "DEVELOPER")

    def test_parse_tlv_skips_out_of_range_length(self):
        # Length constraint for client (0x0114) is (2, 8), so a 1-byte value
        # must be skipped.
        bogus = build_tlv(0x0114, b"\x00")
        valid = build_tlv(0x0114, "001".encode("utf-16-le"))
        data = bogus + valid

        tags = list(parse_tlv(data))

        self.assertEqual(len(tags), 1)
        self.assertEqual(decode_string(tags[0][1]), "001")

    def test_parse_tlv_handles_unaligned_data(self):
        # The TLV stream is preceded by some other header bytes that don't
        # form a valid TLV entry; the scanner should skip forward byte by
        # byte until it finds a recognised tag.
        prefix = b"\x00\x01\x02\x03"
        valid = build_tlv(0x0152, "E".encode("utf-16-le"))
        data = prefix + valid

        tags = list(parse_tlv(data))

        self.assertEqual(len(tags), 1)
        self.assertEqual(tags[0][0], 0x0152)
        self.assertEqual(decode_string(tags[0][1]), "E")

    def test_decode_string_strips_padding(self):
        raw = "DEVELOPER\x00\x00".encode("utf-16-le")
        self.assertEqual(decode_string(raw), "DEVELOPER")

    def test_decode_string_invalid_returns_empty(self):
        self.assertEqual(decode_string(b"\x00"), "")

    def test_decode_value_none(self):
        self.assertIsNone(decode_value(None))

    def test_decode_value_utf16le(self):
        raw = "DEVELOPER\x00\x00".encode("utf-16-le")
        self.assertEqual(decode_value(raw), "DEVELOPER")

    def test_decode_value_ascii(self):
        raw = b"DEVELOPER\x00"
        self.assertEqual(decode_value(raw), "DEVELOPER")

    def test_decode_value_short_ascii(self):
        # Too short to be detected as UTF-16LE (< 4 bytes); falls back to ASCII.
        self.assertEqual(decode_value(b"001"), "001")

    def test_username_tags_priority_order(self):
        self.assertEqual(NWRFC_USERNAME_TAGS, (0x0111, 0x0119, 0x0009))
        for tag in NWRFC_USERNAME_TAGS:
            self.assertEqual(NWRFC_TAGS[tag], "username")

    def test_sid_regex_extraction(self):
        match = NWRFC_SID_RE.search("sapnw752_NPL_00")
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "NPL")

    def test_sid_regex_no_match(self):
        self.assertIsNone(NWRFC_SID_RE.search("sapnw752"))

    def test_tag_constraints_cover_all_tags(self):
        # 0x0203 (param_value) has no length constraint: RFC parameter
        # values vary widely in size (scalars to large XML table fragments).
        for tag in NWRFC_TAGS:
            if tag == 0x0203:
                self.assertNotIn(tag, NWRFC_TAG_CONSTRAINTS)
            else:
                self.assertIn(tag, NWRFC_TAG_CONSTRAINTS)

    def test_parse_tlv_dest_and_ip(self):
        dest = build_tlv(0x0006, "BACKEND".encode("utf-16-le"))
        ip = build_tlv(0x0007, "10.0.0.1".encode("utf-16-le"))
        data = dest + ip

        tags = dict(parse_tlv(data))

        self.assertEqual(decode_string(tags[0x0006]), "BACKEND")
        self.assertEqual(decode_string(tags[0x0007]), "10.0.0.1")

    def test_parse_tlv_param_name_and_value(self):
        name = build_tlv(0x0201, "IV_NAME".encode("utf-16-le"))
        value = build_tlv(0x0203, "Hello, World!".encode("utf-16-le"))
        data = name + value

        tags = dict(parse_tlv(data))

        self.assertEqual(decode_string(tags[0x0201]), "IV_NAME")
        self.assertEqual(decode_string(tags[0x0203]), "Hello, World!")

    def test_find_tlv_field_by_marker_int_tag(self):
        # [end-of-prev (2)][tag (2)][length (2)][value]
        value = "DEVELOPER".encode("utf-16-le")
        data = b"\x00\x00" + struct.pack(">H", 0x0111) + struct.pack(">H", len(value)) + value

        found, end = find_tlv_field_by_marker(data, 0x0111)

        self.assertEqual(found, value)
        self.assertEqual(end, len(data))

    def test_find_tlv_field_by_marker_bytes_tag_and_search_start(self):
        value1 = "001".encode("utf-16-le")
        value2 = "100".encode("utf-16-le")
        entry1 = b"\x00\x00" + b"\x01\x14" + struct.pack(">H", len(value1)) + value1
        entry2 = b"\x00\x00" + b"\x01\x14" + struct.pack(">H", len(value2)) + value2
        data = entry1 + entry2

        found1, end1 = find_tlv_field_by_marker(data, b"\x01\x14")
        self.assertEqual(found1, value1)

        found2, end2 = find_tlv_field_by_marker(data, b"\x01\x14", search_start=end1)
        self.assertEqual(found2, value2)

    def test_find_tlv_field_by_marker_not_found(self):
        data = b"\x00\x00\x01\x11\x00\x00"
        found, end = find_tlv_field_by_marker(data, 0x0117)
        self.assertIsNone(found)
        self.assertEqual(end, 0)

    def test_find_tlv_field_by_padd(self):
        value = "001".encode("utf-16-le")
        padd = b"\x00\x00\x01\x14"
        data = b"garbage" + padd + struct.pack(">H", len(value)) + value

        found = find_tlv_field_by_padd(data, padd)

        self.assertEqual(found, value)

    def test_find_tlv_field_by_padd_not_found(self):
        self.assertIsNone(find_tlv_field_by_padd(b"\x00\x00\x00\x00", b"\x01\x14\x01\x17"))

    def test_parse_tlv_param_value_large(self):
        # 0x0203 has no length constraint, so large values must parse fine.
        big = ("<IT_TABLE>" + "X" * 5000 + "</IT_TABLE>").encode("utf-16-le")
        data = build_tlv(0x0203, big)

        tags = dict(parse_tlv(data))

        self.assertEqual(decode_string(tags[0x0203]), big.decode("utf-16-le"))


class PySAPNWRFCExtractTest(unittest.TestCase):

    def _param_field(self, tag, value):
        return b"\x00\x00" + struct.pack(">H", tag) + struct.pack(">H", len(value)) + value

    def test_extract_rfc_params_single(self):
        name = "IV_GUID".encode("utf-16-le")
        value = "Hello, World!".encode("utf-16-le")
        data = self._param_field(0x0201, name) + self._param_field(0x0203, value)

        params = extract_rfc_params(data)

        self.assertEqual(params, {"IV_GUID": "Hello, World!"})

    def test_extract_rfc_params_multiple(self):
        data = (self._param_field(0x0201, "IV_A".encode("utf-16-le"))
                + self._param_field(0x0203, "1".encode("utf-16-le"))
                + self._param_field(0x0201, "IV_B".encode("utf-16-le"))
                + self._param_field(0x0203, "2".encode("utf-16-le")))

        params = extract_rfc_params(data)

        self.assertEqual(params, {"IV_A": "1", "IV_B": "2"})

    def test_extract_rfc_params_skips_invalid_name(self):
        # Name containing non-identifier characters should be skipped.
        bogus_name = "\x01\x02\x03\x04".encode("utf-16-le")
        data = self._param_field(0x0201, bogus_name) + self._param_field(0x0203, "x".encode("utf-16-le"))

        params = extract_rfc_params(data)

        self.assertEqual(params, {})

    def test_extract_rfc_params_no_value(self):
        name = "IV_GUID".encode("utf-16-le")
        data = self._param_field(0x0201, name)

        params = extract_rfc_params(data)

        self.assertEqual(params, {})

    def test_extract_xml_data_scalar(self):
        raw = b"junk<IV_GUID>abc123==</IV_GUID>"

        result = extract_xml_data(raw)

        self.assertEqual(result, {"IV_GUID": "abc123=="})

    def test_extract_xml_data_table_structured_rows(self):
        raw = (b"<IT_MODULE>"
               b"<item><FIELD>value1</FIELD></item>"
               b"<item><FIELD>value2</FIELD></item>"
               b"</IT_MODULE>")

        result = extract_xml_data(raw)

        self.assertEqual(result, {"IT_MODULE": [{"FIELD": "value1"}, {"FIELD": "value2"}]})

    def test_extract_xml_data_table_scalar_rows(self):
        raw = b"<IT_LINES><item>line1</item><item>line2</item></IT_LINES>"

        result = extract_xml_data(raw)

        self.assertEqual(result, {"IT_LINES": ["line1", "line2"]})

    def test_extract_xml_data_html_unescape(self):
        raw = b"<IV_TEXT>a &amp; b &lt; c</IV_TEXT>"

        result = extract_xml_data(raw)

        self.assertEqual(result, {"IV_TEXT": "a & b < c"})

    def test_extract_xml_data_no_xml(self):
        self.assertEqual(extract_xml_data(b"\x06\xcb\x02\x00binary"), {})


class PySAPNWRFCPasswordTest(unittest.TestCase):

    def test_ab_scramble_roundtrip_ascii(self):
        raw = ab_scramble("secret", seed=0x12345678)
        self.assertEqual(ab_descramble(raw), "secret")

    def test_ab_scramble_roundtrip_utf16le(self):
        raw = ab_scramble("secret", seed=0x12345678, encoding="utf-16-le")
        self.assertEqual(ab_descramble(raw, encoding="utf-16-le"), "secret")

    def test_ab_scramble_random_seed(self):
        raw1 = ab_scramble("secret")
        raw2 = ab_scramble("secret")
        # Random seeds should (almost certainly) differ, producing different
        # ciphertexts for the same plaintext.
        self.assertNotEqual(raw1, raw2)
        self.assertEqual(ab_descramble(raw1), "secret")
        self.assertEqual(ab_descramble(raw2), "secret")

    def test_ab_descramble_too_short_raises(self):
        with self.assertRaises(ValueError):
            ab_descramble(b"\x00\x00\x00")

    def test_nwrfc_password_tlv_roundtrip(self):
        # Simulate an NWRFC password TLV (tag 0x0117): 4-byte seed +
        # ab_scrambled UTF-16LE password.
        scrambled = ab_scramble("s3cr3t!", seed=0xdeadbeef, encoding="utf-16-le")
        data = build_tlv(0x0117, scrambled)

        tags = dict(parse_tlv(data))

        self.assertIn(0x0117, tags)
        self.assertEqual(ab_descramble(tags[0x0117], encoding="utf-16-le"), "s3cr3t!")


if __name__ == "__main__":
    unittest.main()
