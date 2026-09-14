# encoding: utf-8

import unittest

from pysap.SAPDiag import SAPDiagItem
from pysap.SAPDiagItems import SAPEPP
from pysap.SAPEPP import (EPP_MAGIC, SAPEPPItem, SAPEPPVariablePart,
                          epp_from_http_header, epp_to_http_header)


class PySAPEPPTest(unittest.TestCase):

    def test_version_3_empty_round_trip(self):
        packet = SAPEPP(component=b"ICM", user=b"anonymous", client=b"000")
        raw = bytes(packet)
        decoded = SAPEPP(raw)

        self.assertEqual(len(raw), 0xe6)
        self.assertEqual(decoded.magic, EPP_MAGIC)
        self.assertEqual(decoded.length, len(raw))
        self.assertEqual(decoded.variable_part_offset, 0xe2)
        self.assertEqual(decoded.variable_part_count, 0)
        self.assertEqual(decoded.trailer, EPP_MAGIC)
        self.assertEqual(bytes(decoded), raw)

    def test_variable_string_item_round_trip(self):
        item = SAPEPPItem(key=1, application=2, item_type=4, value=b"marker")
        part = SAPEPPVariablePart(last=1, part_id=2, items=[item])
        packet = SAPEPP(variable_parts=[part])
        raw = bytes(packet)
        decoded = SAPEPP(raw)

        self.assertEqual(decoded.length, len(raw))
        self.assertEqual(decoded.variable_part_count, 1)
        self.assertEqual(decoded.variable_parts[0].length, 12 + 7 + len(b"marker"))
        self.assertEqual(decoded.variable_parts[0].item_count, 1)
        self.assertEqual(decoded.variable_parts[0].items[0].value, b"marker")
        self.assertEqual(bytes(decoded), raw)

    def test_http_header_round_trip(self):
        packet = SAPEPP(component=b"HTTP")
        value = epp_to_http_header(packet)

        self.assertEqual(value[:8], "2a54482a")
        self.assertEqual(bytes(epp_from_http_header(value)), bytes(packet))

    def test_diag_passport_binding(self):
        for item_type in ("APPL", "APPL4"):
            with self.subTest(item_type=item_type):
                passport = SAPEPP(component=b"SAP GUI")
                item = SAPDiagItem(item_type=item_type, item_id="ST_USER",
                                   item_sid="PASSPORT_DATA",
                                   item_value=passport)
                decoded = SAPDiagItem(bytes(item))

                self.assertIsInstance(decoded.item_value, SAPEPP)
                self.assertEqual(decoded.item_value.component.rstrip(b" "),
                                 b"SAP GUI")


if __name__ == '__main__':
    unittest.main()
