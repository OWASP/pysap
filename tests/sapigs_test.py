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

import importlib
import sys
import unittest
from unittest import mock

from pysap.SAPIGS import SAPIGS, SAPIGSTable
from tests.utils import roundtrip_packet


class PySAPIGSTest(unittest.TestCase):

    def test_table_add_entry_roundtrip(self):
        entry = SAPIGSTable.add_entry("TABLE", 1, 2, 3, "COLUMN", 4)
        parsed = roundtrip_packet(entry)

        self.assertEqual(parsed.table_name.strip(), b"TABLE")
        self.assertEqual(parsed.table_line.strip(), b"1")
        self.assertEqual(parsed.table_width.strip(), b"2")
        self.assertEqual(parsed.column_name.strip(), b"COLUMN")
        self.assertEqual(parsed.column_width.strip(), b"4")

    def test_packet_roundtrip(self):
        packet = SAPIGS(function="FUNCTION", listener="LISTENER", hostname="HOST")
        parsed = roundtrip_packet(packet)

        self.assertEqual(parsed.function.rstrip(b"\x00"), b"FUNCTION")
        self.assertEqual(parsed.listener.rstrip(b"\x00"), b"LISTENER")
        self.assertEqual(parsed.hostname.rstrip(b"\x00"), b"HOST")

    def test_http_request_builder_uses_user_agent(self):
        module = importlib.import_module("pysap.SAPIGS")

        class FakePreparedRequest(object):
            def __init__(self):
                self.method = "POST"
                self.url = "http://host:8000/ZIPPER"
                self.headers = {"Host": "host:8000"}
                self.body = "body"

        class FakeRequest(object):
            def __init__(self, method, url, files=None):
                self.method = method
                self.url = url
                self.files = files

            def prepare(self):
                return FakePreparedRequest()

        with mock.patch.object(module, "Request", FakeRequest):
            request = SAPIGS.http("host", 8000, "ZIPPER")

        self.assertIsInstance(request, bytes)
        self.assertIn(b"POST http://host:8000/ZIPPER HTTP/1.1", request)
        self.assertIn(b"User-Agent: pysap", request)
        self.assertTrue(request.endswith(b"body"))


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(PySAPIGSTest))
    return suite


if __name__ == "__main__":
    test_runner = unittest.TextTestRunner(verbosity=2, resultclass=unittest.TextTestResult)
    result = test_runner.run(suite())
    sys.exit(not result.wasSuccessful())
