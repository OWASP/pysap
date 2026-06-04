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
# Custom imports
from pysap.SAPSNC import SAPSNCFrame, unwrap_snc, wrap_snc


class PySAPSNCFrameTest(unittest.TestCase):

    def test_sapsncframe_roundtrip(self):
        frame = SAPSNCFrame(
            frame_type=0x07,
            token_length=3,
            data_length=4,
            token=b"tok",
            data=b"data",
        )

        parsed = SAPSNCFrame(bytes(frame))
        self.assertEqual(parsed.eye_catcher, b"SNCFRAME")
        self.assertEqual(parsed.frame_type, 0x07)
        self.assertEqual(parsed.protocol_version, 5)
        self.assertEqual(parsed.header_length, 24)
        self.assertEqual(parsed.token_length, 3)
        self.assertEqual(parsed.data_length, 4)
        self.assertEqual(parsed.token, b"tok")
        self.assertEqual(parsed.data, b"data")


class PySAPSNCUtilsTest(unittest.TestCase):

    def test_unwrap_snc_for_data_open_and_signed(self):
        for frame_type in [0x07, 0x08]:
            with self.subTest(frame_type=frame_type):
                frame = SAPSNCFrame(
                    frame_type=frame_type,
                    token_length=3,
                    data_length=4,
                    token=b"tok",
                    data=b"data",
                )
                raw = bytes(frame)

                unwrapped, offset = unwrap_snc(raw, 0)
                self.assertEqual(offset, len(raw))
                self.assertEqual(unwrapped, raw + b"data")

    def test_unwrap_snc_is_noop_for_other_frame_types(self):
        frame = SAPSNCFrame(
            frame_type=0x09,
            token_length=3,
            data_length=4,
            token=b"tok",
            data=b"data",
        )
        raw = bytes(frame)

        unwrapped, offset = unwrap_snc(raw, 0)
        self.assertEqual(offset, 0)
        self.assertEqual(unwrapped, raw)

    def test_wrap_snc_for_data_open(self):
        frame = SAPSNCFrame(
            frame_type=0x07,
            token_length=3,
            data_length=4,
            token=b"tok",
            data=b"data",
        )
        raw = bytes(frame)

        wrapped = wrap_snc(raw, 0, b"payload")
        parsed = SAPSNCFrame(wrapped)

        self.assertEqual(parsed.frame_type, 0x07)
        self.assertEqual(parsed.data_length, len(b"payload"))
        self.assertEqual(parsed.data, b"payload")
        self.assertEqual(len(wrapped), parsed.header_length + parsed.token_length + parsed.data_length)

    def test_wrap_snc_is_noop_for_other_frame_types(self):
        frame = SAPSNCFrame(
            frame_type=0x09,
            token_length=3,
            data_length=4,
            token=b"tok",
            data=b"data",
        )
        raw = bytes(frame)

        wrapped = wrap_snc(raw, 0, b"payload")
        self.assertEqual(wrapped, raw)


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(PySAPSNCFrameTest))
    suite.addTest(loader.loadTestsFromTestCase(PySAPSNCUtilsTest))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite())
