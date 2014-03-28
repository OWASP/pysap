## ===========
## pysap - Python library for crafting SAP's network protocols packets
##
## Copyright (C) 2014 Core Security Technologies
##
## The library was designed and developed by Martin Gallo from the Security
## Consulting Services team of Core Security Technologies.
##
## This program is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License
## as published by the Free Software Foundation; either version 2
## of the License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##==============

# Standard imports
import unittest
from binascii import unhexlify
from os.path import join as join, dirname


def read_data_file(filename):
    filename = join(dirname(__file__), 'data', filename)
    with open(filename, 'r') as f:
        data = f.read()

    data = data.replace('\n', ' ').replace(' ', '')
    data = unhexlify(data)

    return data


class PySAPCompressTest(unittest.TestCase):

    test_string_plain = "TEST" * 70
    test_string_compr_lzc = "\x18\x01\x00\x00\x11\x1f\x9d\x8dT\x8aL\xa1\x12p`A\x82\x02\x11\x1aLx\xb0!\xc3\x87\x0b#*\x9c\xe8PbE\x8a\x101Z\xccx\xb1#\xc7\x8f\x1bCj\x1c\xe9QdI\x92 Q\x9aLy\xf2 "  # + "\x00"*2
    test_string_compr_lzh = "\x18\x01\x00\x00\x12\x1f\x9d\x02{!\xae\xc1!!\xa3\x18\x03\x03\x00\x00"

    def test_import(self):
        try:
            import pysapcompress  # @UnusedImport
        except ImportError, e:
            self.Fail(str(e))

    def test_compress_input(self):
        """ Test compress function input.
        """
        from pysapcompress import compress, CompressError
        self.assertRaisesRegexp(CompressError, "invalid input length", compress, "")
        self.assertRaisesRegexp(CompressError, "unknown algorithm", compress, "TestString", algorithm=999)

    def test_decompress_input(self):
        """ Test decompress function input.
        """
        from pysapcompress import decompress, DecompressError
        self.assertRaisesRegexp(DecompressError, "invalid input length", decompress, "", 1)
        self.assertRaisesRegexp(DecompressError, "input not compressed", decompress, "AAAAAAAA", 1)
        self.assertRaisesRegexp(DecompressError, "unknown algorithm", decompress, "\x0f\x00\x00\x00\xff\x1f\x9d\x00\x00\x00\x00", 1)

    def test_compress_output_lzc(self):
        """ Test compress function output using LZC algorithm.
        """
        from pysapcompress import compress, ALG_LZC
        status, out_length, out = compress(self.test_string_plain, ALG_LZC)

        self.assertTrue(status)
        self.assertEqual(out_length, len(out))
        self.assertEqual(out_length, len(self.test_string_compr_lzc))
        self.assertEqual(out, self.test_string_compr_lzc)

    def test_compress_output_lzh(self):
        """ Test compress function output using LZH algorithm.

        """
        from pysapcompress import compress, ALG_LZH
        status, out_length, out = compress(self.test_string_plain, ALG_LZH)

        self.assertTrue(status)
        self.assertEqual(out_length, len(out))
        self.assertEqual(out_length, len(self.test_string_compr_lzh))
        self.assertEqual(out, self.test_string_compr_lzh)

    def test_decompres_output_lzh(self):
        """ Test decompress function output using LZH algorithm.
        """
        from pysapcompress import decompress
        status, out_length, out = decompress(self.test_string_compr_lzh, len(self.test_string_plain))

        self.assertTrue(status)
        self.assertEqual(out_length, len(out))
        self.assertEqual(out_length, len(self.test_string_plain))
        self.assertEqual(out, self.test_string_plain)

    def test_decompress_login(self):
        """ Test decompression of a login packet. The result is
        compared with decompressed data obtained from SAP GUI.

        """
        from pysapcompress import decompress
        login_compressed = read_data_file('sapgui_730_login_compressed.data')
        login_decompressed = read_data_file('sapgui_730_login_decompressed.data')

        status, out_length, decompressed = decompress(login_compressed, len(login_decompressed))

        self.assertTrue(status)
        self.assertEqual(out_length, len(login_decompressed))
        self.assertEqual(decompressed, login_decompressed)


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(PySAPCompressTest))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite())
