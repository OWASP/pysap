# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# Copyright (C) 2012-2016 by Martin Gallo, Core Security
#
# The library was designed and developed by Martin Gallo from the Security
# Consulting Services team of Core Security.
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

# Standard imports
import unittest
from os.path import basename
# External imports
# Custom imports
from tests.utils import data_filename
from pysap.SAPCAR import SAPCARArchive


class PySAPCARTest(unittest.TestCase):

    test_filename = "test_string.txt"
    test_timestamp = "01 Dec 2015 19:48"
    test_permissions = "-rw-rw-r--"
    test_string = "The quick brown fox jumps over the lazy dog"

    def check_sapcar_archive(self, filename, version):
        """Test SAP CAR archive file version 201"""

        with open(data_filename(filename)) as fd:
            sapcar_archive = SAPCARArchive(fd, mode="r")

            self.assertEqual(filename, basename(sapcar_archive.filename))
            self.assertEqual(version, sapcar_archive.version)
            self.assertEqual(1, len(sapcar_archive.files))
            self.assertEqual(1, len(sapcar_archive.files_names))
            self.assertListEqual([self.test_filename], sapcar_archive.files_names)
            self.assertListEqual([self.test_filename], sapcar_archive.files.keys())

            af = sapcar_archive.open(self.test_filename)
            self.assertEqual(self.test_string, af.read())
            af.close()

            ff = sapcar_archive.files[self.test_filename]
            self.assertEqual(len(self.test_string), ff.size)
            self.assertEqual(self.test_filename, ff.filename)
            self.assertEqual(self.test_timestamp, ff.timestamp)
            self.assertEqual(self.test_permissions, ff.permissions)

            self.assertTrue(ff.check_checksum())
            self.assertEqual(ff.calculate_checksum(self.test_string), ff.checksum)

            af = ff.open()
            self.assertEqual(self.test_string, af.read())
            af.close()

    def test_sapcar_archive_200(self):
        """Test SAP CAR archive file version 200"""

        self.check_sapcar_archive("car200_test_string.sar", "2.00")

    def test_sapcar_archive_201(self):
        """Test SAP CAR archive file version 201"""

        self.check_sapcar_archive("car201_test_string.sar", "2.01")


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(PySAPCARTest))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite())
