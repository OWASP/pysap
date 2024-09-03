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
# External imports
# Custom imports
from tests.utils import data_filename
from pysap.SAPSSFS import (SAPSSFSKey, SAPSSFSData, SAPSSFSLock)


class PySAPSSFSKeyTest(unittest.TestCase):

    USERNAME = b"SomeUser                "
    HOST =     b"ubuntu                  "

    def test_ssfs_key_parsing(self):
        """Test parsing of a SSFS Key file"""

        with open(data_filename("ssfs_hdb_key"), "rb") as fd:
            s = fd.read()

        key = SAPSSFSKey(s)

        self.assertEqual(key.preamble, b"RSecSSFsKey")
        self.assertEqual(key.type, 1)
        self.assertEqual(key.user, self.USERNAME)
        self.assertEqual(key.host, self.HOST)


class PySAPSSFSDataTest(unittest.TestCase):

    USERNAME = b"SomeUser                "
    HOST =     b"ubuntu                  "

    PLAIN_VALUES = {"HDB/KEYNAME/DB_CON_ENV": "Env",
                    "HDB/KEYNAME/DB_DATABASE_NAME": "Database",
                    "HDB/KEYNAME/DB_USER": "SomeUser",
                    }

    def test_ssfs_data_parsing(self):
        """Test parsing of a SSFS Data file"""

        with open(data_filename("ssfs_hdb_dat"), "rb") as fd:
            s = fd.read()

        data = SAPSSFSData(s)
        self.assertEqual(len(data.records), 4)

        for record in data.records:
            self.assertEqual(record.preamble, b"RSecSSFsData")
            self.assertEqual(record.length, len(record))
            self.assertEqual(record.type, 1)
            self.assertEqual(record.user, self.USERNAME)
            self.assertEqual(record.host, self.HOST)

    def test_ssfs_data_record_lookup(self):
        """Test looking up for a record with a given key name in a SSFS Data file."""

        with open(data_filename("ssfs_hdb_dat"), "rb") as fd:
            s = fd.read()

        data = SAPSSFSData(s)

        self.assertFalse(data.has_record("HDB/KEYNAME/UNEXISTENT"))
        self.assertIsNone(data.get_record("HDB/KEYNAME/UNEXISTENT"))
        self.assertIsNone(data.get_value("HDB/KEYNAME/UNEXISTENT"))

        for key, value in list(self.PLAIN_VALUES.items()):
            self.assertTrue(data.has_record(key))
            self.assertIsNotNone(data.get_record(key))
            self.assertEqual(data.get_value(key), value.encode())

            record = data.get_record(key)
            self.assertTrue(record.is_stored_as_plaintext)

    def test_ssfs_data_record_hmac(self):
        """Test validation of header and data with HMAC field in a SSFS Data file."""

        with open(data_filename("ssfs_hdb_dat"), "rb") as fd:
            s = fd.read()
        data = SAPSSFSData(s)

        for record in data.records:
            self.assertTrue(record.valid)

            # Now tamper with the header
            original_user = record.user
            record.user = "NewUser"
            self.assertFalse(record.valid)
            record.user = original_user
            self.assertTrue(record.valid)

            # Now tamper with the data
            orginal_data = record.data
            record.data = orginal_data + "AddedDataBytes"
            self.assertFalse(record.valid)
            record.data = orginal_data
            self.assertTrue(record.valid)

            # Now tamper with the HMAC
            orginal_hmac = record.hmac
            record.hmac = orginal_hmac[:-1] + "A"
            self.assertFalse(record.valid)
            record.hmac = orginal_hmac
            self.assertTrue(record.valid)


class PySAPSSFSDataDecryptTest(unittest.TestCase):

    ENCRYPTED_VALUES = {"HDB/KEYNAME/DB_PASSWORD": "SomePassword"}

    def test_ssfs_data_record_decrypt(self):
        """Test decrypting a record with a given key in a SSFS Data file."""

        with open(data_filename("ssfs_hdb_key"), "rb") as fd:
            s = fd.read()
        key = SAPSSFSKey(s)

        with open(data_filename("ssfs_hdb_dat"), "rb") as fd:
            s = fd.read()
        data = SAPSSFSData(s)

        for name, value in list(self.ENCRYPTED_VALUES.items()):
            self.assertTrue(data.has_record(name))
            self.assertIsNotNone(data.get_record(name))
            self.assertEqual(data.get_value(name, key), value)

            record = data.get_record(name)
            self.assertFalse(record.is_stored_as_plaintext)
            self.assertTrue(record.valid)


if __name__ == "__main__":
    unittest.main(verbosity=1)
