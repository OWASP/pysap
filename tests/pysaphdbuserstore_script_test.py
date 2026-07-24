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
import subprocess
import sys
import unittest
from os.path import dirname, join
# External imports
import pytest
# Custom imports
from tests.utils import data_filename, script_env


pytestmark = pytest.mark.bin_script


class PySAPHDBUserStoreScriptTest(unittest.TestCase):

    SCRIPT = join(dirname(dirname(__file__)), "bin", "pysaphdbuserstore")

    @staticmethod
    def run_script(*args):
        command = [sys.executable, PySAPHDBUserStoreScriptTest.SCRIPT]
        command.extend(args)
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=script_env(), check=False)
        output = result.stdout + result.stderr
        return result.returncode, output.decode("utf-8", errors="replace")

    def test_list_records(self):
        """Test listing records from a SSFS Data file."""

        returncode, output = self.run_script("-c", "list",
                                             "-d", data_filename("ssfs_hdb_dat"))

        self.assertEqual(returncode, 0)
        self.assertIn("HDB/KEYNAME/DB_USER\tPlaintext", output)
        self.assertIn("HDB/KEYNAME/DB_PASSWORD\tEncrypted", output)

    def test_get_plaintext_record(self):
        """Test getting a plaintext record from a SSFS Data file."""

        returncode, output = self.run_script("-c", "get",
                                             "-d", data_filename("ssfs_hdb_dat"),
                                             "HDB/KEYNAME/DB_USER")

        self.assertEqual(returncode, 0)
        self.assertIn("Record Key   : HDB/KEYNAME/DB_USER", output)
        self.assertIn("Record Value : b'SomeUser'", output)

    def test_get_encrypted_record_without_decrypt(self):
        """Test getting an encrypted record without decrypting it."""

        returncode, output = self.run_script("-c", "get",
                                             "-d", data_filename("ssfs_hdb_dat"),
                                             "HDB/KEYNAME/DB_PASSWORD")

        self.assertEqual(returncode, 0)
        self.assertIn("Record Key   : HDB/KEYNAME/DB_PASSWORD", output)
        self.assertNotIn("SomePassword", output)

    def test_get_encrypted_record_with_decrypt(self):
        """Test decrypting an encrypted record with a SSFS Key file."""

        returncode, output = self.run_script("-c", "get",
                                             "-d", data_filename("ssfs_hdb_dat"),
                                             "-k", data_filename("ssfs_hdb_key"),
                                             "--decrypt",
                                             "HDB/KEYNAME/DB_PASSWORD")

        self.assertEqual(returncode, 0)
        self.assertIn("Record Key   : HDB/KEYNAME/DB_PASSWORD", output)
        self.assertIn("Record Value : b'SomePassword'", output)

    def test_get_missing_record(self):
        """Test getting a missing record from a SSFS Data file."""

        returncode, output = self.run_script("-c", "get",
                                             "-d", data_filename("ssfs_hdb_dat"),
                                             "HDB/KEYNAME/MISSING")

        self.assertEqual(returncode, 0)
        self.assertIn("Record with key HDB/KEYNAME/MISSING not found", output)

    def test_get_without_record_key_returns_cleanly(self):
        """Test the get command reports a missing record key."""

        returncode, output = self.run_script("-c", "get",
                                             "-d", data_filename("ssfs_hdb_dat"))

        self.assertEqual(returncode, 0)
        self.assertIn("No record key specified", output)
        self.assertNotIn("Traceback", output)

    def test_missing_file_path_returns_cleanly(self):
        """Test missing files are reported without a traceback."""

        returncode, output = self.run_script("-c", "list",
                                             "-d", data_filename("ssfs_missing_dat"))

        self.assertEqual(returncode, 0)
        self.assertIn("Unable to read data", output)
        self.assertNotIn("Traceback", output)
