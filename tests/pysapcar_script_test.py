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
import tempfile
import unittest
from os.path import dirname, join
# External imports
import pytest
# Custom imports
from tests.utils import data_filename, script_env


pytestmark = pytest.mark.bin_script


class PySAPCARScriptTest(unittest.TestCase):

    SCRIPT = join(dirname(dirname(__file__)), "bin", "pysapcar")
    TEST_STRING = b"The quick brown fox jumps over the lazy dog"

    def run_script(self, *args):
        return subprocess.run(
            [sys.executable, self.SCRIPT] + list(args),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=script_env(),
            check=False,
        )

    def test_list_archive(self):
        result = self.run_script("-t", "-f", data_filename("car200_test_string.sar"))

        self.assertEqual(0, result.returncode)
        self.assertIn("Processing archive", result.stdout)
        self.assertIn("test_string.txt", result.stdout)

    def test_list_archive_with_filename_filter(self):
        result = self.run_script("-t", "-f", data_filename("car201_test_string.sar"), "test_string.txt")

        self.assertEqual(0, result.returncode)
        self.assertIn("test_string.txt", result.stdout)

    def test_extract_archive(self):
        with tempfile.TemporaryDirectory() as output_dir:
            result = self.run_script("-x", "-f", data_filename("car200_test_string.sar"), "-o", output_dir)

            self.assertEqual(0, result.returncode)
            self.assertIn("1 file(s) processed", result.stdout)
            with open(join(output_dir, "test_string.txt"), "rb") as extracted_file:
                self.assertEqual(self.TEST_STRING, extracted_file.read())

    def test_create_and_append_archive(self):
        with tempfile.TemporaryDirectory() as output_dir:
            archive_file = join(output_dir, "created.sar")
            first_file = join(output_dir, "first.txt")
            second_file = join(output_dir, "second.txt")
            with open(first_file, "wb") as first:
                first.write(b"first")
            with open(second_file, "wb") as second:
                second.write(b"second")

            create_result = self.run_script("-c", "-f", archive_file, first_file)
            append_result = self.run_script("-a", "-f", archive_file, second_file)
            list_result = self.run_script("-t", "-f", archive_file)

            self.assertEqual(0, create_result.returncode)
            self.assertEqual(0, append_result.returncode)
            self.assertEqual(0, list_result.returncode)
            self.assertIn("first.txt", list_result.stdout)
            self.assertIn("second.txt", list_result.stdout)

    def test_missing_archive_returns_cleanly(self):
        result = self.run_script("-t", "-f", data_filename("does-not-exist.sar"))

        self.assertEqual(0, result.returncode)
        self.assertIn("error opening", result.stdout)
        self.assertNotIn("Traceback", result.stdout)
