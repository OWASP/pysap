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
from os.path import dirname, exists, join
# External imports
import pytest
# Custom imports
from tests.utils import data_filename, script_env


pytestmark = pytest.mark.bin_script


class PySAPGenPSESecLoginScriptTest(unittest.TestCase):

    SCRIPT = join(dirname(dirname(__file__)), "bin", "pysapgenpse")

    def run_script(self, *args):
        return subprocess.run(
            [sys.executable, self.SCRIPT] + list(args),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=script_env(),
            check=False,
        )

    def test_seclogin_lists_credentials(self):
        result = self.run_script("-c", "seclogin", "-l", "-f", data_filename("credv2_lps_off_v0_3des"))

        self.assertEqual(0, result.returncode)
        self.assertIn("Reading credentials file", result.stdout)
        self.assertIn("CN=PSEOwner", result.stdout)
        self.assertIn("/secudir/pse-v2-noreq-DSA-1024-SHA1.pse", result.stdout)
        self.assertNotIn("b'CN=PSEOwner'", result.stdout)
        self.assertNotIn("b'/secudir/", result.stdout)
        self.assertIn("1 readable SSO-Credentials available", result.stdout)

    def test_seclogin_decrypts_credentials(self):
        result = self.run_script(
            "-c", "seclogin",
            "-d",
            "-f", data_filename("credv2_lps_off_v1_aes256"),
            "-u", "username",
            "--no-decrypt-provider",
        )

        self.assertEqual(0, result.returncode)
        self.assertIn("PIN:", result.stdout)
        self.assertIn("1234567890", result.stdout)
        self.assertNotIn("b'1234567890'", result.stdout)

    def test_seclogin_writes_decrypted_pin_as_ascii(self):
        with tempfile.TemporaryDirectory() as output_dir:
            output_file = join(output_dir, "pin.txt")
            result = self.run_script(
                "-c", "seclogin",
                "-d",
                "-f", data_filename("credv2_lps_off_v1_aes256"),
                "-u", "username",
                "--no-decrypt-provider",
                "-o", output_file,
            )

            self.assertEqual(0, result.returncode)
            self.assertIn("Output written to file", result.stdout)
            with open(output_file, "rb") as output:
                self.assertEqual(b"1234567890", output.read())

    def test_missing_credential_file_returns_cleanly(self):
        result = self.run_script("-c", "seclogin", "-l", "-f", data_filename("does-not-exist"))

        self.assertEqual(0, result.returncode)
        self.assertIn("Error reading credentials file", result.stdout)
        self.assertNotIn("Traceback", result.stdout)


class PySAPGenPSEPSEScriptTest(unittest.TestCase):

    SCRIPT = join(dirname(dirname(__file__)), "bin", "pysapgenpse")
    DECRYPT_PIN = "1234567980"

    def run_script(self, *args):
        return subprocess.run(
            [sys.executable, self.SCRIPT] + list(args),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=script_env(),
            check=False,
        )

    def test_get_pse_certs_decrypts_pse(self):
        result = self.run_script(
            "-c", "get_pse_certs",
            "-f", data_filename("pse_v2_lps_off_pbes1_3des_sha1.pse"),
            "-x", self.DECRYPT_PIN,
        )

        self.assertEqual(0, result.returncode)
        self.assertIn("Reading PSE file", result.stdout)
        self.assertIn("Decrypted PSE", result.stdout)

    def test_get_pse_certs_reads_plain_pse_without_pin(self):
        with tempfile.TemporaryDirectory() as output_dir:
            output_file = join(output_dir, "certs.der")

            result = self.run_script(
                "-c", "get_pse_certs",
                "-f", data_filename("pse_v2_lps_off_pbes1_3des_sha1_plain.pse"),
                "-o", output_file,
            )

            self.assertEqual(0, result.returncode)
            self.assertIn("Reading PSE file", result.stdout)
            self.assertIn("Read plain PSE", result.stdout)
            self.assertNotIn("No PIN provided", result.stdout)
            self.assertTrue(exists(output_file))
            with open(output_file, "rb") as output:
                output_data = output.read()
            with open(data_filename("pse_v2_lps_off_pbes1_3des_sha1_cert.der"), "rb") as expected:
                self.assertEqual(expected.read(), output_data)

    def test_get_pse_certs_requires_pin_for_encrypted_pse(self):
        result = self.run_script(
            "-c", "get_pse_certs",
            "-f", data_filename("pse_v2_lps_off_pbes1_3des_sha1.pse"),
        )

        self.assertEqual(0, result.returncode)
        self.assertIn("Reading PSE file", result.stdout)
        self.assertIn("No PIN provided", result.stdout)

    def test_get_pse_certs_writes_output_file(self):
        with tempfile.TemporaryDirectory() as output_dir:
            output_file = join(output_dir, "certs.der")
            result = self.run_script(
                "-c", "get_pse_certs",
                "-f", data_filename("pse_v2_lps_off_pbes1_3des_sha1.pse"),
                "-x", self.DECRYPT_PIN,
                "-o", output_file,
            )

            self.assertEqual(0, result.returncode)
            self.assertIn("Output written to file", result.stdout)
            self.assertTrue(exists(output_file))
            with open(output_file, "rb") as output:
                self.assertTrue(output.read().startswith(b"\x30"))

    def test_missing_pse_file_returns_cleanly(self):
        result = self.run_script(
            "-c", "get_pse_certs",
            "-f", data_filename("does-not-exist.pse"),
            "-x", self.DECRYPT_PIN,
        )

        self.assertEqual(0, result.returncode)
        self.assertIn("Error reading PSE file", result.stdout)
        self.assertNotIn("Traceback", result.stdout)
