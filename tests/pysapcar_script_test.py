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
from pysap.SAPCAR import SAPCARArchive


pytestmark = pytest.mark.bin_script


class PySAPCARScriptTest(unittest.TestCase):

    SCRIPT = join(dirname(dirname(__file__)), "bin", "pysapcar")
    TEST_STRING = b"The quick brown fox jumps over the lazy dog"
    SIGNED_ARCHIVE = data_filename("manifest_signed.sar")
    SIGNER_CERTIFICATE = data_filename("manifest_test_signer.crt")
    SIGNER_KEY = data_filename("manifest_test_signer.key")
    TSA_CERTIFICATE = data_filename("manifest_test_tsa.crt")
    TSA_KEY = data_filename("manifest_test_tsa.key")

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
        self.assertIn("(version 2.00)", result.stdout)
        self.assertNotIn("b'", result.stdout)
        self.assertIn("test_string.txt", result.stdout)

    def test_help_includes_signature_examples(self):
        result = self.run_script("--help")

        self.assertEqual(0, result.returncode)
        self.assertIn("pysapcar -tvf archive --strict-manifest", result.stdout)
        self.assertIn(
            "pysapcar -cvf archive --sign-manifest certificate "
            "--signing-key key [file1 ...]",
            result.stdout,
        )

    def test_validate_manifest_reports_integrity_and_signature_separately(self):
        result = self.run_script(
            "-t", "-f", self.SIGNED_ARCHIVE, "--strict-manifest",
            "--manifest-certificate-dir", dirname(self.SIGNER_CERTIFICATE),
        )

        self.assertEqual(0, result.returncode)
        self.assertIn("manifest integrity=valid signature=valid", result.stdout)

    def test_strict_manifest_highlights_tampered_content(self):
        with tempfile.TemporaryDirectory() as output_dir:
            archive_file = join(output_dir, "tampered.sar")
            payload_file = join(output_dir, "payload.txt")
            manifest_file = join(output_dir, "MANIFEST.MF")
            with open(payload_file, "wb") as payload:
                payload.write(b"tampered payload")
            with open(manifest_file, "w", encoding="utf-8") as manifest:
                manifest.write("[payload]\nfilename=payload.txt\nsha256=%s\n" % ("0" * 64))
            archive = SAPCARArchive(archive_file, "w")
            archive.add_file(payload_file, archive_filename="payload.txt")
            archive.add_file(manifest_file, archive_filename="MANIFEST.MF")
            archive.write()
            archive.close()

            result = self.run_script("-t", "-f", archive_file, "--strict-manifest")

            self.assertEqual(1, result.returncode)
            self.assertIn("digest mismatch for payload.txt", result.stdout)
            self.assertIn("manifest signature is not-present", result.stdout)

    def test_strict_manifest_is_independent_from_break_on_error(self):
        result = self.run_script("-t", "-f", data_filename("car201_test_string.sar"),
                                 "--strict-manifest")

        self.assertEqual(1, result.returncode)
        self.assertIn("no manifest found", result.stdout)

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

    def test_extract_signed_archive_includes_signature_manifest(self):
        with tempfile.TemporaryDirectory() as output_dir:
            result = self.run_script(
                "-x", "-f", self.SIGNED_ARCHIVE, "-o", output_dir,
                "--strict-manifest",
                "--manifest-certificate-dir", dirname(self.SIGNER_CERTIFICATE),
            )

            self.assertEqual(0, result.returncode)
            self.assertIn("2 file(s) processed", result.stdout)
            self.assertTrue(exists(join(output_dir, "payload.txt")))
            self.assertTrue(exists(join(output_dir, "SIGNATURE.SMF")))

    def test_extract_rejects_unsafe_archive_path(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_file = join(directory, "unsafe.sar")
            payload_file = join(directory, "payload.txt")
            output_dir = join(directory, "output")
            with open(payload_file, "wb") as payload:
                payload.write(b"payload")
            archive = SAPCARArchive(archive_file, "w")
            archive.add_file(payload_file, archive_filename="../escaped.txt")
            archive.write()
            archive.close()

            result = self.run_script("-x", "-f", archive_file, "-o", output_dir)

            self.assertEqual(1, result.returncode)
            self.assertIn("unsafe archive member", result.stdout)
            self.assertFalse(exists(join(directory, "escaped.txt")))

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

    def test_create_signed_archive(self):
        with tempfile.TemporaryDirectory() as output_dir:
            archive_file = join(output_dir, "signed.sar")
            payload_file = join(output_dir, "payload.txt")
            with open(payload_file, "wb") as payload:
                payload.write(b"signed payload")
            result = self.run_script(
                "-c", "-f", archive_file,
                "--sign-manifest", self.SIGNER_CERTIFICATE,
                "--signing-key", self.SIGNER_KEY,
                "--timestamp-certificate", self.TSA_CERTIFICATE,
                "--timestamp-key", self.TSA_KEY,
                payload_file,
            )

            self.assertEqual(0, result.returncode)
            with open(archive_file, "rb") as archive_fd:
                report = SAPCARArchive(archive_fd, "r").validate_manifest(
                    strict=True, certificate_dir=dirname(self.SIGNER_CERTIFICATE))
            self.assertTrue(report["valid"])

    def test_signing_with_missing_material_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as output_dir:
            archive_file = join(output_dir, "signed.sar")
            payload_file = join(output_dir, "payload.txt")
            with open(payload_file, "wb") as payload:
                payload.write(b"signed payload")

            result = self.run_script(
                "-c", "-f", archive_file,
                "--sign-manifest", join(output_dir, "missing.crt"),
                "--signing-key", join(output_dir, "missing.key"),
                payload_file,
            )

            self.assertEqual(1, result.returncode)
            self.assertIn("failed to sign manifest", result.stdout)
            self.assertNotIn("Traceback", result.stdout)

    def test_missing_archive_returns_cleanly(self):
        result = self.run_script("-t", "-f", data_filename("does-not-exist.sar"))

        self.assertEqual(1, result.returncode)
        self.assertIn("error opening", result.stdout)
        self.assertNotIn("Traceback", result.stdout)
