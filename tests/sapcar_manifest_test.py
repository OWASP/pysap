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

import hashlib
import os
import tempfile
import unittest
import shutil

from pysap.SAPCAR import SAPCARArchive
from pysap.SAPCARManifest import SAPCARManifest, SAPCARManifestError
from tests.utils import data_filename


class SAPCARManifestTest(unittest.TestCase):

    SIGNED_ARCHIVE = data_filename("manifest_signed.sar")
    SIGNER_CERTIFICATE = data_filename("manifest_test_signer.crt")
    SIGNER_KEY = data_filename("manifest_test_signer.key")
    TSA_CERTIFICATE = data_filename("manifest_test_tsa.crt")

    def test_parse_sap_manifest_and_signature_metadata(self):
        payload = b"payload"
        digest = hashlib.sha256(payload).hexdigest()
        data = ("SAP-MANIFEST\nVersion: 1.0\nHash: SHA256\n"
                "Signature: PKCS7-TSTAMP\nBody: Digest | Name-Length | Name\n\n"
                "%s 0007 payload\n\n-----BEGIN SIGNATURE-----\n"
                "AA==\n-----END SIGNATURE-----\n" % digest).encode()
        manifest = SAPCARManifest.from_bytes(data, "SIGNATURE.SMF")
        self.assertIsInstance(manifest, SAPCARManifest)
        self.assertEqual("payload", manifest.entries[0].filename)
        self.assertEqual("sha256", manifest.entries[0].digest_algorithm)
        self.assertEqual("unsupported", manifest.signature["status"])
        self.assertTrue(manifest.signed_data.endswith(b"\n\n"))

    def test_reject_duplicate_and_unsafe_entries(self):
        duplicate = b"[one]\nfilename=file\nsha256=" + b"0" * 64 + b"\n[ two ]\nfilename=file\nsha256=" + b"0" * 64 + b"\n"
        with self.assertRaises(SAPCARManifestError):
            SAPCARManifest.from_bytes(duplicate)
        with self.assertRaises(SAPCARManifestError):
            SAPCARManifest.from_bytes(
                b"[one]\nfilename=../file\nsha256=" + b"0" * 64 + b"\n")

    def test_validate_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            payload_name = os.path.join(directory, "payload")
            manifest_name = os.path.join(directory, "MANIFEST.MF")
            archive_name = os.path.join(directory, "archive.sar")
            with open(payload_name, "wb") as fd:
                fd.write(b"payload")
            digest = hashlib.sha256(b"payload").hexdigest()
            with open(manifest_name, "w", encoding="utf-8") as fd:
                fd.write("[file]\nfilename=payload\nsize=7\nsha256=%s\n" % digest)
            archive = SAPCARArchive(archive_name, "w")
            archive.add_file(payload_name, archive_filename="payload")
            archive.add_file(manifest_name, archive_filename="MANIFEST.MF")
            archive.write()
            archive.close()
            with open(archive_name, "rb") as fd:
                report = SAPCARArchive(fd, "r").validate_manifest()
            self.assertTrue(report["valid"])
            self.assertEqual([], report["unexpected"])

    def test_strict_validation_rejects_missing_content_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            payload_name = os.path.join(directory, "payload")
            manifest_name = os.path.join(directory, "MANIFEST.MF")
            archive_name = os.path.join(directory, "archive.sar")
            with open(payload_name, "wb") as payload:
                payload.write(b"payload")
            with open(manifest_name, "w", encoding="utf-8") as manifest:
                manifest.write("[file]\nfilename=payload\n")
            archive = SAPCARArchive(archive_name, "w")
            archive.add_file(payload_name, archive_filename="payload")
            archive.add_file(manifest_name, archive_filename="MANIFEST.MF")
            archive.write()
            archive.close()

            with open(archive_name, "rb") as archive_file:
                report = SAPCARArchive(archive_file, "r").validate_manifest(strict=True)

            self.assertFalse(report["valid"])
            self.assertEqual("strict validation requires a content digest",
                             report["malformed_entries"][0]["error"])

    def test_multiple_manifests_are_rejected_as_ambiguous(self):
        with tempfile.TemporaryDirectory() as directory:
            payload_name = os.path.join(directory, "payload")
            first_manifest = os.path.join(directory, "MANIFEST")
            second_manifest = os.path.join(directory, "MANIFEST.MF")
            archive_name = os.path.join(directory, "archive.sar")
            with open(payload_name, "wb") as payload:
                payload.write(b"payload")
            digest = hashlib.sha256(b"payload").hexdigest()
            manifest = "[file]\nfilename=payload\nsha256=%s\n" % digest
            for manifest_name in (first_manifest, second_manifest):
                with open(manifest_name, "w", encoding="utf-8") as manifest_file:
                    manifest_file.write(manifest)
            archive = SAPCARArchive(archive_name, "w")
            archive.add_file(payload_name, archive_filename="payload")
            archive.add_file(first_manifest, archive_filename="MANIFEST")
            archive.add_file(second_manifest, archive_filename="MANIFEST.MF")
            archive.write()
            archive.close()

            with open(archive_name, "rb") as archive_file:
                report = SAPCARArchive(archive_file, "r").validate_manifest()

            self.assertFalse(report["valid"])
            self.assertEqual("multiple manifest files are ambiguous",
                             report["malformed_entries"][0]["error"])

    def test_signed_fixture_validates_with_test_certificate(self):
        with open(self.SIGNED_ARCHIVE, "rb") as archive_file:
            archive = SAPCARArchive(archive_file, "r")
            manifest = archive.read_manifest()
            report = archive.validate_manifest(
                strict=True, certificate_dir=os.path.dirname(self.SIGNER_CERTIFICATE))
        self.assertTrue(report["valid"])
        self.assertEqual("valid", report["signature_status"])
        self.assertEqual(
            "valid",
            manifest.verify_signature(
                certificate_dir=os.path.dirname(self.SIGNER_CERTIFICATE)),
        )

    def test_valid_signature_with_unrelated_trust_is_unverified(self):
        with tempfile.TemporaryDirectory() as directory:
            unrelated_dir = os.path.join(directory, "unrelated")
            os.makedirs(unrelated_dir)
            shutil.copy(self.TSA_CERTIFICATE, unrelated_dir)

            with open(self.SIGNED_ARCHIVE, "rb") as archive_file:
                report = SAPCARArchive(archive_file, "r").validate_manifest(
                    strict=True, certificate_dir=unrelated_dir)

            self.assertFalse(report["valid"])
            self.assertTrue(report["integrity_valid"])
            self.assertEqual("unverified", report["signature_status"])

    def test_signing_rejects_duplicate_archive_members(self):
        with tempfile.TemporaryDirectory() as directory:
            first = os.path.join(directory, "first")
            second = os.path.join(directory, "second")
            archive_name = os.path.join(directory, "duplicate.sar")
            with open(first, "wb") as payload:
                payload.write(b"first")
            with open(second, "wb") as payload:
                payload.write(b"second")
            archive = SAPCARArchive(archive_name, "w")
            archive.add_file(first, archive_filename="payload")
            archive.add_file(second, archive_filename="payload")

            with self.assertRaisesRegex(SAPCARManifestError, "duplicate archive member"):
                archive.sign_manifest(self.SIGNER_CERTIFICATE, self.SIGNER_KEY)

            archive.close()

    def test_permissive_signing_allows_duplicate_archive_members(self):
        with tempfile.TemporaryDirectory() as directory:
            first = os.path.join(directory, "first")
            second = os.path.join(directory, "second")
            archive_name = os.path.join(directory, "duplicate.sar")
            with open(first, "wb") as payload:
                payload.write(b"first")
            with open(second, "wb") as payload:
                payload.write(b"second")
            archive = SAPCARArchive(archive_name, "w")
            archive.add_file(first, archive_filename="payload")
            archive.add_file(second, archive_filename="payload")

            manifest = archive.sign_manifest(
                self.SIGNER_CERTIFICATE, self.SIGNER_KEY, strict=False)

            self.assertEqual(2, sum(line.endswith(b" payload")
                                    for line in manifest.splitlines()))
            archive.close()


if __name__ == "__main__":
    unittest.main()
