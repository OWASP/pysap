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
from unittest.mock import patch
# External imports
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import Hash, SHA1
from cryptography.hazmat.primitives.hmac import HMAC
# Custom imports
from pysap.SAPLPS import SAPLPSCipher, SAPLPSDecryptionError
from pysap.SAPLPS import cred_key_lps_fallback


def encrypt_aes_cbc_zero_iv(key, plaintext):
    encryptor = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16), backend=default_backend()).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


class PySAPLPSCipherTest(unittest.TestCase):

    fallback_context = b"CredEncryption"
    fallback_encryption_key = b"\x01" * 16
    fallback_plaintext = b"0123456789ABCDEF"
    dpapi_encryption_key = b"\x02" * 16
    dpapi_plaintext = b"FEDCBA9876543210"

    def build_fallback_cipher(self):
        digest = Hash(SHA1(), backend=default_backend())
        digest.update(cred_key_lps_fallback)
        hashed_key = digest.finalize()

        hmac = HMAC(hashed_key, SHA1(), backend=default_backend())
        hmac.update(self.fallback_context)
        default_key = hmac.finalize()[:16]

        encrypted_key = encrypt_aes_cbc_zero_iv(default_key, self.fallback_encryption_key)
        encrypted_data = encrypt_aes_cbc_zero_iv(self.fallback_encryption_key, self.fallback_plaintext)
        return SAPLPSCipher(
            version=2,
            lps_type=SAPLPSCipher.LPS_FALLBACK,
            context=self.fallback_context,
            encrypted_key=encrypted_key,
            encrypted_data=encrypted_data,
        )

    def build_dpapi_cipher(self):
        encrypted_data = encrypt_aes_cbc_zero_iv(self.dpapi_encryption_key, self.dpapi_plaintext)
        return SAPLPSCipher(
            version=2,
            lps_type=SAPLPSCipher.LPS_DPAPI,
            context=b"",
            encrypted_key=b"",
            encrypted_data=encrypted_data,
        )

    def test_decrypt_rejects_unsupported_version(self):
        cipher = SAPLPSCipher(version=1, lps_type=SAPLPSCipher.LPS_FALLBACK)

        with self.assertRaisesRegex(SAPLPSDecryptionError, "Version not supported"):
            cipher.decrypt()

    def test_decrypt_rejects_unknown_lps_type(self):
        cipher = SAPLPSCipher(version=2, lps_type=99)

        with self.assertRaisesRegex(SAPLPSDecryptionError, "Invalid LPS decryption method"):
            cipher.decrypt()

    def test_decrypt_encryption_key_fallback(self):
        cipher = self.build_fallback_cipher()
        self.assertEqual(cipher.decrypt_encryption_key_fallback(), self.fallback_encryption_key)

    def test_decrypt_fallback(self):
        cipher = self.build_fallback_cipher()
        self.assertEqual(cipher.decrypt(), self.fallback_plaintext)

    def test_decrypt_encryption_key_dpapi(self):
        cipher = self.build_dpapi_cipher()

        with patch("pysap.SAPLPS.dpapi_decrypt_blob", return_value=self.dpapi_encryption_key) as decrypt_blob:
            self.assertEqual(cipher.decrypt_encryption_key_dpapi(), self.dpapi_encryption_key)
            decrypt_blob.assert_called_once_with(b"")

    def test_decrypt_dpapi(self):
        cipher = self.build_dpapi_cipher()

        with patch("pysap.SAPLPS.dpapi_decrypt_blob", return_value=self.dpapi_encryption_key) as decrypt_blob:
            self.assertEqual(cipher.decrypt(), self.dpapi_plaintext)
            decrypt_blob.assert_called_once_with(b"")

    def test_decrypt_tpm_raises(self):
        cipher = SAPLPSCipher(version=2, lps_type=SAPLPSCipher.LPS_TPM)

        with self.assertRaises(NotImplementedError):
            cipher.decrypt()


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(PySAPLPSCipherTest))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite())
