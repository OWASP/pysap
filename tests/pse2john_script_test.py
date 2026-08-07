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
from io import StringIO
from importlib.util import module_from_spec, spec_from_file_location
from os.path import join
import sys
import unittest
# Custom imports
from tests.utils import REPO_ROOT, data_filename


def load_pse2john():
    spec = spec_from_file_location("pse2john", join(REPO_ROOT, "extra", "pse2john.py"))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PSE2JohnTest(unittest.TestCase):

    def test_process_file_v2_lps_off_pbes1_3des_sha1(self):
        """Test extracting John the Ripper material from a v2 PBES1 encrypted PSE"""

        pse2john = load_pse2john()
        out = StringIO()
        err = StringIO()

        result = pse2john.process_file(data_filename("pse_v2_lps_off_pbes1_3des_sha1.pse"), out, err)

        self.assertTrue(result)
        self.assertEqual(
            out.getvalue(),
            "pse_v2_lps_off_pbes1_3des_sha1.pse:$pse$1$10000$8$77cb6908be860865$0$$16$"
            "24ee62740976ada0e7a41ade3552ee42:::::\n"
        )
        self.assertEqual(err.getvalue(), "")

    def test_process_file_v4_lps_off_pbes1_3des_sha1(self):
        """Test extracting John the Ripper material from a v4 PBES1 encrypted PSE"""

        pse2john = load_pse2john()
        out = StringIO()
        err = StringIO()

        result = pse2john.process_file(data_filename("pse_v4_lps_off_pbes1_3des_sha1.pse"), out, err)

        self.assertTrue(result)
        self.assertEqual(
            out.getvalue(),
            "pse_v4_lps_off_pbes1_3des_sha1.pse:$pse$1$10000$8$a4e5d94c81aea2fa$0$$20$"
            "c74899707d2a9ebdb50f4bd658c0e64379e3c4bb:::::\n"
        )
        self.assertEqual(err.getvalue(), "")

    def test_process_plain_pse_is_unsupported(self):
        """Test that plain PSE files are not accepted as John the Ripper material"""

        pse2john = load_pse2john()
        out = StringIO()
        err = StringIO()
        plain_pse = data_filename("pse_v2_lps_off_pbes1_3des_sha1_plain.pse")

        result = pse2john.process_file(plain_pse, out, err)

        self.assertFalse(result)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(err.getvalue(), "{}: Unsupported PSE file type\n".format(plain_pse))

    def test_process_files_continues_after_unsupported_pse(self):
        """Test that unsupported PSE files are reported and don't stop processing"""

        pse2john = load_pse2john()
        out = StringIO()
        err = StringIO()

        valid_pse = data_filename("pse_v2_lps_off_pbes1_3des_sha1.pse")
        plain_pse = data_filename("pse_v2_lps_off_pbes1_3des_sha1_plain.pse")
        other_valid_pse = data_filename("pse_v4_lps_off_pbes1_3des_sha1.pse")

        self.assertTrue(pse2john.process_file(valid_pse, out, err))
        self.assertFalse(pse2john.process_file(plain_pse, out, err))
        self.assertTrue(pse2john.process_file(other_valid_pse, out, err))

        self.assertEqual(
            out.getvalue(),
            "pse_v2_lps_off_pbes1_3des_sha1.pse:$pse$1$10000$8$77cb6908be860865$0$$16$"
            "24ee62740976ada0e7a41ade3552ee42:::::\n"
            "pse_v4_lps_off_pbes1_3des_sha1.pse:$pse$1$10000$8$a4e5d94c81aea2fa$0$$20$"
            "c74899707d2a9ebdb50f4bd658c0e64379e3c4bb:::::\n"
        )
        self.assertEqual(
            err.getvalue(),
            "{}: Unsupported PSE file type\n".format(plain_pse)
        )


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(PSE2JohnTest))
    return suite


if __name__ == "__main__":
    test_runner = unittest.TextTestRunner(verbosity=2, resultclass=unittest.TextTestResult)
    result = test_runner.run(suite())
    sys.exit(not result.wasSuccessful())
