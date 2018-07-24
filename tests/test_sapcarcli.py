# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# Copyright (C) 2012-2018 by Martin Gallo, Core Security
#
# The library was designed and developed by Martin Gallo from
# Core Security's CoreLabs team.
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
from __future__ import unicode_literals, absolute_import
import unittest

try:
    from unittest import mock
except ImportError:
    import mock

from testfixtures import LogCapture
from tests.utils import data_filename
from pysap.sapcarcli import PySAPCAR
from pysap.SAPCAR import SAPCARArchive

class PySAPCARCLITest(unittest.TestCase):
    def setUp(self):
        self.cli = PySAPCAR()
        self.cli.mode = "r"
        self.cli.archive_fd = open(data_filename("car201_test_string.sar"), "rb")
        self.cli.logger.handlers = []  # Mute logging while running unit tests
        self.log = LogCapture()  # Enable logger output checking

    def tearDown(self):
        try:
            self.cli.archive_fd.close()
        except Exception:
            pass
        self.log.uninstall()

    def test_open_archive_fd_not_set(self):
        temp = self.cli.archive_fd  # Backup test archive file handle
        self.cli.archive_fd = None
        self.assertIsNone(self.cli.open_archive())
        self.cli.archive_fd = temp

    def test_open_archive_raises_exception(self):
        # While SAPCARArchive is defined in pysap.SAPCAR, it's looked up in sapcarcli, so we need to patch it there
        # See https://docs.python.org/3/library/unittest.mock.html#where-to-patch for details
        with mock.patch("pysap.sapcarcli.SAPCARArchive") as mock_archive:
            mock_archive.side_effect = Exception("unit test exception")
            self.assertIsNone(self.cli.open_archive())
            mock_archive.assert_called_once_with(self.cli.archive_fd, mode=self.cli.mode)

    def test_open_archive_succeeds(self):
        self.assertIsInstance(self.cli.open_archive(), SAPCARArchive)

    def test_target_files_no_kwargs(self):
        names = sorted(["list", "of", "test", "names"])
        self.assertEqual(names, [n for n in self.cli.target_files(names)])

    def test_target_files_with_kwargs(self):
        names = sorted(["list", "of", "test", "names"])
        targets = sorted(["list", "names", "blah"])
        self.assertEqual(["list", "names"], [n for n in self.cli.target_files(names, targets)])

    def test_list_open_fails(self):
        with mock.patch.object(self.cli, "open_archive", return_value=None):
            self.assertIsNone(self.cli.list(None, None))

    def test_list_succeeds(self):
        archive_attrs = {
            "files_names": ["test_string.txt", "blah.so"],
            "files": {
                "test_string.txt": mock.MagicMock(**{
                    "permissions": "-rw-rw-r--",
                    "size": 43,
                    "timestamp": "01 Dec 2015 22:48",
                    "filename": "test_string.txt"
            }),
                "blah.so": mock.MagicMock(**{
                    "permissions": "-rwxrwxr-x",
                    "size": 1243,
                    "timestamp": "01 Dec 2017 13:37",
                    "filename": "blah.so"
                })
            }
        }
        mock_archive = mock.MagicMock(**archive_attrs)
        with mock.patch.object(self.cli, "open_archive", return_value=mock_archive):
            self.cli.list(None, None)
            messages = ("{}  {:>10}    {} {}".format(fil.permissions, fil.size, fil.timestamp, fil.filename)
                        for fil in archive_attrs["files"].values())
            logs = (("pysapcar", "INFO", message) for message in messages)
            self.log.check_present(*logs, order_matters=False)

def test_suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(PySAPCARCLITest))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(test_suite())
