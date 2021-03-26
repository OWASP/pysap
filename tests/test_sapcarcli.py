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

from os import path

from testfixtures import LogCapture
from tests.utils import data_filename
from pysap.sapcarcli import PySAPCAR
from pysap.SAPCAR import SAPCARArchive, SAPCARArchiveFile, SAPCARInvalidFileException, SAPCARInvalidChecksumException


class PySAPCARCLITest(unittest.TestCase):
    def setUp(self):
        self.mock_file = mock.Mock(
            spec=SAPCARArchiveFile,
            filename=path.join("test", "bl\x00ah"),
            is_directory=lambda: False,
            is_file=lambda: True,
            perm_mode="-rw-rw-r--",
            timestamp_raw=7
        )
        self.mock_dir = mock.Mock(
            spec=SAPCARArchiveFile,
            filename=path.basename(self.mock_file.filename),
            is_directory=lambda: True,
            is_file=lambda: False,
            perm_mode="-rwxrw-r--",
            timestamp_raw=8
        )
        self.mock_archive = mock.Mock(
            spec=SAPCARArchive,
            files={
                self.mock_file.filename: self.mock_file,
                self.mock_dir.filename: self.mock_dir
            }
        )
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
            logs = (("pysap.pysapcar", "INFO", message) for message in messages)
            self.log.check_present(*logs, order_matters=False)

    def test_append_no_args(self):
        self.cli.append(None, [])
        self.log.check_present(("pysap.pysapcar", "ERROR", "pysapcar: no files specified for appending"))

    def test_append_open_fails(self):
        with mock.patch.object(self.cli, "open_archive", return_value=None):
            self.assertIsNone(self.cli.append(None, ["blah"]))
            self.log.check()  # Check that there's no log messages

    def test_append_no_renaming(self):
        names = ["list", "of", "test", "names"]
        mock_sar = mock.Mock(spec=SAPCARArchive)
        # Because of pass by reference and lazy string formatting in logging, we can't actually check that args are
        # being printed correctly. Or we could if we logged a copy of args or str(args) in production code, but it would
        # beat the point of pass by reference and lazy string formatting, so let's not. Left the generator here because
        # it's pretty in it's obscurity. And because someone (probably future me) will probably bang one's head
        # against the same wall I just did before coming to the same realization I just did, so here's a little
        # something for the next poor soul. May it make your head-against-the-wall session shorter than mine was.
        # debugs = (("pysap.pysapcar", "DEBUG", str(names[i + 1:])) for i in range(len(names)))
        infos = (("pysap.pysapcar", "INFO", "d {}".format(name)) for name in names)
        calls = [mock.call.add_file(name, archive_filename=name) for name in names]
        calls.append(mock.call.write())
        with mock.patch.object(self.cli, "open_archive", return_value=mock_sar):
            # Pass copy of names so generator works correctly
            self.cli.append(None, names[:])
            # self.log.check_present(*debugs)
            self.log.check_present(*infos)
            # For some reason mock_sar.assert_has_calls(calls) fails, even though this passes...
            self.assertEqual(calls, mock_sar.mock_calls)

    def test_append_with_renaming(self):
        names = ["test", "/n", "blah", "test", "test", "/n", "blah2"]
        archive_names = [("test", "blah"), ("test", "blah2")]
        # List instead of generator, as we need to insert one line
        infos = [("pysap.pysapcar", "INFO", "d {} (original name {})".format(archive_name, name))
                 for name, archive_name in archive_names]
        infos.insert(1, ("pysap.pysapcar", "INFO", "d {}".format("test")))
        mock_sar = mock.Mock(spec=SAPCARArchive)
        calls = [mock.call.add_file(name, archive_filename=archive_name) for name, archive_name in archive_names]
        calls.insert(1, mock.call.add_file("test", archive_filename="test"))
        calls.append(mock.call.write())
        with mock.patch.object(self.cli, "open_archive", return_value=mock_sar):
            self.cli.append(None, names[:])
            self.log.check_present(*infos)
            # For some reason mock_sar.assert_has_calls(calls) fails, even though this passes...
            self.assertEqual(calls, mock_sar.mock_calls)

    def test_extract_open_fails(self):
        with mock.patch.object(self.cli, "open_archive", return_value=None):
            self.assertIsNone(self.cli.extract(None, None))
            self.log.check()  # Check that there's no log messages

    def test_extract_empty_archive(self):
        with mock.patch.object(self.cli, "open_archive", return_value=self.mock_archive):
            with mock.patch.object(self.cli, "target_files", return_value=[]):
                self.cli.extract(None, None)
                self.log.check(("pysap.pysapcar", "INFO", "pysapcar: 0 file(s) processed"))

    def test_extract_invalid_file_type(self):
        key = self.mock_file.filename
        self.mock_file.is_file = lambda: False
        self.mock_file.is_directory = lambda: False
        with mock.patch.object(self.cli, "open_archive", return_value=self.mock_archive):
            with mock.patch.object(self.cli, "target_files", return_value=[key]):
                key = key.replace("\x00", "")
                self.cli.extract(mock.MagicMock(outdir=False), None)
                self.log.check(
                    ("pysap.pysapcar", "WARNING", "pysapcar: Invalid file type '{}'".format(key)),
                    ("pysap.pysapcar", "INFO", "pysapcar: 0 file(s) processed")
                )

    @mock.patch.multiple("pysap.sapcarcli", autospec=True, utime=mock.DEFAULT, chmod=mock.DEFAULT,
                         makedirs=mock.DEFAULT)
    def test_extract_dir_exists(self, makedirs, chmod, utime):
        makedirs.side_effect = OSError(17, "Unit test error")
        key = self.mock_dir.filename
        with mock.patch.object(self.cli, "open_archive", return_value=self.mock_archive):
            with mock.patch.object(self.cli, "target_files", return_value=[key]):
                key = key.replace("\x00", "")
                self.cli.extract(mock.MagicMock(outdir=False), None)
                makedirs.assert_called_once_with(key)
                chmod.assert_not_called()
                utime.assert_not_called()
                self.log.check(
                    ("pysap.pysapcar", "INFO", "d {}".format(key)),
                    ("pysap.pysapcar", "INFO", "pysapcar: 1 file(s) processed")
                )

    @mock.patch.multiple("pysap.sapcarcli", autospec=True, utime=mock.DEFAULT, chmod=mock.DEFAULT,
                         makedirs=mock.DEFAULT)
    def test_extract_dir_creation_fails(self, makedirs, chmod, utime):
        makedirs.side_effect = OSError(13, "Unit test error")
        key = self.mock_dir.filename
        with mock.patch.object(self.cli, "open_archive", return_value=self.mock_archive):
            with mock.patch.object(self.cli, "target_files", return_value=[key]):
                key = key.replace("\x00", "")
                self.cli.extract(mock.MagicMock(outdir=False), None)
                makedirs.assert_called_once_with(key)
                chmod.assert_not_called()
                utime.assert_not_called()
                self.log.check(
                    ("pysap.pysapcar", "ERROR", "pysapcar: Could not create directory '{}' ([Errno 13] Unit test error)"
                     .format(key)),
                    ("pysap.pysapcar", "INFO", "pysapcar: Stopping extraction"),
                    ("pysap.pysapcar", "INFO", "pysapcar: 0 file(s) processed")
                )

    @mock.patch.multiple("pysap.sapcarcli", autospec=True, utime=mock.DEFAULT, chmod=mock.DEFAULT,
                         makedirs=mock.DEFAULT)
    def test_extract_dir_passes(self, makedirs, chmod, utime):
        key = self.mock_dir.filename
        with mock.patch.object(self.cli, "open_archive", return_value=self.mock_archive):
            with mock.patch.object(self.cli, "target_files", return_value=[key]):
                key = key.replace("\x00", "")
                self.cli.extract(mock.MagicMock(outdir=False), None)
                makedirs.assert_called_once_with(key)
                chmod.assert_called_once_with(key, self.mock_dir.perm_mode)
                utime.assert_called_once_with(key, (self.mock_dir.timestamp_raw, self.mock_dir.timestamp_raw))
                self.log.check(
                    ("pysap.pysapcar", "INFO", "d {}".format(key)),
                    ("pysap.pysapcar", "INFO", "pysapcar: 1 file(s) processed")
                )

    @mock.patch.multiple("pysap.sapcarcli", autospec=True, utime=mock.DEFAULT, fchmod=mock.DEFAULT,
                         makedirs=mock.DEFAULT)
    def test_extract_file_intermediate_dir_exists(self, makedirs, fchmod, utime):
        makedirs.side_effect = OSError(17, "Unit test error")
        key = path.join("test", "bl\x00ah")
        mock_file = mock.Mock(spec=SAPCARArchiveFile, is_directory=lambda: False, perm_mode="-rw-rw-r--",
                              timestamp_raw=7)
        mock_arch = mock.Mock(spec=SAPCARArchive, files={key: mock_file})
        with mock.patch.object(self.cli, "open_archive", return_value=mock_arch):
            with mock.patch.object(self.cli, "target_files", return_value=[key]):
                key = key.replace("\x00", "")
                with mock.patch("pysap.sapcarcli.open", mock.mock_open()) as mock_open:
                    mock_open.return_value.fileno.return_value = 1337  # yo dawg...
                    self.cli.extract(mock.MagicMock(outdir=False), None)
                    dirname = path.dirname(key)
                    makedirs.assert_called_once_with(dirname)
                    fchmod.assert_called_once_with(1337, "-rw-rw-r--")
                    utime.assert_called_once_with(key, (7, 7))
                    self.log.check(
                        ("pysap.pysapcar", "INFO", "d {}".format(key)),
                        ("pysap.pysapcar", "INFO", "pysapcar: 1 file(s) processed")
                    )

    @mock.patch.multiple("pysap.sapcarcli", autospec=True, utime=mock.DEFAULT, fchmod=mock.DEFAULT,
                         makedirs=mock.DEFAULT)
    def test_extract_file_intermediate_dir_creation_fails(self, makedirs, fchmod, utime):
        key = self.mock_file.filename
        makedirs.side_effect = OSError(13, "Unit test error")
        with mock.patch.object(self.cli, "open_archive", return_value=self.mock_archive):
            with mock.patch.object(self.cli, "target_files", return_value=[key]):
                key = key.replace("\x00", "")
                self.cli.extract(mock.MagicMock(outdir=False), None)
                dirname = path.dirname(key)
                makedirs.assert_called_once_with(dirname)
                fchmod.assert_not_called()
                utime.assert_not_called()
                self.log.check(
                    ("pysap.pysapcar", "ERROR", "pysapcar: Could not create intermediate directory '{}' for '{}' "
                                          "(Unit test error)".format(dirname, key)),
                    ("pysap.pysapcar", "INFO", "pysapcar: Stopping extraction"),
                    ("pysap.pysapcar", "INFO", "pysapcar: 0 file(s) processed")
                )

    @mock.patch.multiple("pysap.sapcarcli", autospec=True, utime=mock.DEFAULT, fchmod=mock.DEFAULT,
                         makedirs=mock.DEFAULT)
    def test_extract_file_passes(self, makedirs, fchmod, utime):
        key = self.mock_file.filename
        with mock.patch.object(self.cli, "open_archive", return_value=self.mock_archive):
            with mock.patch.object(self.cli, "target_files", return_value=[key]):
                key = key.replace("\x00", "")
                with mock.patch("pysap.sapcarcli.open", mock.mock_open()) as mock_open:
                    mock_open.return_value.fileno.return_value = 1337  # yo dawg...
                    self.cli.extract(mock.MagicMock(outdir=False), None)
                    dirname = path.dirname(key)
                    makedirs.assert_called_once_with(dirname)
                    fchmod.assert_called_once_with(1337, "-rw-rw-r--")
                    utime.assert_called_once_with(key, (7, 7))
                    self.log.check(
                        ("pysap.pysapcar", "INFO", "d {}".format(dirname)),
                        ("pysap.pysapcar", "INFO", "d {}".format(key)),
                        ("pysap.pysapcar", "INFO", "pysapcar: 1 file(s) processed")
                    )

    @mock.patch.multiple("pysap.sapcarcli", autospec=True, utime=mock.DEFAULT, fchmod=mock.DEFAULT)
    def test_extract_file_invalid_file(self, fchmod, utime):
        key = self.mock_file.filename
        self.mock_file.open.side_effect = SAPCARInvalidFileException("Unit test error")
        with mock.patch.object(self.cli, "open_archive", return_value=self.mock_archive):
            with mock.patch.object(self.cli, "target_files", return_value=[key]):
                self.cli.extract(mock.MagicMock(outdir=False, break_on_error=False), None)
                fchmod.assert_not_called()
                utime.assert_not_called()
                self.log.check(
                    ("pysap.pysapcar", "ERROR", "pysapcar: Invalid SAP CAR file '{}' (Unit test error)"
                     .format(self.cli.archive_fd.name)),
                    ("pysap.pysapcar", "INFO", "pysapcar: Skipping extraction of file '{}'".format(key)),
                    ("pysap.pysapcar", "INFO", "pysapcar: 0 file(s) processed")
                )

    @mock.patch.multiple("pysap.sapcarcli", autospec=True, utime=mock.DEFAULT, fchmod=mock.DEFAULT)
    def test_extract_file_invalid_checksum(self, fchmod, utime):
        key = self.mock_file.filename
        self.mock_file.open.side_effect = SAPCARInvalidChecksumException("Unit test error")
        with mock.patch.object(self.cli, "open_archive", return_value=self.mock_archive):
            with mock.patch.object(self.cli, "target_files", return_value=[key]):
                self.cli.extract(mock.MagicMock(outdir=False, break_on_error=False), None)
                fchmod.assert_not_called()
                utime.assert_not_called()
                self.log.check(
                    ("pysap.pysapcar", "ERROR", "pysapcar: Invalid checksum found for file '{}'"
                     .format(key)),
                    ("pysap.pysapcar", "INFO", "pysapcar: Stopping extraction"),
                    ("pysap.pysapcar", "INFO", "pysapcar: 0 file(s) processed")
                )

    @mock.patch.multiple("pysap.sapcarcli", autospec=True, utime=mock.DEFAULT, fchmod=mock.DEFAULT)
    def test_extract_file_extraction_fails(self, fchmod, utime):
        key = self.mock_file.filename
        with mock.patch.object(self.cli, "open_archive", return_value=self.mock_archive):
            with mock.patch.object(self.cli, "target_files", return_value=[key]):
                key = key.replace("\x00", "")
                with mock.patch("pysap.sapcarcli.open", mock.mock_open()) as mock_open:
                    mock_open.side_effect = OSError(13, "Unit test error")
                    self.cli.extract(mock.MagicMock(outdir=False), None)
                    dirname = path.dirname(key)
                    fchmod.assert_not_called()
                    utime.assert_not_called()
                    self.log.check(
                        ("pysap.pysapcar", "INFO", "d {}".format(dirname)),
                        ("pysap.pysapcar", "ERROR", "pysapcar: Failed to extract file '{}', ([Errno 13] Unit test error)".format(key)),
                        ("pysap.pysapcar", "INFO", "pysapcar: Stopping extraction"),
                        ("pysap.pysapcar", "INFO", "pysapcar: 0 file(s) processed")
                    )


def test_suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(PySAPCARCLITest))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(test_suite())
