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
import sys
import unittest
from io import BytesIO
from struct import pack
from unittest.mock import patch
from os import unlink, rmdir
from os.path import basename, exists
import pytest
# External imports
# Custom imports
from tests.utils import data_filename
from pysap.SAPCAR import (SAPCARArchive, SAPCARArchiveFile, SAPCARArchiveFilev200Format, SAPCARArchiveFilev201Format,
                          SAPCAR_VERSION_200, SAPCAR_VERSION_201, SIZE_FOUR_GB, SAPCARCompressedBlockFormat,
                          SAPCARInvalidFileException, SAPCARInvalidChecksumException, DecompressError)


class PySAPCARTest(unittest.TestCase):

    test_archive_file = "somefile"
    test_filename = b"test_string.txt"
    test_timestamp_raw = 1449010128
    test_timestamp = "01 Dec 2015 22:48"
    test_perm_mode = 33204
    test_permissions = "-rw-rw-r--"
    test_string = b"The quick brown fox jumps over the lazy dog"

    def setUp(self):
        fname = self.test_filename.decode() if isinstance(self.test_filename, bytes) else self.test_filename
        with open(fname, "wb") as fd:
            fd.write(self.test_string)

    def tearDown(self):
        for filename in [self.test_filename, self.test_archive_file]:
            if isinstance(filename, bytes):
                filename = filename.decode()
            if exists(filename):
                unlink(filename)
        if exists("test"):
            rmdir("test")

    def check_sapcar_archive(self, filename, version):
        """Test SAP CAR archive file"""

        with open(data_filename(filename), "rb") as fd:
            sapcar_archive = SAPCARArchive(fd, mode="r")

            self.assertEqual(filename, basename(sapcar_archive.filename))
            self.assertEqual(version, sapcar_archive.version)
            self.assertEqual(1, len(sapcar_archive.files))
            self.assertEqual(1, len(sapcar_archive.files_names))
            self.assertListEqual([self.test_filename], list(sapcar_archive.files_names))
            self.assertListEqual([self.test_filename], list(sapcar_archive.files.keys()))

            af = sapcar_archive.open(self.test_filename)
            self.assertEqual(self.test_string, af.read())
            af.close()

            ff = sapcar_archive.files[self.test_filename]
            self.assertEqual(len(self.test_string), ff.size)
            self.assertEqual(self.test_filename, ff.filename)
            self.assertEqual(self.test_timestamp, ff.timestamp)
            self.assertEqual(self.test_timestamp_raw, ff.timestamp_raw)
            self.assertEqual(self.test_permissions, ff.permissions)
            self.assertEqual(self.test_perm_mode, ff.perm_mode)
            self.assertEqual(version, ff.version)
            self.assertTrue(ff.is_file())
            self.assertFalse(ff.is_directory())

            self.assertTrue(ff.check_checksum())
            self.assertEqual(ff.calculate_checksum(self.test_string), ff.checksum)

            af = ff.open()
            self.assertEqual(self.test_string, af.read())
            af.close()

    def test_sapcar_archive(self):
        """Test some basic construction of a SAP CAR archive"""

        self.assertRaises(ValueError, SAPCARArchive, self.test_archive_file, "w", version="2.02")
        self.assertRaises(ValueError, SAPCARArchive, self.test_archive_file, "x")

    def test_sapcar_archive_200(self):
        """Test SAP CAR archive file version 2.00"""

        self.check_sapcar_archive("car200_test_string.sar", SAPCAR_VERSION_200)

    def test_sapcar_archive_201(self):
        """Test SAP CAR archive file version 2.01"""

        self.check_sapcar_archive("car201_test_string.sar", SAPCAR_VERSION_201)

    def test_sapcar_archive_add_file(self):
        """Test some basic construction of a SAP CAR archive adding from an existent file"""

        ar = SAPCARArchive(self.test_archive_file, "w")
        ar.add_file(self.test_filename)
        ar.add_file(self.test_filename, archive_filename=self.test_filename + b"two")

        self.assertEqual(b"2.01", ar.version)
        self.assertEqual(2, len(ar.files))
        self.assertEqual(2, len(ar.files_names))
        self.assertListEqual([self.test_filename, self.test_filename + b"two"], list(ar.files_names))
        self.assertListEqual([self.test_filename, self.test_filename + b"two"], list(ar.files.keys()))

        for filename in [self.test_filename, self.test_filename + b"two"]:
            af = ar.open(filename)
            self.assertEqual(self.test_string, af.read())
            af.close()

            ff = ar.files[filename]
            self.assertEqual(len(self.test_string), ff.size)
            self.assertEqual(filename, ff.filename)

            self.assertTrue(ff.check_checksum())
            self.assertEqual(ff.calculate_checksum(self.test_string), ff.checksum)

            af = ff.open()
            self.assertEqual(self.test_string, af.read())
            af.close()

        ar.write()
        ar.close()

    def test_sapcar_archive_file_from_file(self):
        """Test SAP CAR archive file object construction from file using the original name
        and a different one"""
        ff = SAPCARArchiveFile.from_file(self.test_filename)
        self.assertEqual(len(self.test_string), ff.size)
        self.assertEqual(self.test_filename, ff.filename)
        self.assertTrue(ff.check_checksum())

        af = ff.open()
        self.assertEqual(self.test_string, af.read())
        af.close()

        test_filename_new = b"some_other_filename.txt"
        ff = SAPCARArchiveFile.from_file(self.test_filename, archive_filename=test_filename_new)
        self.assertEqual(len(self.test_string), ff.size)
        self.assertEqual(test_filename_new, ff.filename)
        self.assertTrue(ff.check_checksum())

        af = ff.open()
        self.assertEqual(self.test_string, af.read())
        af.close()

    def test_sapcar_archive_file_200_to_201(self):
        """Test SAP CAR archive file object conversion from 2.00 to 2.01"""

        with open(data_filename("car200_test_string.sar"), "rb") as fd200:
            ar200 = SAPCARArchive(fd200, mode="r")
            ff200 = ar200.files[self.test_filename]
            ff201 = SAPCARArchiveFile.from_archive_file(ff200, SAPCAR_VERSION_201)

            self.assertEqual(ff200.size, ff201.size)
            self.assertEqual(ff200.filename, ff201.filename)
            self.assertEqual(ff200.timestamp, ff201.timestamp)
            self.assertEqual(ff200.timestamp_raw, ff201.timestamp_raw)
            self.assertEqual(ff200.permissions, ff201.permissions)
            self.assertEqual(ff200.perm_mode, ff201.perm_mode)
            self.assertEqual(ff200.checksum, ff201.checksum)
            self.assertIs(ff200.is_file(), ff201.is_file())
            self.assertIs(ff200.is_directory(), ff201.is_directory())

            af = ff201.open()
            self.assertEqual(self.test_string, af.read())
            af.close()

    def test_sapcar_archive_200_to_201(self):
        """Test SAP CAR archive object conversion from 2.00 to 2.01"""

        with open(data_filename("car200_test_string.sar"), "rb") as fd:
            ar = SAPCARArchive(fd, mode="r")
            ff200 = ar.files[self.test_filename]

            ar.version = SAPCAR_VERSION_201
            ff201 = ar.files[self.test_filename]

            self.assertEqual(ff200.size, ff201.size)
            self.assertEqual(ff200.filename, ff201.filename)
            self.assertEqual(ff200.timestamp, ff201.timestamp)
            self.assertEqual(ff200.timestamp_raw, ff201.timestamp_raw)
            self.assertEqual(ff200.permissions, ff201.permissions)
            self.assertEqual(ff200.perm_mode, ff201.perm_mode)
            self.assertEqual(ff200.checksum, ff201.checksum)
            self.assertIs(ff200.is_file(), ff201.is_file())
            self.assertIs(ff200.is_directory(), ff201.is_directory())

            af = ff201.open()
            self.assertEqual(self.test_string, af.read())
            af.close()

    def test_sapcar_archive_201_to_200(self):
        """Test SAP CAR archive object conversion from 2.01 to 2.00"""

        with open(data_filename("car201_test_string.sar"), "rb") as fd:
            ar = SAPCARArchive(fd, mode="r")
            ff201 = ar.files[self.test_filename]

            ar.version = SAPCAR_VERSION_200
            ff200 = ar.files[self.test_filename]

            self.assertEqual(ff200.size, ff201.size)
            self.assertEqual(ff200.filename, ff201.filename)
            self.assertEqual(ff200.timestamp, ff201.timestamp)
            self.assertEqual(ff200.timestamp_raw, ff201.timestamp_raw)
            self.assertEqual(ff200.permissions, ff201.permissions)
            self.assertEqual(ff200.perm_mode, ff201.perm_mode)
            self.assertEqual(ff200.checksum, ff201.checksum)
            self.assertIs(ff200.is_file(), ff201.is_file())
            self.assertIs(ff200.is_directory(), ff201.is_directory())

            af = ff200.open()
            self.assertEqual(self.test_string, af.read())
            af.close()

    def test_sapcar_archive_file_length(self):

        for cls in [SAPCARArchiveFilev200Format, SAPCARArchiveFilev201Format]:
            ff = cls()

            # Test several get file length combinations
            ff.file_length_low = 0
            ff.file_length_high = 0
            self.assertEqual(ff.file_length, 0)

            ff.file_length_low = 99999
            ff.file_length_high = 0
            self.assertEqual(ff.file_length, 99999)

            ff.file_length_low = 0
            ff.file_length_high = 99999
            self.assertEqual(ff.file_length, SIZE_FOUR_GB * 99999)

            ff.file_length_low = 99999
            ff.file_length_high = 99999
            self.assertEqual(ff.file_length, (SIZE_FOUR_GB * 99999) + 99999)

            # Test several set file length combinations
            ff.file_length = 0
            self.assertEqual(ff.file_length_low, 0)
            self.assertEqual(ff.file_length_high, 0)

            ff.file_length = 99999
            self.assertEqual(ff.file_length_low, 99999)
            self.assertEqual(ff.file_length_high, 0)

            ff.file_length = SIZE_FOUR_GB * 99999
            self.assertEqual(ff.file_length_low, 0)
            self.assertEqual(ff.file_length_high, 99999)

            ff.file_length = (SIZE_FOUR_GB * 99999) + 99999
            self.assertEqual(ff.file_length_low, 99999)
            self.assertEqual(ff.file_length_high, 99999)


def _block(kind, data, checksum=0):
    if kind in (b"DA", b"ED"):
        block = SAPCARArchiveFile.from_data(data, b"chunk")._file_format.blocks[0]
        block.type = kind
        block.checksum = checksum
        return bytes(block)
    return kind + pack("<I", len(data)) + data + (pack("<i", checksum) if kind == b"UE" else b"")


@pytest.mark.parametrize("kind", [b"UD", b"UE"])
def test_uncompressed_block_wire_format(kind):
    raw = _block(kind, b"abc", -123)
    block = SAPCARCompressedBlockFormat(raw + b"tail")
    assert block.uncompressed_length == 3
    assert block.uncompressed == b"abc"
    assert bytes(block.payload) == b"tail"
    block.remove_payload()
    assert bytes(block) == raw
    built = SAPCARCompressedBlockFormat(type=kind, uncompressed=b"abc", checksum=-123)
    assert bytes(built) == raw


@pytest.mark.parametrize("version", [SAPCAR_VERSION_200, SAPCAR_VERSION_201])
@pytest.mark.parametrize("kinds", [(b"UD", b"UE"), (b"DA", b"UE"), (b"UD", b"ED"), (b"DA", b"ED")])
def test_mixed_blocks_and_following_member(version, kinds):
    first, second = b"first block", b"second block"
    value = first + second
    member = SAPCARArchiveFile.from_data(value, b"one", version)
    member._file_format.blocks = []
    crc = member.calculate_checksum(value)
    raw = b"CAR " + version + bytes(member._file_format)
    raw += _block(kinds[0], first) + _block(kinds[1], second, crc)
    following = SAPCARArchiveFile.from_data(b"next", b"two", version)
    raw += bytes(following._file_format)
    archive = SAPCARArchive(BytesIO(raw), "r")
    assert bytes(archive._sapcar) == raw
    assert list(archive.files) == [b"one", b"two"]
    member = archive.files[b"one"]
    assert member.open(enforce_checksum=True).read() == value
    assert member.checksum == crc
    assert member.check_checksum()
    assert archive.files[b"two"].open(enforce_checksum=True).read() == b"next"
    member.checksum = crc ^ 1
    with pytest.raises(SAPCARInvalidChecksumException):
        member.open(enforce_checksum=True)
    member.checksum = crc
    target = SAPCAR_VERSION_201 if version == SAPCAR_VERSION_200 else SAPCAR_VERSION_200
    archive.version = target
    converted = SAPCARArchive(BytesIO(bytes(archive._sapcar)), "r")
    assert list(converted.files) == [b"one", b"two"]
    assert converted.files[b"one"].open(enforce_checksum=True).read() == value
    # Conversion must not append members to Scapy's shared default lists.
    assert not SAPCARArchive(BytesIO(), "w", target).files


@pytest.mark.parametrize("kind", [b"ED", b"UE"])
def test_truncated_blocks_and_unknown_types(kind):
    valid = _block(kind, b"abc")
    member = SAPCARArchiveFile.from_data(b"abc", b"one")
    member._file_format.blocks = []
    header = b"CAR 2.01" + bytes(member._file_format)
    invalid_blocks = [valid[:length] for length in range(len(valid))]
    invalid_blocks += [b"XX" + valid[2:], b"ED" + pack("<I", 7) + b"x" * 11]
    for raw in invalid_blocks:
        if raw:
            with pytest.raises(SAPCARInvalidFileException):
                SAPCARCompressedBlockFormat(raw)
        with pytest.raises(SAPCARInvalidFileException):
            SAPCARArchive(BytesIO(header + raw), "r")


@pytest.mark.parametrize("kind", [b"DA", b"UD"])
def test_missing_terminal_block(kind):
    member = SAPCARArchiveFile.from_data(b"abc", b"one")
    member._file_format.blocks = [SAPCARCompressedBlockFormat(_block(kind, b"abc"))]
    with pytest.raises(SAPCARInvalidFileException, match="Missing end"):
        member.open()
    with pytest.raises(SAPCARInvalidFileException):
        SAPCARArchive(BytesIO(b"CAR 2.01" + bytes(member._file_format)), "r")


def test_extraction_checks_lengths_before_decompression():
    member = SAPCARArchiveFile.from_data(b"abc", b"one")
    member._file_format.blocks[0].compressed.uncompress_length = 0xffffffff
    with patch("pysap.SAPCAR.decompress") as decoder:
        with pytest.raises(SAPCARInvalidFileException, match="decompression length"):
            member.open()
        decoder.assert_not_called()
    member._file_format.blocks[0].compressed.uncompress_length = 3
    with patch("pysap.SAPCAR.decompress", return_value=(0, 3, b"ab")):
        with pytest.raises(DecompressError):
            member.open()
    member._file_format.file_length = 4
    with pytest.raises(SAPCARInvalidFileException, match="Extracted length"):
        member.open()


def test_uncompressed_length_and_terminal_block_validation():
    member = SAPCARArchiveFile.from_data(b"abc", b"one")
    block = SAPCARCompressedBlockFormat(_block(b"UE", b"abc"))
    member._file_format.blocks = [block]
    for declared, member_size in [(4, 3), (3, 2)]:
        block.uncompressed_length = declared
        member._file_format.file_length = member_size
        output = BytesIO()
        with pytest.raises(SAPCARInvalidFileException, match="uncompressed block length"):
            member._file_format.extract(output)
        assert not output.getvalue()
    block.uncompressed_length = member._file_format.file_length = 3
    member._file_format.blocks.append(block.copy())
    with pytest.raises(SAPCARInvalidFileException, match="Blocks follow"):
        member.open()
    with pytest.raises(SAPCARInvalidFileException, match="More than one"):
        _ = member.checksum


@pytest.mark.parametrize("version", [SAPCAR_VERSION_200, SAPCAR_VERSION_201])
def test_version_conversion_keeps_archives_independent(version):
    archive = SAPCARArchive(BytesIO(), "w", version)
    member = SAPCARArchiveFile.from_data(b"abc", b"named.txt", version)
    member._file_format.user_info = b"info"
    member._file_format.user_info_length = 4
    archive._files.append(member._file_format)
    original_files = archive._files
    archive.version = SAPCAR_VERSION_201 if version == SAPCAR_VERSION_200 else SAPCAR_VERSION_200
    assert len(original_files) == 1
    assert not SAPCARArchive(BytesIO(), "w", archive.version).files
    converted = SAPCARArchive(BytesIO(bytes(archive._sapcar)), "r").files[b"named.txt"]
    assert converted.open(enforce_checksum=True).read() == b"abc"
    assert converted._file_format.user_info == b"info"


def test_many_uncompressed_blocks():
    value = b"a" * 256
    member = SAPCARArchiveFile.from_data(value, b"one")
    member._file_format.blocks = []
    raw = b"CAR 2.01" + bytes(member._file_format)
    raw += _block(b"UD", b"a") * 255
    raw += _block(b"UE", b"a", member.calculate_checksum(value))
    parsed = SAPCARArchive(BytesIO(raw), "r").files[b"one"]
    assert len(parsed._file_format.blocks) == 256
    assert parsed.open(enforce_checksum=True).read() == value


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(PySAPCARTest))
    return suite


if __name__ == "__main__":
    test_runner = unittest.TextTestRunner(verbosity=2, resultclass=unittest.TextTestResult)
    result = test_runner.run(suite())
    sys.exit(not result.wasSuccessful())
