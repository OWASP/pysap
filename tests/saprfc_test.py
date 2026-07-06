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

import struct
import sys
import unittest

from pysap.SAPRFC import DEF_FIELDS, SAPRFCDTStruct, SAPRFCEXTEND, SAPRFCPING, SAPRFC
from tests.utils import roundtrip_packet


class PySAPRFCTest(unittest.TestCase):

    def test_rfc_extend_roundtrip(self):
        packet = SAPRFCEXTEND(short_dest_name="DEST", ncpic_lu="LU", ncpic_tp="TP")
        parsed = roundtrip_packet(packet)

        self.assertEqual(parsed.short_dest_name.strip(), b"DEST")
        self.assertEqual(parsed.ncpic_lu.strip(), b"LU")
        self.assertEqual(parsed.ncpic_tp.strip(), b"TP")

    def test_rfc_dt_struct_roundtrip(self):
        packet = SAPRFCDTStruct(user="USER", long_lu="LONG_LU", long_tp="LONG_TP")
        parsed = roundtrip_packet(packet)

        self.assertEqual(parsed.user.rstrip(b"\x00 "), b"USER")
        self.assertEqual(parsed.long_lu.rstrip(b"\x00 "), b"LONG_LU")
        self.assertEqual(parsed.long_tp.rstrip(b"\x00 "), b"LONG_TP")

    def test_rfc_ping_roundtrip(self):
        packet = SAPRFCPING(fields_test=[DEF_FIELDS(start_field1="FIELD") for _ in range(7)])
        parsed = roundtrip_packet(packet)

        self.assertEqual(len(parsed.fields_test), 7)
        self.assertEqual(parsed.fields_test[0].start_field1, b"FIELD")

    def test_rfc_version_three_client_roundtrip(self):
        packet = SAPRFC(version=3, req_type=0x03, address="127.0.0.1",
                        service="sapgw00", lu="LU", tp="TP",
                        conversation_id="CONV")
        parsed = roundtrip_packet(packet)

        self.assertEqual(parsed.version, 3)
        self.assertEqual(parsed.req_type, 0x03)
        self.assertEqual(parsed.address, "127.0.0.1")
        self.assertEqual(parsed.service.strip(), b"sapgw00")

    def test_rfc_version_six_appc_roundtrip(self):
        packet = SAPRFC(version=6, func_type=0xca)
        parsed = roundtrip_packet(packet)

        self.assertEqual(parsed.version, 6)
        self.assertEqual(parsed.func_type, 0xca)

    def test_rfc_f_sap_send_receive_without_codepage(self):
        # F_SAP_SEND (0xcb) with vector=F_V_RECEIVE and info3 lacking
        # GW_WITH_CODE_PAGE leaves codepage_size2 as None. Dissection used to
        # raise TypeError comparing None > 0 for the "repl" condition.
        raw = bytearray()
        raw += bytes([0x06])               # version
        raw += bytes([0xcb])               # func_type
        raw += bytes([0x03])               # protocol
        raw += bytes([0x00])               # mode
        raw += struct.pack("!H", 0)        # uid
        raw += struct.pack("!H", 0)        # gw_id
        raw += struct.pack("!H", 0)        # err_len
        raw += bytes([0x00])               # info2
        raw += bytes([0x01])               # trace_level
        raw += struct.pack("!I", 0)        # time
        raw += bytes([0x00])               # info3 - no GW_WITH_CODE_PAGE
        raw += struct.pack("!i", -1)       # timeout
        raw += bytes([0x00])               # info4
        raw += struct.pack("!I", 0)        # seq_no
        raw += struct.pack("!H", 0)        # sap_param_len
        raw += bytes([0x00])               # padd_appc
        raw += struct.pack("!H", 0)        # info - no SYNC_CPIC_FUNCTION
        raw += bytes([0x08])               # vector - F_V_RECEIVE
        raw += struct.pack("!I", 0)        # appc_rc
        raw += struct.pack("!I", 0)        # sap_rc
        raw += b"\x00" * 8                 # conv_id
        raw += b"\x05\x00\x00\x00"         # anon_repl_sign for F_V_RECEIVE
        raw += b"PAYLOADDATA1234"

        packet = SAPRFC(bytes(raw))

        self.assertEqual(packet.version, 6)
        self.assertEqual(packet.func_type, 0xcb)
        self.assertIsNone(packet.codepage_size2)
        self.assertIsNone(packet.repl)


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(PySAPRFCTest))
    return suite


if __name__ == "__main__":
    test_runner = unittest.TextTestRunner(verbosity=2, resultclass=unittest.TextTestResult)
    result = test_runner.run(suite())
    sys.exit(not result.wasSuccessful())
