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

import sys
import unittest

from pysap.SAPMS import (SAPMS, SAPMSAdmRecord, SAPMSClient1, SAPMSLogon,
                         SAPMSLogonResponse, SAPMSProperty, SAPMSJ2EEHeader)
from tests.utils import roundtrip_packet


class PySAPMessageServerTest(unittest.TestCase):

    def test_adm_record_roundtrip(self):
        packet = SAPMSAdmRecord(opcode=0x01, parameter="PROFILE")
        parsed = roundtrip_packet(packet)

        self.assertEqual(parsed.opcode, 0x01)
        self.assertEqual(parsed.parameter.rstrip(b"\x00 "), b"PROFILE")

    def test_client_roundtrip(self):
        packet = SAPMSClient1(client="CLIENT", host="HOST", service="DIA",
                              msgtype=0x01, hostaddrv4="127.0.0.1", servno=3200)
        parsed = roundtrip_packet(packet)

        self.assertEqual(parsed.client.rstrip(b"\x00"), b"CLIENT")
        self.assertEqual(parsed.host.rstrip(b"\x00"), b"HOST")
        self.assertEqual(parsed.service.rstrip(b"\x00"), b"DIA")
        self.assertEqual(parsed.servno, 3200)

    def test_property_roundtrip(self):
        packet = SAPMSProperty(client="CLIENT", id=0x07, release="720",
                               patchno=1, supplvl=2, platform=3)
        parsed = roundtrip_packet(packet)

        self.assertEqual(parsed.id, 0x07)
        self.assertEqual(parsed.release.rstrip(b"\x00 "), b"720")
        self.assertEqual(parsed.patchno, 1)
        self.assertEqual(parsed.supplvl, 2)
        self.assertEqual(parsed.platform, 3)

    def test_j2ee_header_roundtrip(self):
        parsed = roundtrip_packet(SAPMSJ2EEHeader())

        self.assertEqual(parsed.sender_cluster_id, SAPMSJ2EEHeader.cluster_no)
        self.assertEqual(parsed.cluster_id, SAPMSJ2EEHeader.cluster_no)

    def test_message_server_diag_port_roundtrip(self):
        packet = SAPMS(flag=0x02, iflag=0x08, diag_port=3300)
        parsed = roundtrip_packet(packet)

        self.assertEqual(parsed.flag, 0x02)
        self.assertEqual(parsed.iflag, 0x08)
        self.assertEqual(parsed.diag_port, 3300)

    def test_message_server_shutdown_opcodes_roundtrip(self):
        for opcode in [0x2e, 0x2f, 0x30, 0x4a]:
            packet = SAPMS(iflag=0x01, opcode=opcode,
                           shutdown_reason="maintenance")
            parsed = roundtrip_packet(packet)

            self.assertEqual(parsed.opcode, opcode)
            self.assertIsNotNone(parsed.shutdown_client)
            self.assertEqual(parsed.shutdown_reason, b"maintenance")

    def test_message_server_ip_to_name_roundtrip(self):
        packet = SAPMS(iflag=0x01, opcode=0x46,
                       ip_to_name_address4="127.0.0.1",
                       ip_to_name_port=3200,
                       ip_to_name="server.example")
        parsed = roundtrip_packet(packet)

        self.assertEqual(parsed.opcode, 0x46)
        self.assertEqual(parsed.ip_to_name_address4, "127.0.0.1")
        self.assertEqual(parsed.ip_to_name_port, 3200)
        self.assertEqual(parsed.ip_to_name, b"server.example")

    def test_message_server_logon_request_roundtrip(self):
        packet = SAPMS(flag=0x02, iflag=0x01, opcode=0x2c,
                       logon=SAPMSLogon(type=0, logonname="PUBLIC",
                                        address6_length=-1))
        parsed = roundtrip_packet(packet)

        self.assertIsInstance(parsed.logon, SAPMSLogon)
        self.assertEqual(parsed.logon.type, 0)
        self.assertEqual(parsed.logon.logonname, b"PUBLIC")
        self.assertEqual(parsed.logon.address6_length, -1)

    def test_message_server_logon_response_roundtrip(self):
        packet = SAPMS(flag=0x03, iflag=0x01, opcode=0x2c,
                       logon=SAPMSLogonResponse(
                           type=0, port=3200, address="127.0.0.1",
                           logonname="PUBLIC", response_data=b"payload",
                           response_tail=b"\x00\x10\x00\x00"))
        parsed = roundtrip_packet(packet)

        self.assertIsInstance(parsed.logon, SAPMSLogonResponse)
        self.assertEqual(parsed.logon.port, 3200)
        self.assertEqual(parsed.logon.logonname, b"PUBLIC")
        self.assertEqual(parsed.logon.response_data, b"payload")
        self.assertEqual(parsed.logon.response_tail, b"\x00\x10\x00\x00")

    def test_message_server_codepage_error_without_payload(self):
        packet = SAPMS(flag=0x03, iflag=0x01, opcode=0x1c,
                       opcode_error=0x05)
        parsed = roundtrip_packet(packet)

        self.assertEqual(parsed.opcode_error, 0x05)
        self.assertFalse(parsed.payload)


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(PySAPMessageServerTest))
    return suite


if __name__ == "__main__":
    test_runner = unittest.TextTestRunner(verbosity=2, resultclass=unittest.TextTestResult)
    result = test_runner.run(suite())
    sys.exit(not result.wasSuccessful())
