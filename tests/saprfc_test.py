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

import struct
import sys
import unittest

from pysap.SAPEPP import SAPEPP
from pysap.SAPRFC import (DEF_FIELDS, RFCID_CONNECTION, RFCID_END,
                          RFCID_EXTENDED_PASSPORT, SAPRFCDTStruct, SAPRFCEXTEND,
                          SAPRFCPartnerLU, SAPRFCPartnerLUParameters,
                          SAPRFCPING, SAPRFC, SAPRFCRFCIDBody,
                          SAPRFCRFCIDCallBody,
                          SAPRFCRFCIDTransition)
from tests.utils import roundtrip_packet


class PySAPRFCTest(unittest.TestCase):

    def test_rfc_id_constants(self):
        self.assertEqual(RFCID_EXTENDED_PASSPORT, 0x0131)
        self.assertEqual(RFCID_CONNECTION, 0x0514)
        self.assertEqual(RFCID_END, 0xffff)

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

    def test_rfc_partner_long_lu_roundtrip(self):
        packet = SAPRFC(
            version=6, func_type=0x0f, protocol=2, uid=0xffff,
            info2="WITH_LONG_LU_NAME", info="WITH_GW_SAP_PARAMS_HDR",
            conv_id=b"12345678",
            partner_lu_parameters=SAPRFCPartnerLUParameters(
                short_lu=b"192.168.", long_lu_length=13,
                comm_idx=0xffff, conn_idx=2),
            partner_lu=SAPRFCPartnerLU(long_lu=b"192.168.68.67"))

        parsed = roundtrip_packet(packet)

        self.assertEqual(len(bytes(packet)), 224)
        self.assertEqual(parsed.sap_param_len, 144)
        self.assertEqual(parsed.partner_lu_parameters.long_lu_length, 13)
        self.assertEqual(parsed.partner_lu.long_lu.rstrip(), b"192.168.68.67")

    def test_rfc_id_body_epp_roundtrip(self):
        passport = SAPEPP(component=b"RFCID")
        body = SAPRFCRFCIDBody(transitions=[
            SAPRFCRFCIDTransition(
                current_rfc_id=0x0503, next_rfc_id=0x0131,
                value=passport),
            SAPRFCRFCIDTransition(
                current_rfc_id=0x0131, next_rfc_id=0xffff,
                value=b""),
        ])
        packet = SAPRFC(
            version=6, func_type=0xcb, protocol=2, uid=0xffff,
            sap_param_len=8,
            info="SYNC_CPIC_FUNCTION+WITH_GW_SAP_PARAMS_HDR",
            vector="F_V_SEND_DATA+F_V_RECEIVE", conv_id=b"12345678",
            rfc_id_body=body)

        parsed = roundtrip_packet(packet)

        self.assertIsNone(body.rfc_packet_size)
        self.assertEqual(parsed.rfc_id_body.rfc_packet_size,
                         len(bytes(body)) - 8)
        self.assertEqual(len(parsed.rfc_id_body.transitions), 2)
        self.assertIsInstance(parsed.rfc_id_body.transitions[0].value, SAPEPP)
        self.assertEqual(bytes(parsed.rfc_id_body.transitions[0].value),
                         bytes(passport))
        self.assertEqual(parsed.rfc_id_body.transitions[1].next_rfc_id,
                         0xffff)

    def test_rfc_id_body_early_epp_roundtrip(self):
        passport = SAPEPP(component=b"RFCID-EARLY")
        body = SAPRFCRFCIDBody(transitions=[
            SAPRFCRFCIDTransition(current_rfc_id=0x0106,
                                  next_rfc_id=0x0131, value=passport),
            SAPRFCRFCIDTransition(current_rfc_id=0x0131,
                                  next_rfc_id=0x0514,
                                  value=b"CONNECTION-ID-01"),
        ])

        parsed = SAPRFCRFCIDBody(bytes(body))

        self.assertIsInstance(parsed.transitions[0].value, SAPEPP)
        self.assertEqual(parsed.transitions[0].current_rfc_id, 0x0106)
        self.assertEqual(parsed.transitions[0].next_rfc_id, 0x0131)
        self.assertEqual(parsed.transitions[1].next_rfc_id, 0x0514)

    def test_rfc_id_body_empty_roundtrip(self):
        parsed = roundtrip_packet(SAPRFCRFCIDBody())

        self.assertEqual(parsed.transitions, [])
        self.assertEqual(parsed.end_signature, 0xffff)

    def test_rfc_id_call_body_epp_slot_roundtrip(self):
        passport = SAPEPP(component=b"RFCID-CALL")
        padded_passport = bytes(passport).ljust(512, b"\x00")
        body = SAPRFCRFCIDCallBody(transitions=[
            SAPRFCRFCIDTransition(current_rfc_id=0x0502,
                                  next_rfc_id=0x000b,
                                  value="754".encode("utf-16-be")),
            SAPRFCRFCIDTransition(current_rfc_id=0x000b,
                                  next_rfc_id=0x0102,
                                  value="RFC_PING".encode("utf-16-be")),
            SAPRFCRFCIDTransition(current_rfc_id=0x0102,
                                  next_rfc_id=0x0131,
                                  value=padded_passport),
            SAPRFCRFCIDTransition(current_rfc_id=0x0131,
                                  next_rfc_id=0x0512, value=b""),
            SAPRFCRFCIDTransition(current_rfc_id=0x0512,
                                  next_rfc_id=0xffff, value=b""),
        ])
        parsed = SAPRFCRFCIDCallBody(bytes(body))

        self.assertEqual(parsed.initial_rfc_id, 0x0502)
        self.assertEqual(parsed.transitions[2].value_length, 512)
        self.assertIsInstance(parsed.transitions[2].value, SAPEPP)
        self.assertEqual(parsed.transitions[-1].next_rfc_id, 0xffff)

        packet = SAPRFC(version=6, func_type=0xcb, protocol=2, uid=0xffff,
                        sap_param_len=8,
                        info="SYNC_CPIC_FUNCTION+WITH_GW_SAP_PARAMS_HDR",
                        vector="F_V_SEND_DATA+F_V_RECEIVE",
                        conv_id=b"12345678", rfc_id_body=body)
        parsed_packet = roundtrip_packet(packet)
        self.assertIsInstance(parsed_packet.rfc_id_body,
                              SAPRFCRFCIDCallBody)

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
