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

import sys
import unittest
from unittest import mock
from struct import pack

from scapy.packet import Raw

from pysap.SAPEnqueue import (SAPEnqueue, SAPEnqueueParam,
                              SAPEnqueueStreamSocket, SAPEnqueueTracePattern)
from tests.utils import roundtrip_packet


class PySAPEnqueueTest(unittest.TestCase):

    def test_trace_pattern_roundtrip(self):
        packet = SAPEnqueueTracePattern(len=6, pattern="TRACE")
        parsed = roundtrip_packet(packet)

        self.assertEqual(parsed.len, 6)
        self.assertEqual(parsed.pattern, b"TRACE")

    def test_param_roundtrip(self):
        packet = SAPEnqueueParam(param=0x03, set_name="SERVER")
        parsed = roundtrip_packet(packet)

        self.assertEqual(parsed.param, 0x03)
        self.assertEqual(parsed.set_name, b"SERVER")

    def test_enqueue_connection_admin_roundtrip(self):
        packet = SAPEnqueue(dest=0x06, opcode=0x01,
                            params=[SAPEnqueueParam(param=0x03, set_name="ENQ")])
        parsed = roundtrip_packet(packet)

        self.assertEqual(parsed.dest, 0x06)
        self.assertEqual(parsed.opcode, 0x01)
        self.assertEqual(parsed.params_count, 1)
        self.assertEqual(parsed.params[0].param, 0x03)
        self.assertEqual(parsed.params[0].set_name, b"ENQ")

    def test_stream_socket_fragment_reassembly(self):
        def _with_fragment_length(packet, fragment_length):
            raw = bytearray(bytes(packet))
            raw[8:12] = pack("!I", fragment_length)
            raw[12:16] = pack("!I", fragment_length)
            return SAPEnqueue(bytes(raw))

        first = _with_fragment_length(SAPEnqueue(more_frags=1) / Raw(b"hello"), 30)
        second = SAPEnqueue(bytes(SAPEnqueue(more_frags=0) / Raw(b"world")))
        sock = object.__new__(SAPEnqueueStreamSocket)

        with mock.patch("pysap.SAPEnqueue.SAPRoutedStreamSocket.recv", side_effect=[first, second]):
            packet = SAPEnqueueStreamSocket.recv(sock)

        self.assertIn(SAPEnqueue, packet)
        self.assertEqual(packet[SAPEnqueue].payload.load, b"helloworld")


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(PySAPEnqueueTest))
    return suite


if __name__ == "__main__":
    test_runner = unittest.TextTestRunner(verbosity=2, resultclass=unittest.TextTestResult)
    result = test_runner.run(suite())
    sys.exit(not result.wasSuccessful())
