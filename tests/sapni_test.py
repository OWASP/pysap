# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# Copyright (C) 2014 Core Security Technologies
#
# The library was designed and developed by Martin Gallo from the Security
# Consulting Services team of Core Security Technologies.
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
import socket
import unittest
from threading import Thread
from struct import pack, unpack
from SocketServer import BaseRequestHandler, ThreadingTCPServer
# External imports
from scapy.fields import StrField
from scapy.packet import Packet, Raw
# Custom imports
from pysap.SAPNI import SAPNI, SAPNIStreamSocket


class PySAPNITest(unittest.TestCase):

    test_string = "LALA" * 10

    def test_sapni_building(self):
        """Test SAPNI length field building"""
        sapni = SAPNI() / self.test_string

        (sapni_length, ) = unpack("!I", str(sapni)[:4])
        self.assertEqual(sapni_length, len(self.test_string))
        self.assertEqual(sapni.payload.load, self.test_string)

    def test_sapni_dissection(self):
        """Test SAPNI length field dissection"""

        data = pack("!I", len(self.test_string)) + self.test_string
        sapni = SAPNI(data)
        sapni.decode_payload_as(Raw)

        self.assertEqual(sapni.length, len(self.test_string))
        self.assertEqual(sapni.payload.load, self.test_string)


class SAPNITestHandler(BaseRequestHandler):
    """Basic SAP NI echo server"""

    def handle(self):
        data = self.request.recv(4)
        (length, ) = unpack("!I", data)
        data = self.request.recv(length)

        response_length = pack("!I", len(data))
        self.request.sendall(response_length + data)


class SAPNITestHandlerKeepAlive(SAPNITestHandler):
    """Basic SAP NI keep alive server"""

    def handle(self):
        self.request.sendall("\x00\x00\x00\x08NI_PING\x00")
        SAPNITestHandler.handle(self)


class PySAPNIStreamSocketBase(unittest.TestCase):

    test_port = 8005
    test_string = "TEST" * 10
    handler_cls = SAPNITestHandler

    def setUp(self):
        self.server = ThreadingTCPServer(("127.0.0.1", self.test_port),
                                         self.handler_cls,
                                         bind_and_activate=False)
        self.server.allow_reuse_address = True
        self.server.server_bind()
        self.server.server_activate()
        self.server_thread = Thread(target=self.server.serve_forever)
        self.server_thread.start()

    def tearDown(self):
        self.client.close()
        self.server.shutdown()
        self.server.server_close()


class PySAPNIStreamSocket(PySAPNIStreamSocketBase):

    def test_sapnistreamsocket(self):
        """Test SAPNIStreamSocket"""
        sock = socket.socket()
        sock.connect(("127.0.0.1", self.test_port))

        self.client = SAPNIStreamSocket(sock)
        packet = self.client.sr(self.test_string)
        packet.decode_payload_as(Raw)
        self.client.close()

        self.assertIn(SAPNI, packet)
        self.assertEqual(packet[SAPNI].length, len(self.test_string))
        self.assertEqual(packet.payload.load, self.test_string)

    def test_sapnistreamsocket_base_cls(self):
        """Test SAPNIStreamSocket handling of custom base packet classes"""

        class SomeClass(Packet):
            fields_desc = [StrField("text", None)]

        sock = socket.socket()
        sock.connect(("127.0.0.1", self.test_port))

        self.client = SAPNIStreamSocket(sock, base_cls=SomeClass)
        packet = self.client.sr(self.test_string)
        self.client.close()

        self.assertIn(SAPNI, packet)
        self.assertIn(SomeClass, packet)
        self.assertEqual(packet[SAPNI].length, len(self.test_string))
        self.assertEqual(packet[SomeClass].text, self.test_string)

    def test_sapnistreamsocket_getnisocket(self):
        """Test SAPNIStreamSocket get nisocket class method"""

        self.client = SAPNIStreamSocket.get_nisocket("127.0.0.1",
                                                     self.test_port)

        packet = self.client.sr(self.test_string)
        packet.decode_payload_as(Raw)
        self.client.close()

        self.assertIn(SAPNI, packet)
        self.assertEqual(packet[SAPNI].length, len(self.test_string))
        self.assertEqual(packet.payload.load, self.test_string)


class PySAPNIStreamSocketKeepAlive(PySAPNIStreamSocketBase):

    handler_cls = SAPNITestHandlerKeepAlive

    def test_sapnistreamsocket_without_keep_alive(self):
        """Test SAPNIStreamSocket without keep alive"""
        sock = socket.socket()
        sock.connect(("127.0.0.1", self.test_port))

        self.client = SAPNIStreamSocket(sock, keep_alive=False)
        packet = self.client.sr(self.test_string)
        packet.decode_payload_as(Raw)
        self.client.close()

        # We should receive a PING instead of our packet
        self.assertIn(SAPNI, packet)
        self.assertEqual(packet[SAPNI].length, len(SAPNI.SAPNI_PING))
        self.assertEqual(packet.payload.load, SAPNI.SAPNI_PING)

    def test_sapnistreamsocket_with_keep_alive(self):
        """Test SAPNIStreamSocket with keep alive"""
        sock = socket.socket()
        sock.connect(("127.0.0.1", self.test_port))

        self.client = SAPNIStreamSocket(sock, keep_alive=True)
        packet = self.client.sr(self.test_string)
        packet.decode_payload_as(Raw)
        self.client.close()

        # We should receive our packet, the PING should be handled by the
        # stream socket
        self.assertIn(SAPNI, packet)
        self.assertEqual(packet[SAPNI].length, len(self.test_string))
        self.assertEqual(packet.payload.load, self.test_string)


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(PySAPNITest))
    suite.addTest(loader.loadTestsFromTestCase(PySAPNIStreamSocket))
    suite.addTest(loader.loadTestsFromTestCase(PySAPNIStreamSocketKeepAlive))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite())
