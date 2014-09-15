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
from pysap.SAPNI import SAPNI, SAPNIStreamSocket, SAPNIServerThreaded,\
    SAPNIServerHandler


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
    """Basic SAP NI echo server implemented using TCPServer"""

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


class SAPNITestHandlerClose(SAPNITestHandler):
    """Basic SAP NI server that closes the connection"""

    def handle(self):
        self.request.send("")


class PySAPNIStreamSocketTest(unittest.TestCase):

    test_port = 8005
    test_string = "TEST" * 10

    def start_server(self, handler_cls):
        self.server = ThreadingTCPServer(("127.0.0.1", self.test_port),
                                         handler_cls,
                                         bind_and_activate=False)
        self.server.allow_reuse_address = True
        self.server.server_bind()
        self.server.server_activate()
        self.server_thread = Thread(target=self.server.serve_forever)
        self.server_thread.start()

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join()

    def test_sapnistreamsocket(self):
        """Test SAPNIStreamSocket"""
        self.start_server(SAPNITestHandler)

        sock = socket.socket()
        sock.connect(("127.0.0.1", self.test_port))

        self.client = SAPNIStreamSocket(sock)
        packet = self.client.sr(self.test_string)
        packet.decode_payload_as(Raw)
        self.client.close()

        self.assertIn(SAPNI, packet)
        self.assertEqual(packet[SAPNI].length, len(self.test_string))
        self.assertEqual(packet.payload.load, self.test_string)

        self.stop_server()

    def test_sapnistreamsocket_base_cls(self):
        """Test SAPNIStreamSocket handling of custom base packet classes"""
        self.start_server(SAPNITestHandler)

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

        self.stop_server()

    def test_sapnistreamsocket_getnisocket(self):
        """Test SAPNIStreamSocket get nisocket class method"""
        self.start_server(SAPNITestHandler)

        self.client = SAPNIStreamSocket.get_nisocket("127.0.0.1",
                                                     self.test_port)

        packet = self.client.sr(self.test_string)
        packet.decode_payload_as(Raw)
        self.client.close()

        self.assertIn(SAPNI, packet)
        self.assertEqual(packet[SAPNI].length, len(self.test_string))
        self.assertEqual(packet.payload.load, self.test_string)

        self.stop_server()

    def test_sapnistreamsocket_without_keep_alive(self):
        """Test SAPNIStreamSocket without keep alive"""
        self.start_server(SAPNITestHandlerKeepAlive)

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

        self.stop_server()

    def test_sapnistreamsocket_with_keep_alive(self):
        """Test SAPNIStreamSocket with keep alive"""
        self.start_server(SAPNITestHandlerKeepAlive)

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

        self.stop_server()

    def test_sapnistreamsocket_close(self):
        """Test SAPNIStreamSocket with a server that closes the connection"""
        self.start_server(SAPNITestHandlerClose)

        sock = socket.socket()
        sock.connect(("127.0.0.1", self.test_port))

        self.client = SAPNIStreamSocket(sock, keep_alive=False)

        with self.assertRaises(socket.error):
            self.client.sr(self.test_string)

        self.stop_server()


class SAPNIServerTestHandler(SAPNIServerHandler):
    """Basic SAP NI echo server implemented using SAPNIServer"""

    def handle_data(self):
        self.request.send(self.packet)


class PySAPNIServerTest(unittest.TestCase):

    test_port = 8005
    test_string = "TEST" * 10
    handler_cls = SAPNIServerTestHandler

    def start_sapniserver(self):
        self.server = SAPNIServerThreaded(("127.0.0.1", self.test_port),
                                          self.handler_cls,
                                          bind_and_activate=False)
        self.server.allow_reuse_address = True
        self.server.server_bind()
        self.server.server_activate()
        self.server_thread = Thread(target=self.server.serve_forever)
        self.server_thread.start()

    def stop_sapniserver(self):
        self.server.shutdown()
        self.server.server_close()

    def test_sapniserver(self):
        """Test SAPNIServer"""
        self.start_sapniserver()

        sock = socket.socket()
        sock.connect(("127.0.0.1", self.test_port))
        sock.sendall(pack("!I", len(self.test_string)) + self.test_string)

        response = sock.recv(1024)

        self.assertEqual(len(response), len(self.test_string) + 8)
        self.assertEqual(unpack("!I", response[:4]), (len(self.test_string) + 4, ))
        self.assertEqual(unpack("!I", response[4:8]), (len(self.test_string), ))
        self.assertEqual(response[8:], self.test_string)

        sock.close()
        self.stop_sapniserver()

# TODO: SAPNIProxy tests


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(PySAPNITest))
    suite.addTest(loader.loadTestsFromTestCase(PySAPNIStreamSocketTest))
    suite.addTest(loader.loadTestsFromTestCase(PySAPNIServerTest))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite())
