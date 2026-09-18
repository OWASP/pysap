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
import socket
import unittest
from unittest import mock
from threading import Thread
from struct import pack, unpack
from socketserver import BaseRequestHandler, ThreadingTCPServer
# External imports
import pytest
from scapy.fields import StrField
from scapy.packet import Packet, Raw
# Custom imports
from pysap.SAPNI import (SAPNI, SAPNIFrameLengthError, SAPNIStreamSocket,
                         SAPNIServerThreaded, SAPNIServerHandler, SAPNIProxy,
                         SAPNIProxyHandler)


class PySAPBaseServerTest(unittest.TestCase):

    def start_server(self, address, port, handler_cls, server_cls=None):
        if server_cls is None:
            server_cls = ThreadingTCPServer
        self.server = server_cls((address, port), handler_cls,
                                 bind_and_activate=False)
        self.server.allow_reuse_address = True
        self.server.server_bind()
        self.server.server_activate()
        self.server_thread = Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(1)


class PySAPNITest(unittest.TestCase):

    test_string = b"LALA" * 10

    def test_sapni_building(self):
        """Test SAPNI length field building"""
        sapni = SAPNI() / self.test_string

        (sapni_length, ) = unpack("!I", bytes(sapni)[:4])
        self.assertEqual(sapni_length, len(self.test_string))
        self.assertEqual(sapni.payload.load, self.test_string)

    def test_sapni_dissection(self):
        """Test SAPNI length field dissection"""

        data = pack("!I", len(self.test_string)) + self.test_string
        sapni = SAPNI(data)
        sapni.decode_payload_as(Raw)

        self.assertEqual(sapni.length, len(self.test_string))
        self.assertEqual(sapni.payload.load, self.test_string)


class PySAPNIServerHandlerUnitTest(unittest.TestCase):

    def test_clean_stream_eof_stops_handler_without_dispatching(self):
        """A clean Scapy EOF ends the handler without a packet callback."""
        handler = SAPNIServerHandler.__new__(SAPNIServerHandler)
        handler.closed = mock.Mock()
        handler.closed.is_set.return_value = False
        handler.request = mock.Mock()
        handler.request.recv.side_effect = EOFError()
        handler.client_address = ("127.0.0.1", 50000)
        handler.handle_data = mock.Mock()

        handler.handle()

        handler.request.recv.assert_called_once_with()
        handler.handle_data.assert_not_called()


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
        SAPNITestHandler.handle(self)
        self.request.sendall(b"\x00\x00\x00\x08NI_PING\x00")


class SAPNITestHandlerClose(SAPNITestHandler):
    """Basic SAP NI server that closes the connection"""

    def handle(self):
        self.request.send(b"")


class SAPNITestHandlerPartialFrame(BaseRequestHandler):
    """Return a declared frame only partially, then close the connection."""

    def handle(self):
        self.request.sendall(pack("!I", 8) + b"short")


class SAPNITestHandlerOversizedFrame(BaseRequestHandler):
    """Return only an NI header declaring a frame beyond the test limit."""

    def handle(self):
        self.request.sendall(pack("!I", 1025))


class SAPNITestHandlerPartialHeader(BaseRequestHandler):
    """Return only part of an NI header, then close the connection."""

    def handle(self):
        self.request.sendall(b"\x00\x00")


@pytest.mark.integration
class PySAPNIStreamSocketTest(PySAPBaseServerTest):

    test_port = 8010
    test_address = "127.0.0.1"
    test_string = b"TEST" * 10

    def test_sapnistreamsocket(self):
        """Test SAPNIStreamSocket"""
        self.start_server(self.test_address, self.test_port, SAPNITestHandler)

        sock = socket.socket()
        sock.connect((self.test_address, self.test_port))

        self.client = SAPNIStreamSocket(sock)
        packet = self.client.sr(Raw(self.test_string))
        packet.decode_payload_as(Raw)
        self.client.close()

        self.assertIn(SAPNI, packet)
        self.assertEqual(packet[SAPNI].length, len(self.test_string))
        self.assertEqual(packet.payload.load, self.test_string)

        self.stop_server()

    def test_sapnistreamsocket_base_cls(self):
        """Test SAPNIStreamSocket handling of custom base packet classes"""
        self.start_server(self.test_address, self.test_port, SAPNITestHandler)

        class SomeClass(Packet):
            fields_desc = [StrField("text", None)]

        sock = socket.socket()
        sock.connect((self.test_address, self.test_port))

        self.client = SAPNIStreamSocket(sock, base_cls=SomeClass)
        packet = self.client.sr(Raw(self.test_string))
        self.client.close()

        self.assertIn(SAPNI, packet)
        self.assertIn(SomeClass, packet)
        self.assertEqual(packet[SAPNI].length, len(self.test_string))
        self.assertEqual(packet[SomeClass].text, self.test_string)

        self.stop_server()

    def test_sapnistreamsocket_base_cls_dispatcher(self):
        """Test SAPNIStreamSocket dispatching the base class dynamically based
        on the raw payload (e.g. NWRFC vs classic SAPRFC magic bytes)"""
        self.start_server(self.test_address, self.test_port, SAPNITestHandler)

        class ClassA(Packet):
            fields_desc = [StrField("text", None)]

        class ClassB(Packet):
            fields_desc = [StrField("text", None)]

        def dispatcher(packet, payload):
            if payload.startswith(b"AAAA"):
                return ClassA
            return ClassB

        sock = socket.socket()
        sock.connect((self.test_address, self.test_port))

        self.client = SAPNIStreamSocket(sock, base_cls=dispatcher)
        packet = self.client.sr(Raw(b"AAAA" + self.test_string))
        self.client.close()

        self.assertIn(SAPNI, packet)
        self.assertIn(ClassA, packet)
        self.assertNotIn(ClassB, packet)
        self.assertEqual(packet[ClassA].text, b"AAAA" + self.test_string)

        self.stop_server()

        self.start_server(self.test_address, self.test_port + 1, SAPNITestHandler)

        sock = socket.socket()
        sock.connect((self.test_address, self.test_port + 1))

        self.client = SAPNIStreamSocket(sock, base_cls=dispatcher)
        packet = self.client.sr(Raw(self.test_string))
        self.client.close()

        self.assertIn(SAPNI, packet)
        self.assertIn(ClassB, packet)
        self.assertNotIn(ClassA, packet)
        self.assertEqual(packet[ClassB].text, self.test_string)

        self.stop_server()

    def test_sapnistreamsocket_getnisocket(self):
        """Test SAPNIStreamSocket get nisocket class method"""
        self.start_server(self.test_address, self.test_port, SAPNITestHandler)

        self.client = SAPNIStreamSocket.get_nisocket(self.test_address,
                                                     self.test_port)

        packet = self.client.sr(Raw(self.test_string))
        packet.decode_payload_as(Raw)
        self.client.close()

        self.assertIn(SAPNI, packet)
        self.assertEqual(packet[SAPNI].length, len(self.test_string))
        self.assertEqual(packet.payload.load, self.test_string)

        self.stop_server()

    def test_sapnistreamsocket_without_keep_alive(self):
        """Test SAPNIStreamSocket without keep alive"""
        self.start_server(self.test_address, self.test_port, SAPNITestHandlerKeepAlive)

        sock = socket.socket()
        sock.connect((self.test_address, self.test_port))

        self.client = SAPNIStreamSocket(sock, keep_alive=False)
        packet = self.client.sr(Raw(self.test_string))
        packet.decode_payload_as(Raw)

        # We should receive our packet first
        self.assertIn(SAPNI, packet)
        self.assertEqual(packet[SAPNI].length, len(self.test_string))
        self.assertEqual(packet.payload.load, self.test_string)

        # Then we should get a we should receive a PING
        packet = self.client.recv()

        self.assertIn(SAPNI, packet)
        self.assertEqual(packet[SAPNI].length, len(SAPNI.SAPNI_PING))
        self.assertEqual(packet.payload.load, SAPNI.SAPNI_PING)

        self.client.close()
        self.stop_server()

    def test_sapnistreamsocket_with_keep_alive(self):
        """Test SAPNIStreamSocket with keep alive"""
        self.start_server(self.test_address, self.test_port, SAPNITestHandlerKeepAlive)

        sock = socket.socket()
        sock.connect((self.test_address, self.test_port))

        self.client = SAPNIStreamSocket(sock, keep_alive=True)
        self.client.send(Raw(self.test_string))

        packet = self.client.recv()
        packet.decode_payload_as(Raw)

        # We should receive our packet first
        self.assertIn(SAPNI, packet)
        self.assertEqual(packet[SAPNI].length, len(self.test_string))
        self.assertEqual(packet.payload.load, self.test_string)

        # Then we should get a connection reset if we try to receive from the server
        self.assertRaises(socket.error, self.client.recv)

        self.client.close()
        self.stop_server()

    def test_sapnistreamsocket_close(self):
        """Test SAPNIStreamSocket with a server that closes the connection"""
        self.start_server(self.test_address, self.test_port, SAPNITestHandlerClose)

        sock = socket.socket()
        sock.connect((self.test_address, self.test_port))

        self.client = SAPNIStreamSocket(sock, keep_alive=False)

        with self.assertRaises(socket.error):
            self.client.sr(Raw(self.test_string))

        self.stop_server()

    def test_sapnistreamsocket_partial_frame_eof(self):
        """Test that EOF after a partial frame fails instead of looping"""
        self.start_server(self.test_address, self.test_port,
                          SAPNITestHandlerPartialFrame)
        sock = socket.socket()
        sock.connect((self.test_address, self.test_port))
        self.client = SAPNIStreamSocket(sock, keep_alive=False, timeout=1)

        with self.assertRaises(socket.error):
            self.client.recv()

        self.client.close()
        self.stop_server()

    def test_sapnistreamsocket_partial_header_eof(self):
        """Test deterministic failure when the peer truncates the NI header"""
        self.start_server(self.test_address, self.test_port,
                          SAPNITestHandlerPartialHeader)
        sock = socket.socket()
        sock.connect((self.test_address, self.test_port))
        self.client = SAPNIStreamSocket(sock, keep_alive=False, timeout=1)

        with self.assertRaises(socket.error):
            self.client.recv()

        self.client.close()
        self.stop_server()

    def test_sapnistreamsocket_frame_length_bound(self):
        """Test rejection of a peer-declared frame beyond the configured bound"""
        self.start_server(self.test_address, self.test_port,
                          SAPNITestHandlerOversizedFrame)
        sock = socket.socket()
        sock.connect((self.test_address, self.test_port))
        self.client = SAPNIStreamSocket(sock, keep_alive=False,
                                        max_frame_length=1024)

        with self.assertRaises(SAPNIFrameLengthError):
            self.client.recv()

        self.client.close()
        self.stop_server()

    def test_sapnistreamsocket_timeout(self):
        """Test applying a read/write timeout to an existing socket"""
        left, right = socket.socketpair()
        try:
            self.client = SAPNIStreamSocket(left, timeout=0.25)
            self.assertEqual(self.client.ins.gettimeout(), 0.25)
            self.client.close()
        finally:
            right.close()

    def test_sapnistreamsocket_invalid_frame_length_bound(self):
        """Test rejecting negative NI frame bounds"""
        left, right = socket.socketpair()
        try:
            with self.assertRaises(ValueError):
                SAPNIStreamSocket(left, max_frame_length=-1)
        finally:
            left.close()
            right.close()

    def test_sapnistreamsocket_connection_timeout(self):
        """Test passing a distinct timeout to connection establishment"""
        left, right = socket.socketpair()
        try:
            with mock.patch("pysap.SAPNI.socket.create_connection",
                            return_value=left) as create_connection:
                self.client = SAPNIStreamSocket.get_nisocket(
                    "example.invalid", 3299, connect_timeout=1.5,
                    timeout=0.25)
            create_connection.assert_called_once_with(
                ("example.invalid", 3299), 1.5)
            self.assertEqual(self.client.ins.gettimeout(), 0.25)
            self.client.close()
        finally:
            right.close()


class SAPNIServerTestHandler(SAPNIServerHandler):
    """Basic SAP NI echo server implemented using SAPNIServer"""

    def handle_data(self):
        self.request.send(self.packet)


@pytest.mark.integration
class PySAPNIServerTest(PySAPBaseServerTest):

    test_port = 8011
    test_address = "127.0.0.1"
    test_string = b"TEST" * 10
    handler_cls = SAPNIServerTestHandler

    def test_sapniserver(self):
        """Test SAPNIServer"""
        self.start_server(self.test_address, self.test_port, self.handler_cls, SAPNIServerThreaded)

        sock = socket.socket()
        sock.connect((self.test_address, self.test_port))
        sock.sendall(pack("!I", len(self.test_string)) + self.test_string)

        response = sock.recv(4)
        self.assertEqual(len(response), 4)
        ni_length, = unpack("!I", response)
        self.assertEqual(ni_length, len(self.test_string) + 4)

        response = sock.recv(ni_length)
        self.assertEqual(unpack("!I", response[:4]), (len(self.test_string), ))
        self.assertEqual(response[4:], self.test_string)

        sock.close()
        self.stop_server()


@pytest.mark.integration
class PySAPNIProxyTest(PySAPBaseServerTest):

    test_proxyport = 8012
    test_serverport = 8013
    test_address = "127.0.0.1"
    test_string = b"TEST" * 10
    proxyhandler_cls = SAPNIProxyHandler
    serverhandler_cls = SAPNIServerTestHandler

    def start_sapniproxy(self, handler_cls):
        self.proxy = SAPNIProxy(self.test_address, self.test_proxyport,
                                self.test_address, self.test_serverport,
                                handler=handler_cls)
        self.proxy_thread = Thread(target=self.handle_sapniproxy)
        self.proxy_thread.daemon = True
        self.proxy_thread.start()

    def handle_sapniproxy(self):
        self.proxy.handle_connection()

    def stop_sapniproxy(self):
        self.proxy.stop()

    def test_sapniproxy(self):
        self.start_server(self.test_address, self.test_serverport,
                          self.serverhandler_cls, SAPNIServerThreaded)
        self.start_sapniproxy(self.proxyhandler_cls)

        sock = socket.socket()
        sock.connect((self.test_address, self.test_proxyport))
        sock.sendall(pack("!I", len(self.test_string)) + self.test_string)

        response = sock.recv(4)
        self.assertEqual(len(response), 4)
        ni_length, = unpack("!I", response)
        self.assertEqual(ni_length, len(self.test_string) + 4)

        response = sock.recv(ni_length)
        self.assertEqual(unpack("!I", response[:4]), (len(self.test_string), ))
        self.assertEqual(response[4:], self.test_string)

        sock.close()
        self.stop_sapniproxy()
        self.stop_server()

    def test_sapniproxy_process(self):
        self.start_server(self.test_address, self.test_serverport,
                          self.serverhandler_cls, SAPNIServerThreaded)

        class SAPNIProxyHandlerTest(SAPNIProxyHandler):

            def process_client(self, packet):
                return packet / Raw("Client")

            def process_server(self, packet):
                return packet / Raw("Server")

        self.start_sapniproxy(SAPNIProxyHandlerTest)

        sock = socket.socket()
        sock.connect((self.test_address, self.test_proxyport))
        sock.sendall(pack("!I", len(self.test_string)) + self.test_string)

        expected_reponse = self.test_string + b"Client" + b"Server"

        response = sock.recv(4)
        self.assertEqual(len(response), 4)
        ni_length, = unpack("!I", response)
        self.assertEqual(ni_length, len(expected_reponse) + 4)

        response = sock.recv(ni_length)
        self.assertEqual(unpack("!I", response[:4]), (len(self.test_string) + 6, ))
        self.assertEqual(response[4:], expected_reponse)

        sock.close()
        self.stop_sapniproxy()
        self.stop_server()


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(PySAPNITest))
    suite.addTest(loader.loadTestsFromTestCase(PySAPNIServerHandlerUnitTest))
    suite.addTest(loader.loadTestsFromTestCase(PySAPNIStreamSocketTest))
    suite.addTest(loader.loadTestsFromTestCase(PySAPNIServerTest))
    suite.addTest(loader.loadTestsFromTestCase(PySAPNIProxyTest))
    return suite


if __name__ == "__main__":
    test_runner = unittest.TextTestRunner(verbosity=2, resultclass=unittest.TextTestResult)
    result = test_runner.run(suite())
    sys.exit(not result.wasSuccessful())
