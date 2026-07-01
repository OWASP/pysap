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

import unittest
from struct import pack
from types import SimpleNamespace

from scapy.packet import Packet, raw

from pysap.SAPNI import SAPNI, SAPNIStreamSocket
from pysap.SAPRouter import (ROUTER_TALK_MODE_NI_MSG_IO, ROUTER_TALK_MODE_NI_RAW_IO,
                             SAPRouterNativeRouterHandler, SAPRouterRouteHop,
                             normalize_route_hops)


class FailingPacket(Packet):
    name = "Failing test packet"
    fields_desc = []

    def do_dissect(self, s):
        raise ValueError("forced dissector failure")


class FakeSocket(object):
    def __init__(self, data=b""):
        self.data = data
        self.sent = []
        self.closed = False

    def recv(self, size, flags=0):
        if flags:
            return self.data[:size]
        chunk = self.data[:size]
        self.data = self.data[size:]
        return chunk

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True

    def fileno(self):
        return -1


class SocketWrapper(object):
    def __init__(self, ins):
        self.ins = ins
        self.closed = False

    def close(self):
        self.closed = True
        self.ins.close()


class PySAPNIStreamSocketUnitTest(unittest.TestCase):

    def test_recv_raises_decode_errors_for_base_class(self):
        stream = SAPNIStreamSocket.__new__(SAPNIStreamSocket)
        stream.ins = FakeSocket(raw(SAPNI() / b"bad"))
        stream.keep_alive = False
        stream.basecls = FailingPacket

        with self.assertRaises(ValueError):
            stream.recv()

    def test_recv_keeps_ping_payload_raw_when_saprouter_is_bound(self):
        stream = SAPNIStreamSocket.__new__(SAPNIStreamSocket)
        stream.ins = FakeSocket(raw(SAPNI() / SAPNI.SAPNI_PING))
        stream.keep_alive = False
        stream.basecls = None

        packet = stream.recv()

        self.assertIn(SAPNI, packet)
        self.assertEqual(packet[SAPNI].length, len(SAPNI.SAPNI_PING))
        self.assertEqual(packet.payload.load, SAPNI.SAPNI_PING)


class PySAPRouterRouteUnitTest(unittest.TestCase):

    def test_normalize_route_hops_converts_integer_ports(self):
        route = [SAPRouterRouteHop(hostname="router", port=3299),
                 SAPRouterRouteHop(hostname="target", port=3200)]

        normalize_route_hops(route)

        self.assertEqual(route[0].port, b"3299")
        self.assertEqual(route[1].port, b"3200")
        self.assertEqual(raw(route[1]), b"target\x003200\x00\x00")


class PySAPRouterNativeRouterHandlerUnitTest(unittest.TestCase):

    def _handler(self, talk_mode):
        handler = SAPRouterNativeRouterHandler.__new__(SAPRouterNativeRouterHandler)
        handler.options = SimpleNamespace(talk_mode=talk_mode)
        handler.mtu = 2048
        return handler

    def test_raw_mode_forwards_bytes_unchanged(self):
        handler = self._handler(ROUTER_TALK_MODE_NI_RAW_IO)
        local = SocketWrapper(FakeSocket(b"native"))
        remote = SocketWrapper(FakeSocket())

        handler.recv_send(local, remote, handler.process_client)

        self.assertEqual(remote.ins.sent, [b"native"])

    def test_ni_message_mode_wraps_client_payload_once(self):
        handler = self._handler(ROUTER_TALK_MODE_NI_MSG_IO)
        local = SocketWrapper(FakeSocket(b"payload"))
        remote = SocketWrapper(FakeSocket())

        handler.recv_send(local, remote, handler.process_client)

        self.assertEqual(remote.ins.sent, [pack("!I", 7) + b"payload"])

    def test_ni_message_mode_forwards_router_frame_once(self):
        handler = self._handler(ROUTER_TALK_MODE_NI_MSG_IO)
        frame = pack("!I", 7) + b"payload"
        local = SocketWrapper(FakeSocket(frame))
        remote = SocketWrapper(FakeSocket())

        handler.recv_send(local, remote, handler.process_server)

        self.assertEqual(remote.ins.sent, [frame])

    def test_ni_message_mode_skips_keepalive_frame(self):
        handler = self._handler(ROUTER_TALK_MODE_NI_MSG_IO)
        local = SocketWrapper(FakeSocket(b"\xff\xff\xff\xff"))
        remote = SocketWrapper(FakeSocket())

        handler.recv_send(local, remote, handler.process_server)

        self.assertEqual(remote.ins.sent, [])


if __name__ == "__main__":
    unittest.main()
