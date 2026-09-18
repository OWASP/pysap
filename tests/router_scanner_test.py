# encoding: utf-8
# pysap - Python library for crafting SAP's network protocols packets
# SPDX-License-Identifier: GPL-2.0-or-later

import socket
import unittest
from unittest import mock

from pysap.SAPRouter import (SAPRouteException, SAPRouterResponseError,
                             ROUTER_TALK_MODE_NI_MSG_IO,
                             ROUTER_TALK_MODE_NI_RAW_IO)
from examples import router_scanner


class RouterScannerTest(unittest.TestCase):

    def test_network_targets_are_normalized_to_strings(self):
        if router_scanner.netaddr is None:
            self.skipTest("netaddr not installed")
        targets = list(router_scanner.parse_target_hosts("127.0.0.1/30", "3600"))
        self.assertEqual([host for host, _ in targets],
                         ["127.0.0.0", "127.0.0.1", "127.0.0.2", "127.0.0.3"])
        self.assertTrue(all(isinstance(host, str) for host, _ in targets))

    def test_ni_route_statuses_keep_denial_distinct_from_unreachable(self):
        with mock.patch.object(router_scanner.SAPRoutedStreamSocket,
                               "get_nisocket", side_effect=SAPRouteException("denied")):
            self.assertEqual(router_scanner.route_test("127.0.0.1", 3299,
                             "127.0.0.2", 3600, ROUTER_TALK_MODE_NI_MSG_IO, 40),
                             "denied")
        with mock.patch.object(router_scanner.SAPRoutedStreamSocket,
                               "get_nisocket", side_effect=SAPRouterResponseError(-92)):
            self.assertEqual(router_scanner.route_test("127.0.0.1", 3299,
                             "127.0.0.2", 3600, ROUTER_TALK_MODE_NI_MSG_IO, 40),
                             "unreachable")

    def test_raw_route_checks_quick_close_and_silent_backend(self):
        connection = mock.Mock()
        connection.ins.recv.return_value = b""
        with mock.patch.object(router_scanner.SAPRoutedStreamSocket,
                               "get_nisocket", return_value=connection) as factory:
            status = router_scanner.route_test("127.0.0.1", 3299,
                         "127.0.0.2", 3700, ROUTER_TALK_MODE_NI_RAW_IO, 40,
                         timeout=0.5)
        self.assertEqual(status, "closed")
        connection.ins.recv.assert_called_once_with(1, socket.MSG_PEEK)
        self.assertEqual(factory.call_args.kwargs["timeout"], 0.5)
        connection.close.assert_called_once()

        connection = mock.Mock()
        connection.ins.recv.side_effect = socket.timeout()
        with mock.patch.object(router_scanner.SAPRoutedStreamSocket,
                               "get_nisocket", return_value=connection):
            status = router_scanner.route_test("127.0.0.1", 3299,
                         "127.0.0.2", 3700, ROUTER_TALK_MODE_NI_RAW_IO, 40,
                         timeout=0.5)
        self.assertEqual(status, "open")
        connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
