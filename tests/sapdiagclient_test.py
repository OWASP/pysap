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

from pysap.SAPDiag import SAPDiag, SAPDiagDP, SAPDiagItem
from pysap.SAPDiagClient import SAPDiagConnection
from pysap.SAPDiagItems import SAPDiagStep, SAPDiagSupportBits
from tests.utils import DummyConnection


class PySAPDiagClientTest(unittest.TestCase):

    def test_get_terminal_name(self):
        with mock.patch("pysap.SAPDiagClient.randint", side_effect=[10, 20, 30, 40]):
            self.assertEqual(SAPDiagConnection.get_terminal_name(), "10.20.30.40")

    def test_get_support_data_item(self):
        conn = SAPDiagConnection("host", 3200, init=False)

        item = conn.get_support_data_item("00" * 32)

        self.assertIsInstance(item, SAPDiagItem)
        self.assertIsInstance(item.item_value, SAPDiagSupportBits)
        self.assertEqual(item.item_value.SAPGUI_COMPR_ENHANCED, 0)

    def test_connect_uses_router_socket(self):
        conn = SAPDiagConnection("host", 3200, route="route", init=False)
        sentinel = object()

        with mock.patch("pysap.SAPDiagClient.SAPRoutedStreamSocket.get_nisocket", return_value=sentinel) as patched:
            conn.connect()

        self.assertIs(conn._connection, sentinel)
        patched.assert_called_once_with("host", 3200, "route", base_cls=SAPDiag)

    def test_init_send_receive_and_interact(self):
        conn = SAPDiagConnection("host", 3200, terminal="TERM", compress=True, init=False)
        response = object()
        conn._connection = DummyConnection([response, response])

        init_response = conn.init()

        self.assertIs(init_response, response)
        self.assertTrue(conn.initialized)
        self.assertEqual(len(conn._connection.sent), 1)
        init_packet = conn._connection.sent[0]
        self.assertIn(SAPDiagDP, init_packet)
        self.assertTrue(init_packet[SAPDiagDP].terminal.startswith(b"TERM"))
        self.assertEqual(init_packet[SAPDiag].com_flag_TERM_INI, 1)

        message = [SAPDiagItem(item_type="SES")]
        interact_response = conn.interact(message)

        self.assertIs(interact_response, response)
        self.assertEqual(conn.step, 1)
        self.assertEqual(message[0].item_value.step, 1)
        self.assertEqual(message[-1].item_type, 0x0c)

    def test_receive_send_and_close(self):
        class ClosingConnection(DummyConnection):
            def close(self):
                super(ClosingConnection, self).close()
                raise OSError()

        conn = SAPDiagConnection("host", 3200, init=False)
        response = object()
        conn._connection = DummyConnection([response])

        self.assertIs(conn.receive(), response)
        self.assertIs(conn.last_response, response)

        conn.send(SAPDiag(compress=0))
        self.assertEqual(len(conn._connection.sent), 1)

        conn._connection = ClosingConnection()
        conn.close()
        self.assertTrue(conn._connection.closed)
        self.assertEqual(conn._connection.sent[-1][SAPDiag].com_flag_TERM_EOC, 1)


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(PySAPDiagClientTest))
    return suite


if __name__ == "__main__":
    test_runner = unittest.TextTestRunner(verbosity=2, resultclass=unittest.TextTestResult)
    result = test_runner.run(suite())
    sys.exit(not result.wasSuccessful())
