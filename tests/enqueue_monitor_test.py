# encoding: utf-8
# pysap - Python library for crafting SAP's network protocols packets

import unittest
from types import SimpleNamespace
from unittest import mock

from examples import enqueue_monitor
from pysap.SAPEnqueue import SAPEnqueue


class EnqueueMonitorTest(unittest.TestCase):

    def test_connect_uses_bounded_routed_stream(self):
        options = SimpleNamespace(
            client="test", consolelog=None, verbose=False,
            remote_host="127.0.0.1", remote_port=3200,
            route_string=None, timeout=2.5)
        connection = mock.Mock()
        connection.sr.return_value = SAPEnqueue(
            dest=6, opcode=2, params=[])
        console = enqueue_monitor.SAPEnqueueAdminConsole(options)

        with mock.patch.object(enqueue_monitor.SAPEnqueueStreamSocket,
                               "get_nisocket",
                               return_value=connection) as get_nisocket:
            console.do_connect(None)

        get_nisocket.assert_called_once_with(
            "127.0.0.1", 3200, None,
            connect_timeout=2.5, timeout=2.5,
            max_frame_length=16 << 20)
        self.assertTrue(console.connected)


if __name__ == "__main__":
    unittest.main()
