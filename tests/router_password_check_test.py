# encoding: utf-8
# pysap - Python library for crafting SAP's network protocols packets
# SPDX-License-Identifier: GPL-2.0-or-later

import io
import unittest
from types import SimpleNamespace
from unittest import mock

from examples import router_password_check
from pysap.SAPRouter import SAPRouter


class RouterPasswordCheckTest(unittest.TestCase):

    def setUp(self):
        self.options = SimpleNamespace(remote_host="127.0.0.1",
                                       remote_port=3299, timeout=0.5,
                                       router_version=40)

    def test_attempt_uses_bounded_ni_stream_and_closes_it(self):
        connection = mock.Mock()
        output = io.StringIO()
        with mock.patch.object(router_password_check.SAPNIStreamSocket,
                               "get_nisocket", return_value=connection) as factory, \
                mock.patch.object(router_password_check.time, "perf_counter_ns",
                                  side_effect=[100, 250]):
            elapsed = router_password_check.try_password(
                self.options, "guess", output, 3)

        self.assertEqual(elapsed, 150)
        self.assertEqual(output.getvalue(), "3,guess,150\n")
        self.assertEqual(factory.call_args.kwargs,
                         {"connect_timeout": 0.5, "timeout": 0.5})
        request = connection.send.call_args.args[0]
        self.assertIsInstance(request, SAPRouter)
        self.assertEqual(request.adm_password, b"guess")
        connection.recv.assert_called_once_with()
        connection.close.assert_called_once_with()

    def test_failed_response_is_recorded_and_stream_is_closed(self):
        connection = mock.Mock()
        connection.recv.side_effect = OSError("closed")
        output = io.StringIO()
        with mock.patch.object(router_password_check.SAPNIStreamSocket,
                               "get_nisocket", return_value=connection), \
                mock.patch.object(router_password_check.time, "perf_counter_ns",
                                  return_value=100):
            result = router_password_check.try_password(
                self.options, "wrong", output)

        self.assertEqual(result, "ERROR:OSError")
        self.assertEqual(output.getvalue(), "0,wrong,ERROR:OSError\n")
        connection.close.assert_called_once_with()

    def test_version_probe_is_bounded_and_closed(self):
        options = SimpleNamespace(remote_host="127.0.0.1", remote_port=3299,
                                  timeout=0.5, router_version=None,
                                  password="x", tries=0, output="ignored.csv",
                                  verbose=False)
        connection = mock.Mock()
        with mock.patch.object(router_password_check, "parse_options",
                               return_value=options), \
                mock.patch.object(router_password_check.SAPNIStreamSocket,
                                  "get_nisocket", return_value=connection) as factory, \
                mock.patch.object(router_password_check, "get_router_version",
                                  return_value=40), \
                mock.patch("builtins.open", mock.mock_open()):
            router_password_check.main()

        self.assertEqual(options.router_version, 40)
        self.assertEqual(factory.call_args.kwargs,
                         {"connect_timeout": 0.5, "timeout": 0.5})
        connection.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
