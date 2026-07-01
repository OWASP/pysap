# encoding: utf-8
# pysap - Python library for crafting SAP's network protocols packets
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#

import io
import socket
import unittest
from types import SimpleNamespace
from unittest import mock

from pysap.SAPMS import SAPMS
from pysap.SAPNI import SAPNI

from examples import ms_impersonator, router_password_check


class FakeTimingSocket(object):
    def __init__(self):
        self.sent = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.closed = True

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, size):
        return b"response"


class PySAPExamplesRegressionTest(unittest.TestCase):

    def test_ms_impersonator_requires_sapms_layer(self):
        response = SAPMS()

        self.assertIs(ms_impersonator.require_sapms_response(response, "testing"), response)

        with self.assertRaises(ValueError):
            ms_impersonator.require_sapms_response(SAPNI() / b"not-ms", "testing")

    def test_router_password_check_uses_timeout_and_closes_socket(self):
        options = SimpleNamespace(remote_host="router", remote_port=3299,
                                  router_version=40, timeout=2.5)
        conn = FakeTimingSocket()
        output = io.StringIO()

        with mock.patch.object(router_password_check.socket, "create_connection",
                               return_value=conn) as create_connection:
            elapsed = router_password_check.try_password(options, "secret", output, 3)

        create_connection.assert_called_once_with(("router", 3299), timeout=2.5)
        self.assertIsInstance(elapsed, int)
        self.assertTrue(conn.closed)
        self.assertEqual(output.getvalue().split(",")[:2], ["3", "secret"])

    def test_router_password_check_records_socket_errors(self):
        options = SimpleNamespace(remote_host="router", remote_port=3299,
                                  router_version=40, timeout=2.5)
        output = io.StringIO()

        with mock.patch.object(router_password_check.socket, "create_connection",
                               side_effect=socket.timeout("timed out")):
            elapsed = router_password_check.try_password(options, "secret", output, 4)

        self.assertEqual(elapsed, "ERROR:TimeoutError")
        self.assertEqual(output.getvalue(), "4,secret,ERROR:TimeoutError\n")


if __name__ == "__main__":
    unittest.main()
