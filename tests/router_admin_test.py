# encoding: utf-8
# pysap - Python library for crafting SAP's network protocols packets
# SPDX-License-Identifier: GPL-2.0-or-later

import unittest
from types import SimpleNamespace
from unittest import mock

from examples import router_admin
from pysap.SAPNI import SAPNI
from pysap.SAPRouter import SAPRouter, SAPRouterError


class RouterAdminTest(unittest.TestCase):

    def options(self, **updates):
        values = dict(remote_host="127.0.0.1", remote_port=3299,
                      router_version=40, timeout=0.5, verbose=False,
                      stop=False, soft=False, info=False, info_password=None,
                      new_route=False, trace=False, cancel=None, dump=False,
                      flush=False, hide=False, set_peer=None, clear_peer=None,
                      trace_conn=None)
        values.update(updates)
        return SimpleNamespace(**values)

    def denial(self):
        return SAPNI() / SAPRouter(
            type=SAPRouter.SAPROUTER_ERROR, version=40, return_code=-94,
            err_text_value=SAPRouterError(error="Admin from remote denied"))

    def test_refresh_reads_denial_with_bounded_stream_and_closes(self):
        connection = mock.Mock()
        connection.recv.return_value = self.denial()
        with mock.patch.object(router_admin, "parse_options",
                               return_value=self.options(new_route=True)), \
                mock.patch.object(router_admin.SAPNIStreamSocket,
                                  "get_nisocket", return_value=connection) as factory, \
                mock.patch.object(router_admin.logging, "error") as log_error:
            router_admin.main()

        self.assertEqual(connection.send.call_args.args[0].adm_command, 3)
        self.assertEqual(factory.call_args.kwargs,
                         {"connect_timeout": 0.5, "timeout": 0.5})
        connection.recv.assert_called_once_with()
        connection.close.assert_called_once_with()
        self.assertIn("Admin from remote denied",
                      str(log_error.call_args.args[0]))

    def test_password_only_info_request_does_not_log_password(self):
        connection = mock.Mock()
        connection.recv.return_value = self.denial()
        with mock.patch.object(router_admin, "parse_options",
                               return_value=self.options(
                                   info_password="synthetic-secret")), \
                mock.patch.object(router_admin.SAPNIStreamSocket,
                                  "get_nisocket", return_value=connection), \
                mock.patch.object(router_admin.logging, "info") as log_info:
            router_admin.main()

        request = connection.send.call_args.args[0]
        self.assertEqual(request.adm_command, 2)
        self.assertEqual(request.adm_password, b"synthetic-secret")
        connection.close.assert_called_once_with()
        self.assertNotIn("synthetic-secret",
                         " ".join(str(call) for call in log_info.call_args_list))


if __name__ == "__main__":
    unittest.main()
