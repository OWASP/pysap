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
#

import unittest
from types import SimpleNamespace
from unittest import mock

from pysap.SAPMS import (SAPMS, SAPMSAdmRecord, SAPMSClient3,
                         SAPMSLogonResponse, SAPMSProperty,
                         ms_logon_type_values, ms_property_id_values)
from examples import ms_monitor


class MSMonitorTest(unittest.TestCase):

    def test_ms_monitor_dump_all_uses_parsed_commands_and_dump_response(self):
        options = SimpleNamespace(client="test", domain="ABAP",
                                  consolelog=None, verbose=False)
        console = ms_monitor.SAPMSMonitorConsole(options)
        console._send_simple = mock.Mock(
            return_value=SimpleNamespace(dump_response=b"dump output\x00"))
        console._print = mock.Mock()

        console.do_dump("all")

        commands = [call.kwargs["dump_command"]
                    for call in console._send_simple.call_args_list]
        self.assertEqual(commands, [command for command in range(1, 33)
                                    if command not in (1, 12)])
        console._print.assert_any_call("Dump information:\ndump output")
        console._print.assert_any_call(
            "Skipping MS_DUMP_MSADM: requires an argument")
        console._print.assert_any_call(
            "Skipping MS_DUMP_COUNTER: requires an argument")

    def test_ms_monitor_preserves_spaces_in_command_values(self):
        options = SimpleNamespace(client="test", domain="ABAP",
                                  consolelog=None, verbose=False)
        console = ms_monitor.SAPMSMonitorConsole(options)
        console.connected = True
        console.clients = [SAPMSClient3(client="SERVER")]
        console.runtimeoptions.update(server_string=b"MSG_SERVER",
                                      client_string=b"test")
        console._send_simple = mock.Mock(return_value=None)
        response = SAPMS(flag=0x04, iflag=0x05, adm_records=[
            SAPMSAdmRecord(opcode=0x2e, errorno=0)])
        console.connection = SimpleNamespace(sr=mock.Mock(return_value=response))

        console.do_server_disconnect("0 planned maintenance window")
        console.do_parameter_set("ms/example value with spaces")

        self.assertEqual(
            console._send_simple.call_args.kwargs["shutdown_reason"],
            "planned maintenance window")
        request = console.connection.sr.call_args.args[0]
        self.assertEqual(request.adm_records[0].parameter.rstrip(b"\x00"),
                         b"ms/example=value with spaces")

    def test_ms_monitor_expanded_opcode_commands(self):
        options = SimpleNamespace(client="test", domain="ABAP",
                                  consolelog=None, verbose=False)
        console = ms_monitor.SAPMSMonitorConsole(options)
        console.connected = True
        console.clients = [SAPMSClient3(client="SERVER")]
        console.runtimeoptions.update(server_string=b"MSG_SERVER",
                                      client_string=b"test")
        response = SimpleNamespace(
            ip_to_name=b"SERVER\x00", text_value=b"description\x00",
            property=SAPMSProperty(client="SERVER", id=1),
            logon=SAPMSLogonResponse())
        console._send_simple = mock.Mock(return_value=response)
        console._print = mock.Mock()

        console.do_set_security_key("SERVER secret")
        console.do_ip_port_to_name("2001:db8::1 3200")
        console.do_change_ip("127.0.0.2")
        console.do_noop("")
        console.do_file_reload("4")
        console.do_set_logon("6 PUBLIC 127.0.0.1 50000 HTTP host misc")
        console.do_del_logon("6 PUBLIC")
        console.do_text_set("SERVER description")
        console.do_text_get("SERVER")
        console.do_property_set("0 1 description")
        console.do_property_delete("0 1")
        console.do_subsystem_list("")
        console.do_soft_shutdown("")

        opcodes = [call.kwargs["opcode"]
                   for call in console._send_simple.call_args_list]
        self.assertEqual(opcodes, [0x07, 0x46, 0x06, 0x21, 0x1f, 0x2b,
                                   0x2d, 0x22, 0x23, 0x43, 0x45, 0x4d,
                                   0x1d])
        self.assertEqual(console._send_simple.call_args_list[1].kwargs,
                         {"opcode": 0x46, "opcode_version": 2,
                          "ip_to_name_port": 3200,
                          "ip_to_name_address6": "2001:db8::1"})
        self.assertEqual(
            console._send_simple.call_args_list[5].kwargs["logon"].misc,
            b"misc")

    def test_ms_monitor_logon_group_command_is_not_client_list_alias(self):
        options = SimpleNamespace(client="test", domain="ABAP",
                                  consolelog=None, verbose=False)
        console = ms_monitor.SAPMSMonitorConsole(options)
        console.do_dump = mock.Mock()
        console.do_client_list = mock.Mock()

        console.do_logon_group_list("")

        self.assertEqual(console.do_dump.call_args_list,
                         [mock.call("31"), mock.call("32")])
        console.do_client_list.assert_not_called()

    def test_ms_monitor_argument_completion(self):
        options = SimpleNamespace(client="test", domain="ABAP",
                                  consolelog=None, verbose=False)
        console = ms_monitor.SAPMSMonitorConsole(options)
        console.clients = [SAPMSClient3(client="SERVER"),
                           SAPMSClient3(client="SENDER")]

        self.assertEqual(console.complete_dump("3", "dump 3", 5, 6),
                         ["3", "30", "31", "32"])
        self.assertEqual(console.complete_dump("", "dump 1 ", 7, 7),
                         ["0", "1"])
        self.assertEqual(console.complete_file_reload(
            "1", "file_reload 1", 12, 13),
            ["1", "10", "11", "12", "13", "14", "15"])
        self.assertEqual(console.complete_get_logon(
            "1", "get_logon PUBLIC 1", 17, 18),
            sorted(str(value) for value in ms_logon_type_values
                   if str(value).startswith("1")))
        self.assertEqual(console.complete_property_get(
            "", "property_get 0 ", 15, 15),
            sorted(str(value) for value in ms_property_id_values))
        self.assertEqual(console.complete_text_get(
            "SE", "text_get SE", 9, 11), ["SENDER", "SERVER"])

if __name__ == "__main__":
    unittest.main()
