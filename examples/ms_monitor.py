#!/usr/bin/env python3
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
import ipaddress
import logging
from argparse import ArgumentParser
from socket import error as SocketError
# External imports
from scapy.config import conf
# Custom imports
import pysap
from pysap.utils.console import BaseConsole
from pysap.SAPMS import (SAPMS, ms_client_status_values, ms_opcode_error_values,
                         ms_dump_command_values, SAPMSCounter, ms_opcode_values,
                         ms_errorno_values, SAPMSProperty, ms_property_id_values,
                         SAPMSAdmRecord, ms_domain_values_inv,
                         ms_file_reload_values, ms_logon_type_values,
                         SAPMSLogon)
from pysap.SAPRouter import SAPRoutedStreamSocket


# Set the verbosity to 0
conf.verb = 0


class SAPMSMonitorConsole(BaseConsole):

    intro = "SAP MS Monitor Console"
    connection = None
    connected = False
    clients = []

    def __init__(self, options):
        super(SAPMSMonitorConsole, self).__init__(options)
        self.runtimeoptions["client_string"] = self.options.client
        self.runtimeoptions["domain"] = self.options.domain

    # Initialization
    def preloop(self):
        super(SAPMSMonitorConsole, self).preloop()
        self.do_connect(None)
        self.do_client_list(None)

    @staticmethod
    def _decode(value):
        """Decode a bytes field and strip null/space padding."""
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        return value.rstrip("\x00").strip()

    # Helper to extract the clients list from an MS_SERVER_LST response,
    # regardless of which opcode_version the server echoed back.
    def _get_clients(self, response):
        for field in ("clients_v4", "clients_v3", "clients_v2", "clients"):
            value = getattr(response, field, None)
            if value is not None:
                return value
        return []

    def _show_clients(self, response):
        """Display and retain a versioned Message Server client list."""
        clients = self._get_clients(response)
        table = [["#", "Client Name", "Host", "Service", "IPv4", "IPv6",
                  "ServNo", "State", "Services"]]
        instance = self.runtimeoptions["server_string"]
        for index, client in enumerate(clients):
            status = getattr(client, "status", None)
            if status == 1:
                instance = self._decode(client.client)
            table.append([str(index), self._decode(client.client),
                          self._decode(client.host),
                          self._decode(client.service), client.hostaddrv4,
                          client.hostaddrv6 if "hostaddrv6" in client.fields else None,
                          str(client.servno),
                          ms_client_status_values.get(status, str(status))
                          if status is not None else "",
                          str(client.msgtype).replace("+", " ")
                          if client.msgtype else "-"])
        self._tabulate(table)
        self.clients = clients
        self.runtimeoptions["instance"] = instance
        self._debug("Server instance: %s" % instance)

    @staticmethod
    def _complete_values(text, values):
        """Complete a token from a finite set of SAPMS values."""
        return sorted(value for value in (str(item) for item in values)
                      if value.startswith(text))

    @staticmethod
    def _completion_arg(line, begidx):
        """Return the zero-based argument currently being completed."""
        return max(0, len(line[:begidx].split()) - 1)

    def _complete_client_ids(self, text):
        return self._complete_values(text, range(len(self.clients)))

    def _complete_client_names(self, text):
        return self._complete_values(
            text, (self._decode(client.client) for client in self.clients))

    # Helper for crafting packets
    def _build(self, flag, iflag, **args):
        return SAPMS(flag=flag, iflag=iflag,
                     toname=self.runtimeoptions["server_string"],
                     fromname=self.runtimeoptions["client_string"],
                     domain=ms_domain_values_inv[self.runtimeoptions["domain"]],
                     **args)

    # Helper for sending simple commands and opcodes
    def _send_simple(self, flag, iflag, **args):
        if not self._require_connection():
            return

        if "opcode" in args:
            opcode_name = ms_opcode_values[args["opcode"]] + " "
        else:
            opcode_name = ""

        p = self._build(flag, iflag, **args)

        self._debug("Sending %spacket" % opcode_name)
        response = self.connection.sr(p)[SAPMS]

        if response.opcode_error != 0:
            self._print("Error: %s" % ms_opcode_error_values[response.opcode_error])
            return None
        else:
            return response

    # SAP MS Monitor commands

    def do_connect(self, args):
        """ Initiate the connection to the Message Server service. The
        connection is registered using the client_string runtime option. """

        # Create the socket connection
        try:
            self.connection = SAPRoutedStreamSocket.get_nisocket(self.options.remote_host,
                                                                 self.options.remote_port,
                                                                 self.options.route_string,
                                                                 base_cls=SAPMS)
        except SocketError as e:
            self._error("Error connecting with the Message Server")
            self._error(str(e))
            return

        self._print("Attached to %s / %d" % (self.options.remote_host, self.options.remote_port))

        # Send MS_LOGIN_2 packet
        p = SAPMS(flag=0x02, iflag=0x08, domain=ms_domain_values_inv[self.runtimeoptions["domain"]],
                  toname=self.runtimeoptions["client_string"],
                  fromname=self.runtimeoptions["client_string"])

        self._debug("Sending login packet")
        response = self.connection.sr(p)[SAPMS]

        if response.errorno == 0:
            self.runtimeoptions["server_string"] = response.fromname.strip() + b"\x00"
            fromname = response.fromname
            self._debug("Login performed, server string: %s" % (fromname.decode("utf-8", errors="replace").strip() if isinstance(fromname, bytes) else fromname))
            self._print("pysap's Message Server monitor, connected to %s / %d" % (self.options.remote_host,
                                                                                  self.options.remote_port))
            self.connected = True
        else:
            if response.errorno in ms_errorno_values:
                self._error("Error performing login: %s" % ms_errorno_values[response.errorno])
            else:
                self._error("Unknown error performing login: %d" % response.errorno)

    def do_disconnect(self, args):
        """ Disconnects from the Message Server service. """

        if not self.connected:
            self._error("You need to connect to the server first !")
            return

        # Send MS_LOGOUT packet
        p = self._build(0x00, 0x04)
        p.toname = self.runtimeoptions["client_string"]
        self._debug("Sending logout packet")
        self.connection.send(p)

        self.connection.close()
        self._print("Dettached from %s / %d ..." % (self.options.remote_host, self.options.remote_port))

        self.connected = False

    def do_exit(self, args):
        if self.connected:
            self.do_disconnect(None)
        return super(SAPMSMonitorConsole, self).do_exit(args)

    def do_client_list(self, args):
        """ Retrieve the list of clients connected to the Message Server
        service. Use the client # value when required to provide a client
        IDs as parameter. """

        if not self.connected:
            self._error("You need to connect to the server first !")
            return

        # Send MS_SERVER_LONG_LIST packet
        p = self._build(0x01, 0x01, opcode=0x40, opcode_charset=0x00)
        self._debug("Sending server long list packet")
        self.connection.send(p)

        # Send MS_SERVER_LST packet
        response = self._send_simple(0x02, 0x01, opcode=0x05, opcode_version=0x68)

        if response is None:
            return

        self._show_clients(response)

    def do_hardware_id(self, args):
        """ Retrieve the installation's hardware ID. """
        response = self._send_simple(0x02, 0x01, opcode=0x0a)
        if response:
            self._print("Hardware ID: %s" % response.hwid)

    def do_get_security_by_name(self, args):
        """ Get Security Key by name. """
        response = self._send_simple(0x02, 0x01, opcode=0x08, security_name=args)
        if response:
            self._print("Security Key: %s" % response.security_key)

    def complete_get_security_by_name(self, text, line, begidx, endidx):
        return self._complete_client_names(text)

    def do_get_security_by_ip(self, args):
        """ Get Security Key by ip/port. Options <IPv4 address> <port> """

        try:
            ip, port = args.split()
            port = int(port)
        except ValueError:
            self._error("Wrong parameters !")
            return

        # Send MS_GET_SECURITY
        response = self._send_simple(0x02, 0x01, opcode=0x09, security2_addressv4=ip, security2_port=port)
        if response:
            self._print("Security Key: %s" % response.security2_key)

    def do_set_security_key(self, args):
        """Set a client security key. Options: <client name> <key>"""
        arguments = self._parse_args(args)
        if arguments is None:
            return
        if len(arguments) != 2 or len(arguments[1].encode("utf-8")) > 256:
            self._error("Wrong parameters ! Specify client name and a key up to 256 bytes")
            return
        if self._send_simple(0x02, 0x01, opcode=0x07,
                             security_name=arguments[0],
                             security_key=arguments[1]):
            self._print("Security key set")

    def complete_set_security_key(self, text, line, begidx, endidx):
        if self._completion_arg(line, begidx) == 0:
            return self._complete_client_names(text)
        return []

    def do_ip_port_to_name(self, args):
        """Resolve an IP address and port. Options: <IP address> <port>"""
        arguments = self._parse_args(args)
        if arguments is None:
            return
        try:
            address = ipaddress.ip_address(arguments[0])
            port = int(arguments[1])
            if len(arguments) != 2 or not 0 <= port <= 65535:
                raise ValueError
        except (IndexError, ValueError):
            self._error("Wrong parameters ! Specify an IP address and port")
            return

        request = {"opcode": 0x46,
                   "opcode_version": 1 if address.version == 4 else 2,
                   "ip_to_name_port": port}
        if address.version == 4:
            request["ip_to_name_address4"] = str(address)
        else:
            request["ip_to_name_address6"] = str(address)
        response = self._send_simple(0x02, 0x01, **request)
        if response:
            self._print("Client name: %s" % self._decode(response.ip_to_name))

    def do_change_ip(self, args):
        """Change this client's registered IP address. Options: <IP address>"""
        try:
            address = ipaddress.ip_address((args or "").strip())
        except ValueError:
            self._error("Invalid IP address")
            return
        request = {"opcode": 0x06,
                   "opcode_version": 1 if address.version == 4 else 2}
        if address.version == 4:
            request["change_ip_addressv4"] = str(address)
        else:
            request.update(change_ip_addressv4="0.0.0.0",
                           change_ip_addressv6=str(address))
        if self._send_simple(0x02, 0x01, **request):
            self._print("Registered IP address changed")

    def do_dump(self, args):
        """ Dump information. Options [<dump command> | all] """

        arguments = self._parse_args(args)
        if arguments is None:
            return

        if arguments == ["all"]:
            for key in ms_dump_command_values:
                if key in (1, 12):
                    self._print("Skipping %s: requires an argument" %
                                ms_dump_command_values[key])
                    continue
                self._do_dump(key, [])
            return

        try:
            command = int(arguments[0])
        except (IndexError, ValueError):
            self._error("Wrong dump command ! Valid values:")
            for key in ms_dump_command_values:
                self._error("%d: %s" % (key, ms_dump_command_values[key]))
            self._error("all: dumps all the available information")
            return

        self._do_dump(command, arguments[1:])

    def complete_dump(self, text, line, begidx, endidx):
        argument = self._completion_arg(line, begidx)
        if argument == 0:
            return self._complete_values(
                text, list(ms_dump_command_values) + ["all"])
        tokens = line[:begidx].split()
        if argument == 1 and len(tokens) > 1 and tokens[1] == "1":
            return self._complete_client_ids(text)
        return []

    def _do_dump(self, command, arguments):
        """Execute one parsed dump command."""
        if command == 1:  # MS_DUMP_MSADM
            try:
                client_id = int(arguments[0])
                client = self.clients[client_id]
            except (ValueError, IndexError):
                self._error("Wrong parameters ! Specify client ID")
                return
            response = self._send_simple(0x02, 0x01, opcode=0x1e,
                                         dump_dest=0x02, dump_command=command,
                                         dump_name=self._decode(client.client))
        elif command == 12:  # MS_DUMP_COUNTER
            try:
                counter = arguments[0]
            except IndexError:
                self._error("Wrong parameters ! Specify counter number")
                return
            response = self._send_simple(0x02, 0x01, opcode=0x1e,
                                         dump_dest=0x02, dump_command=command,
                                         dump_name=counter)
        else:
            # Send MS_DUMP_INFO
            response = self._send_simple(0x02, 0x01, opcode=0x1e, dump_dest=0x02, dump_command=command)

        if response:
            value = response.dump_response
            if isinstance(value, bytes):
                value = value.rstrip(b'\x00').decode('utf-8', errors='replace')
            self._print("Dump information:\n%s" % value)

    def do_open_requests(self, args):
        """List open Message Server requests."""
        response = self._send_simple(0x02, 0x01, opcode=0x14)
        if response and response.open_requests is not None:
            table = [["#", "Raw request record"]]
            table.extend([str(index), request.data.hex()]
                         for index, request in enumerate(
                             response.open_requests.requests))
            self._tabulate(table)

    def do_dump_url_map(self, args):
        """Dump the Message Server URL map."""
        self.do_dump("15")

    def do_dump_url_prefixes(self, args):
        """Dump Message Server URL prefixes."""
        self.do_dump("16")

    def do_dump_url_handler(self, args):
        """Dump Message Server URL handlers."""
        self.do_dump("17")

    def do_counter_dump(self, args):
        """Dump a counter. Options: <counter>"""
        arguments = self._parse_args(args)
        if arguments is None:
            return
        if len(arguments) != 1:
            self._error("Wrong parameters ! Specify counter number")
            return
        self.do_dump("12 %s" % arguments[0])

    def do_logon_types(self, args):
        """Display the supported Message Server logon types."""
        arguments = self._parse_args(args)
        if arguments is None:
            return
        if arguments:
            self._error("This command does not accept parameters.")
            return
        table = [["#", "Logon type"]]
        table.extend([str(key), value] for key, value in sorted(ms_logon_type_values.items()))
        self._tabulate(table)

    def _get_logon(self, args, fixed_type=None):
        arguments = self._parse_args(args)
        if arguments is None:
            return
        expected = [1] if fixed_type is not None else [1, 2]
        if len(arguments) not in expected:
            self._error("Wrong parameters ! Specify group name and optional logon type")
            return

        try:
            logon_type = fixed_type if fixed_type is not None else (int(arguments[1]) if len(arguments) == 2 else 0)
        except ValueError:
            self._error("Invalid logon type")
            return
        if logon_type not in ms_logon_type_values:
            self._error("Unknown logon type")
            return

        request = SAPMSLogon(type=logon_type, logonname=arguments[0],
                             address6_length=-1)
        response = self._send_simple(0x02, 0x01, opcode=0x2c, logon=request)
        if response is None or response.logon is None:
            return

        logon = response.logon
        table = [["Group", "Type", "Address", "Port", "Protocol", "Host", "Misc"]]
        table.append([self._decode(logon.logonname),
                      ms_logon_type_values.get(logon.type, str(logon.type)),
                      logon.address,
                      str(logon.port),
                      self._decode(logon.prot),
                      self._decode(logon.host),
                      self._decode(logon.misc)])
        self._tabulate(table)

    def do_get_logon(self, args):
        """Retrieve logon data. Options: <group name> [<logon type>]"""
        return self._get_logon(args)

    def complete_get_logon(self, text, line, begidx, endidx):
        if self._completion_arg(line, begidx) == 1:
            return self._complete_values(text, ms_logon_type_values)
        return []

    def do_logon_data(self, args):
        """Alias for :meth:`get_logon`."""
        return self.do_get_logon(args)

    def do_logon_data_snc(self, args):
        """Retrieve SNC logon data. Options: <group name>"""
        return self._get_logon(args, fixed_type=3)

    def do_logon_data_lb(self, args):
        """Retrieve load-balanced logon data. Options: <group name>"""
        return self._get_logon(args, fixed_type=0)

    def do_logon_data_lb_snc(self, args):
        """Retrieve SNC load-balanced logon data. Options: <group name>"""
        return self._get_logon(args, fixed_type=1)

    complete_logon_data = complete_get_logon

    def do_logon_group_list(self, args):
        """Dump GUI and RFC logon-group lists."""
        self.do_dump("31")
        self.do_dump("32")

    def do_set_logon(self, args):
        """Set logon data. Options: <type> <group> <address> <port> <protocol> <host> [misc]"""
        arguments = self._parse_args(args)
        if arguments is None:
            return
        if len(arguments) not in (6, 7):
            self._error("Wrong parameters ! Specify type, group, address, port, protocol, host and optional misc")
            return
        try:
            logon_type = int(arguments[0])
            address = ipaddress.ip_address(arguments[2])
            port = int(arguments[3])
            if logon_type not in ms_logon_type_values or not 0 <= port <= 65535:
                raise ValueError
        except ValueError:
            self._error("Invalid logon type, address or port")
            return
        values = {"type": logon_type, "logonname": arguments[1],
                  "port": port, "prot": arguments[4], "host": arguments[5],
                  "misc": arguments[6] if len(arguments) == 7 else ""}
        if address.version == 4:
            values.update(address=str(address), address6_length=-1)
        else:
            values.update(address="0.0.0.0", address6_length=16,
                          address6=str(address))
        if self._send_simple(0x02, 0x01, opcode=0x2b,
                             logon=SAPMSLogon(**values)):
            self._print("Logon data set")

    def complete_set_logon(self, text, line, begidx, endidx):
        if self._completion_arg(line, begidx) == 0:
            return self._complete_values(text, ms_logon_type_values)
        return []

    def do_del_logon(self, args):
        """Delete logon data. Options: <type> <group>"""
        arguments = self._parse_args(args)
        if arguments is None:
            return
        try:
            logon_type = int(arguments[0])
            if len(arguments) != 2 or logon_type not in ms_logon_type_values:
                raise ValueError
        except (IndexError, ValueError):
            self._error("Wrong parameters ! Specify logon type and group")
            return
        request = SAPMSLogon(type=logon_type, logonname=arguments[1],
                             address6_length=-1)
        if self._send_simple(0x02, 0x01, opcode=0x2d, logon=request):
            self._print("Logon data deleted")

    def complete_del_logon(self, text, line, begidx, endidx):
        if self._completion_arg(line, begidx) == 0:
            return self._complete_values(text, ms_logon_type_values)
        return []

    def do_text_set(self, args):
        """Set client text. Options: <client name> <text>"""
        arguments = self._parse_args(args)
        if arguments is None:
            return
        if len(arguments) != 2 or len(arguments[1].encode("utf-8")) > 80:
            self._error("Wrong parameters ! Specify client name and text up to 80 bytes")
            return
        if self._send_simple(0x02, 0x01, opcode=0x22,
                             text_name=arguments[0],
                             text_value=arguments[1]):
            self._print("Client text set")

    def do_text_get(self, args):
        """Get client text. Options: <client name>"""
        arguments = self._parse_args(args)
        if arguments is None:
            return
        if len(arguments) != 1:
            self._error("Wrong parameters ! Specify client name")
            return
        response = self._send_simple(0x02, 0x01, opcode=0x23,
                                     text_name=arguments[0])
        if response:
            self._print("Client text: %s" % self._decode(response.text_value))

    def complete_text_get(self, text, line, begidx, endidx):
        return self._complete_client_names(text)

    complete_text_set = complete_set_security_key

    def do_server_parameters(self, args):
        """ Dump server parameters. """
        self.do_dump("3")

    def do_server_release(self, args):
        """ Dump release information. """
        self.do_dump("8")

    def do_trace_increase(self, args):
        """ Increase server's trace level. """

        # Send MS_INCRE_TRACE
        response = self._send_simple(0x02, 0x01, opcode=0x0b)
        if response:
            self._print("Trace increased")

    def do_trace_decrease(self, args):
        """ Decrease server's trace level. """

        # Send MS_DECRE_TRACE
        response = self._send_simple(0x02, 0x01, opcode=0x0c)
        if response:
            self._print("Trace decreased")

    def do_trace_reset(self, args):
        """ Reset server's trace level. """

        # Send MS_RESET_TRACE
        response = self._send_simple(0x02, 0x01, opcode=0x0d)
        if response:
            self._print("Trace reset")

    def do_statistics_activate(self, args):
        """ Activates server's statistics. """

        # Send MS_ACT_STATISTIC
        response = self._send_simple(0x02, 0x01, opcode=0x0e)
        if response:
            self._print("Statistics activated")

    def do_statistics_deactivate(self, args):
        """ Deactivates server's statistics. """

        # Send MS_DEACT_STATISTIC
        response = self._send_simple(0x02, 0x01, opcode=0x0f)
        if response:
            self._print("Statistics deactivated")

    def do_statistics_reset(self, args):
        """ Reset server's statistics. """

        # Send MS_RESET_STATISTIC
        response = self._send_simple(0x02, 0x01, opcode=0x10)
        if response:
            self._print("Statistics reset")

    def do_statistics_get(self, args):
        """ Get server's statistics. """

        # Send MS_GET_STATISTIC
        response = self._send_simple(0x02, 0x01, opcode=0x11)
        if response:
            self._print("Statistics version %d: %d bytes" %
                        (response.opcode_version, len(response.stats)))

    def do_nitrace_get(self, args):
        """Get NI trace settings for a Message Server client."""
        response = self._send_simple(
            0x02, 0x01, opcode=0x3f, nitrace_client=args,
            nitrace_operation=0, nitrace_level=0)
        if response:
            self._print("NI trace operation=%d level=%d" %
                        (response.nitrace_operation,
                         response.nitrace_level))

    def complete_nitrace_get(self, text, line, begidx, endidx):
        return self._complete_client_names(text)

    def do_server_generation_list(self, args):
        """List clients from the active server generation."""
        response = self._send_simple(0x02, 0x01, opcode=0x4f)
        if response:
            clients = getattr(response, "clients_v%d" %
                              response.opcode_version, None)
            if response.opcode_version == 1:
                clients = response.clients
            self._print("Server generation clients: %d" %
                        len(clients or []))

    def do_subsystem_list(self, args):
        """List Message Server clients in the current subsystem."""
        response = self._send_simple(0x02, 0x01, opcode=0x4d)
        if response:
            self._show_clients(response)

    def do_log_counter_read(self, args):
        """Read one page of Message Server log counters."""
        response = self._send_simple(0x02, 0x01, opcode=0x50)
        if response and response.log_counter is not None:
            counter = response.log_counter
            self._print("Log counters: index=%d count=%d end=%d" %
                        (counter.index, counter.count, counter.end))
            for index, record in enumerate(counter.records):
                self._print("%d: %s" % (index, record.data.hex()))

    def do_log_counter_reset(self, args):
        """Reset Message Server log counters."""
        if self._send_simple(0x02, 0x01, opcode=0x51):
            self._print("Log counters reset")

    def do_network_buffer_dump(self, args):
        """ Dump network buffer. """

        # Send MS_DUMP_NIBUFFER
        response = self._send_simple(0x02, 0x01, opcode=0x12)
        if response:
            self._print("Network buffer dumped")

    def do_network_buffer_reset(self, args):
        """ Reset network buffer. """

        # Send MS_RESET_NIBUFFER
        response = self._send_simple(0x02, 0x01, opcode=0x13)
        if response:
            self._print("Network buffer reset")

    def do_noop(self, args):
        """Send a Message Server keepalive request."""
        if self._send_simple(0x02, 0x01, opcode=0x21):
            self._print("NOOP sent")

    def do_file_reload(self, args):
        """Reload a Message Server file/table. Options: <reload operation>"""
        try:
            operation = int((args or "").strip())
            if operation not in ms_file_reload_values:
                raise ValueError
        except ValueError:
            self._error("Invalid reload operation ! Valid values:")
            for key, value in sorted(ms_file_reload_values.items()):
                self._error("%d: %s" % (key, value))
            return
        if self._send_simple(0x02, 0x01, opcode=0x1f,
                             file_reload=operation):
            self._print("Reloaded %s" % ms_file_reload_values[operation])

    def complete_file_reload(self, text, line, begidx, endidx):
        return self._complete_values(text, ms_file_reload_values)

    def do_get_codepage(self, args):
        """ Get code page. """

        # Send MS_GET_CODEPAGE
        response = self._send_simple(0x02, 0x01, opcode=0x1c)
        if response:
            self._print("Codepage: %s" % response.codepage)

    def do_counter_list(self, args):
        """ List Counters. """

        # Send MS_COUNTER_LST
        response = self._send_simple(0x02, 0x01, opcode=0x2a)
        if response:
            self._print("Counters:\n%s" % response.counters)

    def _counter_opcodes(self, counter, opcode, count=0, number=0):
        """ Helper for counter commands. """

        c = SAPMSCounter(uuid=counter, count=count, no=number)
        response = self._send_simple(0x02, 0x01, opcode=opcode, counter=c)
        if response and response.counter:
            self._print("Counter UUID: %s Count: %d No: %d" % (response.counter.uuid,
                                                               response.counter.count,
                                                               response.counter.no))

    def do_counter_get(self, args):
        """ Get Counter. Options: <counter> """
        self._counter_opcodes(args, 0x29)

    def do_counter_create(self, args):
        """ Create Counter. Options: <counter> """
        self._counter_opcodes(args, 0x24)

    def do_counter_delete(self, args):
        """ Delete Counter. Options: <counter> """
        self._counter_opcodes(args, 0x25)

    def do_counter_increment(self, args):
        """ Increment Counter. Options: <counter> <value> """
        try:
            counter, count = args.split()
            count = int(count)
        except ValueError:
            self._error("Invalid parameters !")
            return

        self._counter_opcodes(counter, 0x26, count=count)

    def do_counter_decrement(self, args):
        """ Decrement Counter. Options: <counter> <value> """
        try:
            counter, count = args.split()
            count = int(count)
        except ValueError:
            self._error("Invalid parameters !")
            return

        self._counter_opcodes(counter, 0x27, count=count)

    def do_counter_register(self, args):
        """ Register Counter. Options: <counter> """
        self._counter_opcodes(args, 0x28)

    def do_server_disconnect(self, args):
        """ Server disconnect. Options: <client id> <reason> """

        try:
            client_id, reason = args.split(None, 1)
            client_id = int(client_id)
            client = self.clients[client_id]
        except (ValueError, KeyError, IndexError):
            self._error("Invalid parameters !")
            self.do_client_list(None)
            return

        # Send MS_SERVER_DISC packet
        response = self._send_simple(0x02, 0x01, opcode=0x2e,
                                     shutdown_client=client,
                                     shutdown_reason=reason)
        if response:
            self._print("Disconnected from server")

    def do_server_shutdown(self, args):
        """ Server shutdown. Options: <client id> <reason> """

        try:
            client_id, reason = args.split(None, 1)
            client_id = int(client_id)
            client = self.clients[client_id]
        except (ValueError, KeyError, IndexError):
            self._error("Invalid parameters !")
            self.do_client_list(None)
            return

        # Send MS_SERVER_SHUTDOWN packet
        response = self._send_simple(0x02, 0x01, opcode=0x2f,
                                     shutdown_client=client,
                                     shutdown_reason=reason)
        if response:
            self._print("Server shutdown")

    def do_server_soft_shutdown(self, args):
        """ Server soft shutdown. Options: <client id> <reason> """

        try:
            client_id, reason = args.split(None, 1)
            client_id = int(client_id)
            client = self.clients[client_id]
        except (ValueError, KeyError, IndexError):
            self._error("Invalid parameters !")
            self.do_client_list(None)
            return

        # Send MS_SERVER_SOFT_SHUTDOWN packet
        response = self._send_simple(0x02, 0x01, opcode=0x30,
                                     shutdown_client=client,
                                     shutdown_reason=reason)
        if response:
            self._print("Server soft shutdown")

    def complete_server_client(self, text, line, begidx, endidx):
        if self._completion_arg(line, begidx) == 0:
            return self._complete_client_ids(text)
        return []

    complete_server_disconnect = complete_server_client
    complete_server_shutdown = complete_server_client
    complete_server_soft_shutdown = complete_server_client

    def do_soft_shutdown(self, args):
        """Request a soft shutdown of the Message Server."""
        if self._send_simple(0x02, 0x01, opcode=0x1d):
            self._print("Message Server soft shutdown requested")

    def do_property_get(self, args):
        """ Get property. Options: <client id> <prop id> """

        try:
            prop_client, prop_id = args.split()
            prop_client = self.clients[int(prop_client)]
            prop_id = int(prop_id)
            if prop_id not in ms_property_id_values:
                raise ValueError
        except (ValueError, KeyError, IndexError):
            self._error("Invalid parameters !")
            return

        # Send MS_GET_PROPERTY packet
        prop = SAPMSProperty(client=prop_client.client,
                             id=prop_id)
        response = self._send_simple(0x02, 0x01, opcode=0x44,
                                     property=prop)
        if response:
            self._print("Property %s for client %s:" % (ms_property_id_values[prop_id],
                                                        self._decode(prop_client.client)))
            response.property.show()

    def do_property_set(self, args):
        """Set a property. Options: <client id> <property id> <value>"""
        arguments = self._parse_args(args)
        if arguments is None:
            return
        try:
            client = self.clients[int(arguments[0])]
            property_id = int(arguments[1])
            values = arguments[2:]
            if property_id not in ms_property_id_values:
                raise ValueError
            prop_args = {"client": client.client, "id": property_id}
            if property_id == 2:
                if len(values) != 2:
                    raise ValueError
                prop_args.update(logon=int(values[0]), value=values[1])
            elif property_id == 3:
                if len(values) != 1:
                    raise ValueError
                address = ipaddress.ip_address(values[0])
                if address.version == 4:
                    prop_args["address"] = str(address)
                else:
                    prop_args["address6"] = str(address)
            elif property_id == 4:
                if len(values) != 2:
                    raise ValueError
                prop_args.update(param=values[0], param_value=values[1])
            elif property_id == 5:
                if len(values) != 2:
                    raise ValueError
                prop_args.update(service=int(values[0]),
                                 service_value=int(values[1]))
            elif property_id == 7:
                if len(values) != 4:
                    raise ValueError
                prop_args.update(release=values[0], patchno=int(values[1]),
                                 supplvl=int(values[2]), platform=int(values[3]))
            else:
                if len(values) != 1:
                    raise ValueError
                prop_args["raw_value"] = values[0]
        except (IndexError, KeyError, ValueError):
            self._error("Invalid client, property id or property value")
            return

        prop = SAPMSProperty(**prop_args)
        if self._send_simple(0x02, 0x01, opcode=0x43, property=prop):
            self._print("Property %s set for client %s" %
                        (ms_property_id_values[property_id],
                         self._decode(client.client)))

    def do_property_delete(self, args):
        """Delete a property. Options: <client id> <property id>"""
        try:
            client_id, property_id = (args or "").split()
            client = self.clients[int(client_id)]
            property_id = int(property_id)
            if property_id not in ms_property_id_values:
                raise ValueError
        except (IndexError, KeyError, ValueError):
            self._error("Invalid client or property id")
            return
        prop = SAPMSProperty(client=client.client, id=property_id)
        if self._send_simple(0x02, 0x01, opcode=0x45, property=prop):
            self._print("Property %s deleted for client %s" %
                        (ms_property_id_values[property_id],
                         self._decode(client.client)))

    def complete_property(self, text, line, begidx, endidx):
        argument = self._completion_arg(line, begidx)
        if argument == 0:
            return self._complete_client_ids(text)
        if argument == 1:
            return self._complete_values(text, ms_property_id_values)
        return []

    complete_property_get = complete_property
    complete_property_set = complete_property
    complete_property_delete = complete_property

    def do_parameter_get(self, args):
        """ Get parameter value. Options: <parameter name> """

        if not self._require_connection():
            return

        parameter_name = args

        # Send ADM AD_PROFILE request
        adm = SAPMSAdmRecord(opcode=0x1, parameter=parameter_name)
        p = self._build(0x04, 0x05, adm_records=[adm])

        response = self.connection.sr(p)[SAPMS]

        if response.adm_records and response.adm_records[0].errorno == 0:
            param = response.adm_records[0].parameter
            if isinstance(param, bytes):
                param = param.decode("utf-8", errors="replace").strip("\x00").strip()
            self._print("Parameter value: %s" % param)
        else:
            self._error("Error retrieving the parameter !")

    def do_parameter_set(self, args):
        """ Set parameter value (requires monitor mode enabled).
            Options: <parameter name> <parameter value> """

        if not self._require_connection():
            return
        try:
            parameter_name, parameter_value = args.split(None, 1)
        except ValueError:
            self._error("Invalid parameters !")
            return

        # Send ADM AD_SHARED_PARAMETER request
        adm = SAPMSAdmRecord(opcode=0x2e,
                             parameter="%s=%s" % (parameter_name,
                                                  parameter_value))
        p = self._build(0x04, 0x05, adm_records=[adm])

        response = self.connection.sr(p)[SAPMS]

        if not response.adm_records or response.adm_records[0].errorno != 0:
            self._error("Error changing the parameter !")
        else:
            self._print("Parameter %s set to %s !" % (parameter_name,
                                                       parameter_value))

    def do_check_acl(self, args):
        """ Check the effective Message Server ACL.
            Options: [IP address] """

        address = args.strip() if args else ""
        request = {"opcode": 71, "opcode_version": 1,
                   "opcode_charset": 0}
        if address:
            try:
                parsed_address = ipaddress.ip_address(address)
            except ValueError:
                self._error("Invalid IP address")
                return
            if parsed_address.version == 4:
                address = "::ffff:%s" % parsed_address
            else:
                address = str(parsed_address)
            request.update(opcode_version=2,
                           check_acl_address=address)

        response = self._send_simple(0x02, 0x01, **request)

        if response:
            if response.error_code:
                error = ms_opcode_error_values.get(response.error_code,
                                                   "UNKNOWN")
                self._error("Error checking ACL: %s (%d)" %
                            (error, response.error_code))
            else:
                acl = response.acl
                if isinstance(acl, bytes):
                    acl = acl.decode("utf-8", errors="replace").strip("\x00").strip()
                self._print("ACL: %s" % acl)


# Command line options parser
def parse_options():

    description = "This script is an example implementation of SAP's Message Server Monitor program (msmon). It " \
                  "allows the monitoring of a Message Server service and allows sending different commands and " \
                  "opcodes. Includes some commands not available on the msmon program. Some commands requires the " \
                  "server running in monitor mode, the most requires access to the Message Server internal port."

    usage = "%(prog)s [options] -d <remote host>"

    parser = ArgumentParser(usage=usage, description=description, epilog=pysap.epilog)

    target = parser.add_argument_group("Target")
    target.add_argument("-d", "--remote-host", dest="remote_host",
                        help="Remote host")
    target.add_argument("-p", "--remote-port", dest="remote_port", type=int, default=3900,
                        help="Remote port [%(default)d]")
    target.add_argument("--route-string", dest="route_string",
                        help="Route string for connecting through a SAP Router")
    target.add_argument("--domain", dest="domain", default="ABAP",
                        help="Domain to connect to (ABAP, J2EE or JSTARTUP) [%(default)s]")

    misc = parser.add_argument_group("Misc options")
    misc.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Verbose output")
    misc.add_argument("-c", "--client", dest="client", default="pysap's-monitor",
                      help="Client name [%(default)s]")
    misc.add_argument("--log-file", dest="logfile", metavar="FILE",
                      help="Log file")
    misc.add_argument("--console-log", dest="consolelog", metavar="FILE",
                      help="Console log file")
    misc.add_argument("--script", dest="script", metavar="FILE",
                      help="Script file to run")

    options = parser.parse_args()

    if not (options.remote_host or options.route_string):
        parser.error("Remote host or route string is required")
    if options.domain not in ms_domain_values_inv.keys():
        parser.error("Invalid domain specified")

    return options


# Main function
def main():
    options = parse_options()

    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)

    ms_console = SAPMSMonitorConsole(options)

    try:
        if options.script:
            ms_console.do_script(options.script)
        else:
            ms_console.cmdloop()
    except KeyboardInterrupt:
        print("Cancelled by the user !")
        ms_console.do_exit(None)


if __name__ == "__main__":
    main()
