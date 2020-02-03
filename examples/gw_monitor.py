#!/usr/bin/env python
# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# The library was designed and developed by Martin Gallo from
# the SecureAuth Labs team.
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
# ==============

# Standard imports
import logging
from socket import error as SocketError
from optparse import OptionParser, OptionGroup
# External imports
from scapy.config import conf
# Custom imports
import pysap
from pysap.SAPRFC import SAPRFC
from pysap.utils.console import BaseConsole
from pysap.SAPRouter import SAPRoutedStreamSocket


# Set the verbosity to 0
conf.verb = 0


class SAPGWMonitorConsole(BaseConsole):

    intro = "SAP Gateway/RFC Monitor Console"
    connection = None
    connected = False
    clients = []

    def __init__(self, options):
        super(SAPGWMonitorConsole, self).__init__(options)
        self.runtimeoptions["client"] = self.options.client
        self.runtimeoptions["version"] = self.options.version

    # Initialization
    def preloop(self):
        super(SAPGWMonitorConsole, self).preloop()
        self.do_connect(None)
        self.do_client_list(None)

    # SAP Gateway/RFC Monitor commands

    def do_connect(self, args):
        """ Initiate the connection to the Gateway service. The connection is
        registered using the client_string runtime option. """

        # Create the socket connection
        try:
            self.connection = SAPRoutedStreamSocket.get_nisocket(self.options.remote_host,
                                                                 self.options.remote_port,
                                                                 self.options.route_string,
                                                                 base_cls=SAPRFC)
        except SocketError as e:
            self._error("Error connecting with the Gateway service")
            self._error(str(e))
            return

        self._print("Attached to %s / %d" % (self.options.remote_host, self.options.remote_port))

        p = SAPRFC(version=int(self.runtimeoptions["version"]), req_type=1)

        self._debug("Sending check gateway packet")
        try:
            response = self.connection.send(p)
        except SocketError:
            self._error("Error connecting to the gateway monitor service")
        else:
            self.connected = True

    def do_disconnect(self, args):
        """ Disconnects from the Gateway service. """

        if not self.connected:
            self._error("You need to connect to the server first !")
            return

        self.connection.close()
        self._print("Dettached from %s / %d ..." % (self.options.remote_host, self.options.remote_port))
        self.connected = False

    def do_exit(self, args):
        if self.connected:
            self.do_disconnect(None)
        return super(SAPGWMonitorConsole, self).do_exit(args)

    def do_noop(self, args):
        """ Send a noop command to the Gateway service. """

        if not self.connected:
            self._error("You need to connect to the server first !")
            return

        p = SAPRFC(version=int(self.runtimeoptions["version"]), req_type=9,
                   cmd=1)
        self._debug("Sending noop packet")
        response = self.connection.send(p)

    def do_client_list(self, args):
        """ Retrieve the list of clients connected to the Gateway service.
        Use the client # value when required to provide a client IDs as
        parameter. """

        if not self.connected:
            self._error("You need to connect to the server first !")
            return


# Command line options parser
def parse_options():

    description = "This script is an example implementation of SAP's Gateway Monitor program (gwmon). It allows the " \
                  "monitoring of a Gateway service and allows sending different commands and opcodes."

    epilog = "pysap %(version)s - %(url)s - %(repo)s" % {"version": pysap.__version__,
                                                         "url": pysap.__url__,
                                                         "repo": pysap.__repo__}

    usage = "Usage: %prog [options] -d <remote host>"

    parser = OptionParser(usage=usage, description=description, epilog=epilog)

    target = OptionGroup(parser, "Target")
    target.add_option("-d", "--remote-host", dest="remote_host",
                      help="Remote host")
    target.add_option("-p", "--remote-port", dest="remote_port", type="int", default=3300,
                      help="Remote port [%default]")
    target.add_option("--route-string", dest="route_string",
                      help="Route string for connecting through a SAP Router")
    target.add_option("--version", dest="version", type="int", default=3,
                      help="Version of the protocol to use [%default]")
    parser.add_option_group(target)

    misc = OptionGroup(parser, "Misc options")
    misc.add_option("-c", "--client", dest="client", default="pysap's-monitor",
                    help="Client name [%default]")
    misc.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False,
                    help="Verbose output [%default]")
    misc.add_option("--log-file", dest="logfile", metavar="FILE",
                    help="Log file")
    misc.add_option("--console-log", dest="consolelog", metavar="FILE",
                    help="Console log file")
    misc.add_option("--script", dest="script", metavar="FILE",
                    help="Script file to run")
    parser.add_option_group(misc)

    (options, _) = parser.parse_args()

    if not (options.remote_host or options.route_string):
        parser.error("Remote host or route string is required")

    return options


# Main function
def main():
    options = parse_options()

    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)

    rfc_console = SAPGWMonitorConsole(options)

    try:
        if options.script:
            rfc_console.do_script(options.script)
        else:
            rfc_console.cmdloop()
    except KeyboardInterrupt:
        print("Cancelled by the user !")
        rfc_console.do_exit(None)


if __name__ == "__main__":
    main()
