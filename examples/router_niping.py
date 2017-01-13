#!/usr/bin/env python
# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# Copyright (C) 2012-2017 by Martin Gallo, Core Security
#
# The library was designed and developed by Martin Gallo from the Security
# Consulting Services team of Core Security.
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
from scapy.packet import Raw
from scapy.config import conf
# Custom imports
import pysap
from pysap.SAPRouter import SAPRoutedStreamSocket


# Set the verbosity to 0
conf.verb = 0


# Command line options parser
def parse_options():

    description = "This script is an example implementation of SAP's niping utility."

    epilog = "pysap %(version)s - %(url)s - %(repo)s" % {"version": pysap.__version__,
                                                         "url": pysap.__url__,
                                                         "repo": pysap.__repo__}

    usage = "Usage: %prog [options] [mode] -d <remote host>"

    parser = OptionParser(usage=usage, description=description, epilog=epilog)

    mode = OptionGroup(parser, "Running mode")
    mode.add_option("-s", "--start-server", dest="server", action="store_true",
                    help="Start server")
    mode.add_option("-c", "--start-client", dest="client", action="store_true",
                    help="Start client")
    parser.add_option_group(mode)

    target = OptionGroup(parser, "Target")
    target.add_option("-H", "--host", dest="host", help="Host")
    target.add_option("-S", "--port", dest="port", type="int", default=3298,
                      help="Port [%default]")
    target.add_option("--route-string", dest="route_string",
                      help="Route string for connecting through a SAP Router")
    parser.add_option_group(target)

    misc = OptionGroup(parser, "Misc options")
    misc.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False,
                    help="Verbose output [%default]")
    misc.add_option("-B", "--buffer-size", dest="buffer_size", type="int", default=1000,
                    help="Size of data-buffer [%default]")
    misc.add_option("-L", "--loops", dest="loops", type="int", default=10,
                    help="Number of loops [%default]")
    parser.add_option_group(misc)

    (options, _) = parser.parse_args()

    if not options.server and not options.client:
        parser.error("Running mode is required")

    if options.client and not options.host:
        parser.error("Remote host is required for starting a client")

    return options


# Main function
def main():
    options = parse_options()

    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)

    if options.buffer_size < 10:
        print("[*] Using minimum buffer size of 10 bytes")
        options.buffer_size = 10

    # Client running mode
    if options.client:

        p = Raw("EYECATCHER" + "\x00" * (options.buffer_size - 10))

        try:
            # Establish the connection
            conn = SAPRoutedStreamSocket.get_nisocket(options.host,
                                                      options.port,
                                                      options.route_string)
            print("connect to server o.k.")

            # Send the messages
            for i in range(options.loops):
                r = conn.sr(p)
                if str(r.payload) != str(p):
                    print("[-] Response on message %d differs" % i)

            # Close the connection properly
            conn.send(Raw())
            conn.close()

        except SocketError:
            print("[*] Connection error")
        except KeyboardInterrupt:
            print("[*] Cancelled by the user")

        # Print the stats
        print("send and receive %d messages (len %d)" % (i + 1, options.buffer_size))


if __name__ == "__main__":
    main()
