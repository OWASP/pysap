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
from optparse import OptionParser, OptionGroup
# External imports
from scapy.config import conf
from scapy.packet import Raw
# Custom imports
import pysap
from pysap.SAPRouter import SAPRoutedStreamSocket
from pysap.SAPMS import SAPMS, ms_domain_values_inv


# Set the verbosity to 0
conf.verb = 0


# Command line options parser
def parse_options():

    description = "This example script connects with the Message Server service and sends a message to another client."

    epilog = "pysap %(version)s - %(url)s - %(repo)s" % {"version": pysap.__version__,
                                                         "url": pysap.__url__,
                                                         "repo": pysap.__repo__}

    usage = "Usage: %prog [options] -d <remote host> -t <target server> -m <message>"

    parser = OptionParser(usage=usage, description=description, epilog=epilog)

    target = OptionGroup(parser, "Target")
    target.add_option("-d", "--remote-host", dest="remote_host",
                      help="Remote host")
    target.add_option("-p", "--remote-port", dest="remote_port", type="int", default=3900,
                      help="Remote port [%default]")
    target.add_option("--route-string", dest="route_string",
                      help="Route string for connecting through a SAP Router")
    target.add_option("--domain", dest="domain", default="ABAP",
                      help="Domain to connect to (ABAP, J2EE or JSTARTUP) [%default]")
    parser.add_option_group(target)

    misc = OptionGroup(parser, "Misc options")
    misc.add_option("-c", "--client", dest="client", default="pysap's-messager",
                    help="Client name [%default]")
    misc.add_option("-m", "--message", dest="message", default="Message",
                    help="Message to send to the target client [%default]")
    misc.add_option("-t", "--target", dest="target", default="pysap's-listener",
                    help="Target client name to send the message [%default]")
    misc.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False,
                    help="Verbose output [%default]")
    parser.add_option_group(misc)

    (options, _) = parser.parse_args()

    if not (options.remote_host or options.route_string):
        parser.error("Remote host or route string is required")
    if not options.message or not options.target:
        parser.error("Target server and message are required !")
    if options.domain not in ms_domain_values_inv.keys():
        parser.error("Invalid domain specified")

    return options


# Main function
def main():
    options = parse_options()

    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)

    domain = ms_domain_values_inv[options.domain]

    # Initiate the connection
    conn = SAPRoutedStreamSocket.get_nisocket(options.remote_host,
                                              options.remote_port,
                                              options.route_string,
                                              base_cls=SAPMS)
    print("[*] Connected to the message server %s:%d" % (options.remote_host, options.remote_port))

    client_string = options.client

    # Send MS_LOGIN_2 packet
    p = SAPMS(flag=0x00, iflag=0x08, domain=domain, toname=client_string, fromname=client_string)

    print("[*] Sending login packet")
    response = conn.sr(p)[SAPMS]

    print("[*] Login performed, server string: %s" % response.fromname)

    # Sends a message to another client
    p = SAPMS(flag=0x02, iflag=0x01, domain=domain, toname=options.target, fromname=client_string, opcode=1)
    p /= Raw(options.message)

    print("[*] Sending packet to: %s" % options.target)
    conn.send(p)


if __name__ == "__main__":
    main()
