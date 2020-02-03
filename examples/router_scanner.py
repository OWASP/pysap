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
from scapy.packet import bind_layers
# Custom imports
import pysap
from pysap.SAPNI import SAPNIStreamSocket, SAPNI
from pysap.SAPRouter import (SAPRouterRouteHop, get_router_version,
                             SAPRoutedStreamSocket, SAPRouteException,
                             SAPRouter)
# Optional imports
try:
    import netaddr
except ImportError:
    print("[-] netaddr library not found, running without network range parsing support")
    netaddr = None


# Bind the SAPRouter layer
bind_layers(SAPNI, SAPRouter, )

# Set the verbosity to 0
conf.verb = 0


# Command line options parser
def parse_options():

    description = "This example script performs a port scanning through a SAP Router service. Similar to Bizploit's " \
                  "'saprouterSpy', for more information check: " \
                  "https://blog.onapsis.com/blog/assessing-a-saprouters-security-with-onapsis-bizploit-part-i/ and " \
                  "https://blog.onapsis.com/blog/assessing-a-saprouters-security-with-onapsis-bizploit-part-ii/"

    epilog = "pysap %(version)s - %(url)s - %(repo)s" % {"version": pysap.__version__,
                                                         "url": pysap.__url__,
                                                         "repo": pysap.__repo__}

    usage = "Usage: %prog [options] -d <remote host>"

    parser = OptionParser(usage=usage, description=description, epilog=epilog)

    target = OptionGroup(parser, "Target")
    target.add_option("-d", "--remote-host", dest="remote_host", default="127.0.0.1",
                      help="Remote host [%default]")
    target.add_option("-p", "--remote-port", dest="remote_port", type="int", default=3299,
                      help="Remote port [%default]")
    target.add_option("-t", "--target-hosts", dest="target_hosts",
                      help="Target hosts to scan (comma separated or CIDR if netaddr is installed)")
    target.add_option("-r", "--target-ports", dest="target_ports",
                      help="Target ports to scan (comma separated or range)")
    target.add_option("--router-version", dest="router_version", type="int",
                      help="SAP Router version to use [retrieve from the remote SAP Router]")
    target.add_option("--talk-mode", dest="talk_mode", default="raw",
                      help="Talk mode to use when requesting the route (raw or ni) [%default]")
    parser.add_option_group(target)

    misc = OptionGroup(parser, "Misc options")
    misc.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False,
                    help="Verbose output [%default]")
    parser.add_option_group(misc)

    (options, _) = parser.parse_args()

    if not options.remote_host:
        parser.error("Remote host is required")
    if not options.target_hosts:
        parser.error("Target hosts to scan are required")
    if not options.target_ports:
        parser.error("Target ports to scan are required")
    options.talk_mode = options.talk_mode.lower()
    if options.talk_mode not in ["raw", "ni"]:
        parser.error("Invalid talk mode")

    return options


def parse_target_ports(target_ports):
    ranges = (x.split("-") for x in target_ports.split(","))
    return [i for r in ranges for i in range(int(r[0]), int(r[-1]) + 1)]


def parse_target_hosts(target_hosts, target_ports):
    for port in parse_target_ports(target_ports):
        for host in target_hosts.split(','):
            if netaddr:
                if netaddr.valid_nmap_range(host):
                    for ip in netaddr.iter_nmap_range(host):
                        yield (ip, port)
                else:
                    for ip in netaddr.iter_unique_ips(host):
                        yield (ip, port)
            else:
                yield(host, port)


def route_test(rhost, rport, thost, tport, talk_mode, router_version):

    logging.info("[*] Routing connections to %s:%s" % (thost, tport))

    # Build the route to the target host passing through the SAP Router
    route = [SAPRouterRouteHop(hostname=rhost,
                               port=rport),
             SAPRouterRouteHop(hostname=thost,
                               port=tport)]

    # Try to connect to the target host using the routed stream socket
    try:
        conn = SAPRoutedStreamSocket.get_nisocket(route=route,
                                                  talk_mode=talk_mode,
                                                  router_version=router_version)
        conn.close()
        status = 'open'

    # If an SAPRouteException is raised, the route was denied or an error
    # occurred with the SAP router
    except SAPRouteException:
        status = 'denied'

    # Another error occurred on the server (e.g. timeout), mark the target as error
    except Exception:
        status = 'error'

    return status


# Main function
def main():
    options = parse_options()

    level = logging.INFO
    if options.verbose:
        level = logging.DEBUG
    logging.basicConfig(level=level, format='%(message)s')

    logging.info("[*] Connecting to SAP Router %s:%d (talk mode %s)" % (options.remote_host,
                                                                        options.remote_port,
                                                                        options.talk_mode))

    # Retrieve the router version used by the server if not specified
    if options.router_version is None:
        conn = SAPNIStreamSocket.get_nisocket(options.remote_host,
                                              options.remote_port,
                                              keep_alive=False)
        options.router_version = get_router_version(conn)
        conn.close()
    logging.info("[*] Using SAP Router version %d" % options.router_version)

    options.talk_mode = {"raw": 1,
                         "ni": 0}[options.talk_mode]

    results = []
    for (host, port) in parse_target_hosts(options.target_hosts, options.target_ports):
        status = route_test(options.remote_host, options.remote_port, host, port,
                            options.talk_mode, options.router_version)
        if options.verbose:
            logging.info("[*] Status of %s:%s: %s" % (host, port, status))
        if status == "open":
            results.append((host, port))

    logging.info("[*] Host/Ports found open:")
    for (host, port) in results:
        logging.info("\tHost: %s\tPort:%s" % (host, port))


if __name__ == "__main__":
    main()
