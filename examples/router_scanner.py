#!/usr/bin/python
## ===========
## pysap - Python library for crafting SAP's network protocols packets
##
## Copyright (C) 2014 Core Security Technologies
##
## The library was designed and developed by Martin Gallo from the Security
## Consulting Services team of Core Security Technologies.
##
## This program is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License
## as published by the Free Software Foundation; either version 2
## of the License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##==============

# Standard imports
import logging
from optparse import OptionParser, OptionGroup
# External imports
try:
    import netaddr
except ImportError:
    print "[-] netaddr library not found, running without network range parsing support"
    netaddr = None

from scapy.config import conf
from scapy.supersocket import socket
# Custom imports
from pysap.SAPNI import SAPNIStreamSocket
from pysap.SAPRouter import SAPRouter, router_is_error, router_is_pong,\
    SAPRouterRouteHop, get_router_version


# Set the verbosity to 0
conf.verb = 0


# Command line options parser
def parse_options():

    description = \
    """This example script performs a port scanning through a SAP Router
    service.

    Similar to Bizploit's 'saprouterSpy', for more information check:
    * http://blog.onapsis.com/assessing-a-saprouters-security-with-onapsis-bizploit-part-i/
    * http://blog.onapsis.com/assessing-a-saprouters-security-with-onapsis-bizploit-part-ii/
    """

    epilog = \
    """pysap - http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=tool&name=pysap"""

    usage = "Usage: %prog [options] -d <remote host>"

    parser = OptionParser(usage=usage, description=description, epilog=epilog)

    target = OptionGroup(parser, "Target")
    target.add_option("-d", "--remote-host", dest="remote_host", help="Remote host [%default]", default="127.0.0.1")
    target.add_option("-p", "--remote-port", dest="remote_port", type="int", help="Remote port [%default]", default=3299)
    target.add_option("-t", "--target-hosts", dest="target_hosts", help="Target hosts to scan")
    target.add_option("-r", "--target-ports", dest="target_ports", help="Target ports to scan")
    target.add_option("--router-version", dest="router_version", type="int", help="SAP Router version to use [retrieve from the remote SAP Router]")
    parser.add_option_group(target)

    misc = OptionGroup(parser, "Misc options")
    misc.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False, help="Verbose output [%default]")
    parser.add_option_group(misc)

    (options, _) = parser.parse_args()

    if not options.remote_host:
        parser.error("Remote host is required")
    if not options.target_hosts:
        parser.error("Target hosts to scan are required")
    if not options.target_ports:
        parser.error("Target ports to scan are required")

    return options


def parse_target_hosts(target_hosts, target_ports):
    for port in target_ports.split(','):
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


def route_test(rhost, rport, thost, tport):

    print "[*] Routing connections to %s:%s" % (thost, tport)

    # Initiate the connection. We don't want the NI Stream Socket to handle
    # keep-alive messages, as the response to connect requests are NI_PONG
    conn = SAPNIStreamSocket.get_nisocket(rhost, rport, keep_alive=False)

    router_string = [SAPRouterRouteHop(hostname=rhost,
                                       port=rport),
                     SAPRouterRouteHop(hostname=thost,
                                       port=tport)]

    router_string_lens = map(len, map(str, router_string))

    p = SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                  route_entries=len(router_string),
                  route_talk_mode=1,
                  route_rest_nodes=1,
                  route_length=sum(router_string_lens),
                  route_offset=router_string_lens[0],
                  route_string=router_string,
                  )

    response = conn.sr(p)

    if router_is_error(response):
        status = 'error'
    elif router_is_pong(response):
        status = 'open'

    conn.close()

    return status


# Main function
def main():
    options = parse_options()

    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)

    print "[*] Connecting to SAP Router %s:%d" % (options.remote_host,
                                                  options.remote_port)

    # Retrieve the router version used by the server if not specified
    if options.router_version is None:
        sock = socket.socket()
        sock.connect((options.remote_host, options.remote_port))
        conn = SAPNIStreamSocket(sock, keep_alive=False)
        options.router_version = get_router_version(conn)
        conn.close()
    print "[*] Using SAP Router version %d" % options.router_version

    results = []
    for (host, port) in parse_target_hosts(options.target_hosts, options.target_ports):
        status = route_test(options.remote_host, options.remote_port, host, port)
        if options.verbose:
            print "[*] Status of %s:%s: %s" % (host, port, status)
        if status == "open":
            results.append((host, port))

    print "[*] Host/Ports found open:"
    for (host, port) in results:
        print "\tHost: %s\tPort:%s" % (host, port)


if __name__ == "__main__":
    main()
