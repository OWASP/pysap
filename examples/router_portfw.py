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
from scapy.config import conf
from scapy.supersocket import socket
# Custom imports
from pysap.SAPNI import SAPNIProxy, SAPNIProxyHandler
from pysap.SAPRouter import SAPRouter, router_is_error, router_is_pong,\
    SAPRouterRouteHop


# Set the verbosity to 0
conf.verb = 0


# Command line options parser
def parse_options():

    description = \
    """This example script routes a connection through a SAP Router service.

    Similar to Bizploit's 'saprouterNative', for more information check:
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
    target.add_option("-t", "--target-host", dest="target_host", help="Target host to connect")
    target.add_option("-r", "--target-port", dest="target_port", type="int", help="Target port to connect")
    target.add_option("-P", "--target-pass", dest="target_pass", help="Target password")
    target.add_option("-a", "--local-host", dest="local_host", help="Local host to listen [%default]", default="127.0.0.1")
    target.add_option("-l", "--local-port", dest="local_port", type="int", help="Local port to listen [target-port]")
    parser.add_option_group(target)

    misc = OptionGroup(parser, "Misc options")
    misc.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False, help="Verbose output [%default]")
    parser.add_option_group(misc)

    (options, _) = parser.parse_args()

    if not options.remote_host:
        parser.error("Remote host is required")
    if not options.target_host:
        parser.error("Target host to connect to is required")
    if not options.target_port:
        parser.error("Target port to connect to is required")

    if not options.local_port:
        print "[*] No local port specified, using target port %d" % options.target_port
        options.local_port = options.target_port

    return options


class RouteException(Exception):
    pass


class SAPRouterNativeRouter(SAPNIProxyHandler):

    def __init__(self, client, server, options=None):
        self.options = options
        self.routed = False
        self.mtu = 2048
        self.route(server)
        super(SAPRouterNativeRouter, self).__init__(client, server, options)

    def route(self, server):
        print "[*] Routing to %s:%d !" % (self.options.target_host,
                                          self.options.target_port)

        # Build the Route request packet
        router_string = [SAPRouterRouteHop(hostname=self.options.remote_host,
                                           port=self.options.remote_port),
                         SAPRouterRouteHop(hostname=self.options.target_host,
                                           port=self.options.target_port,
                                           password=self.options.target_pass)]
        router_string_lens = map(len, map(str, router_string))
        p = SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                      route_entries=len(router_string),
                      route_talk_mode=1,
                      route_rest_nodes=1,
                      route_length=sum(router_string_lens),
                      route_offset=router_string_lens[0],
                      route_string=router_string)

        if self.options.verbose:
            p.show2()

        # Send the request and grab the response
        response = server.sr(p)

        if SAPRouter in response:
            response = response[SAPRouter]
            if router_is_pong(response):
                print "[*] Route request accepted !"
                self.routed = True
            elif router_is_error(response) and response.return_code == -94:
                print "[*] Route request not accepted !"
                print response.err_text_value
                raise RouteException("Route request not accepted")
            else:
                print "[*] Router send error"
                print response.err_text_value
                raise Exception("Router error: %s", response.err_text_value)
        else:
            print "[*] Wrong response received !"
            raise Exception("Wrong response received")

    def recv_send(self, local, remote, process):

        # If the route was accepted, we don't need the NI layer anymore.
        # Just use the plain socket inside the NIStreamSockets.
        if self.routed:
            # Receive a native packet (not SAP NI)
            packet = local.ins.recv(self.mtu)
            logging.debug("SAPNIProxyHandler: Received %d native bytes", len(packet))

            # Handle close connection
            if len(packet) == 0:
                local.close()
                #remote.close()
                raise socket.error((100, "Underlying stream socket tore down"))

            # Send the packet to the remote peer
            remote.ins.sendall(packet)
            logging.debug("SAPNIProxyHandler: Sent %d native bytes", len(packet))

        # If the route was not accepted yes, we need the NI layer to send
        # the route request packet.
        else:
            super(SAPRouterNativeRouter, self).recv_send(local, remote, process)


# Main function
def main():
    options = parse_options()

    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)

    print "[*] Setting a proxy between %s:%d and remote SAP Router %s:%d" % (options.local_host,
                                                                             options.local_port,
                                                                             options.remote_host,
                                                                             options.remote_port)
    proxy = SAPNIProxy(options.local_host, options.local_port,
                       options.remote_host, options.remote_port,
                       SAPRouterNativeRouter, keep_alive=False,
                       options=options)

    try:
        while (True):
            try:
                proxy.handle_connection()
            except socket.error, e:
                print "[*] Socket Error %s" % e

    except KeyboardInterrupt:
        print "[*] Cancelled by the user !"
    except RouteException, e:
        print "[*] Closing routing do to error %s" % e


if __name__ == "__main__":
    main()
