#!/usr/bin/env python
# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# Copyright (C) 2015 by Martin Gallo, Core Security
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
from scapy.config import conf
from scapy.packet import bind_layers
# Custom imports
import pysap
from pysap.SAPNI import SAPNIProxy, SAPNIProxyHandler, SAPNI, SAPNIStreamSocket
from pysap.SAPRouter import (SAPRouter, SAPRouterRouteHop, SAPRouteException,
                             router_is_error, router_is_pong)


# Bind the SAPRouter layer
bind_layers(SAPNI, SAPRouter, )

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

    epilog = "pysap %(version)s - %(url)s - %(repo)s" % {"version": pysap.__version__,
                                                         "url": pysap.__url__,
                                                         "repo": pysap.__repo__}

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
    target.add_option("--talk-mode", dest="talk_mode", help="Talk mode to use when requesting the route (raw or ni) [%default]", default="raw")
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
    options.talk_mode = options.talk_mode.lower()
    if options.talk_mode not in ["raw", "ni"]:
        parser.error("Invalid talk mode")

    if not options.local_port:
        print("[*] No local port specified, using target port %d" % options.target_port)
        options.local_port = options.target_port

    return options


class SAPRouterNativeRouterHandler(SAPNIProxyHandler):

    def __init__(self, client, server, options=None):
        self.options = options
        self.mtu = 2048
        super(SAPRouterNativeRouterHandler, self).__init__(client, server, options)

    def recv_send(self, local, remote, process):

        # Receive a native packet (not SAP NI)
        packet = local.ins.recv(self.mtu)
        logging.debug("SAPNIProxyHandler: Received %d native bytes", len(packet))

        # Handle close connection
        if len(packet) == 0:
            local.close()
            raise SocketError((100, "Underlying stream socket tore down"))

        # Send the packet to the remote peer
        remote.ins.sendall(packet)
        logging.debug("SAPNIProxyHandler: Sent %d native bytes", len(packet))


class SAPRouterNativeProxy(SAPNIProxy):

    def __init__(self, bind_address, bind_port, remote_address, remote_port,
                 handler, backlog=5, keep_alive=True, options=None):
        super(SAPRouterNativeProxy, self).__init__(bind_address, bind_port,
                                                   remote_address, remote_port,
                                                   handler, backlog, keep_alive,
                                                   options)
        self.route()

    def handle_connection(self):
        # Accept a client connection
        (client, __) = self.listener.ins.accept()

        # Creates a remote socket
        router = self.route()

        # Create the NI Stream Socket and handle it
        proxy = self.handler(SAPNIStreamSocket(client, self.keep_alive),
                             router,
                             self.options)
        return proxy

    def route(self):
        print("[*] Routing to %s:%d !" % (self.options.target_host,
                                          self.options.target_port))

        # Creates the connection with the SAP Router
        router = SAPNIStreamSocket.get_nisocket(self.options.remote_host,
                                                self.options.remote_port,
                                                keep_alive=self.keep_alive)

        # Build the Route request packet
        router_string = [SAPRouterRouteHop(hostname=self.options.remote_host,
                                           port=self.options.remote_port),
                         SAPRouterRouteHop(hostname=self.options.target_host,
                                           port=self.options.target_port,
                                           password=self.options.target_pass)]
        router_string_lens = list(map(len, list(map(str, router_string))))
        p = SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                      route_entries=len(router_string),
                      route_talk_mode=self.options.talk_mode,
                      route_rest_nodes=1,
                      route_length=sum(router_string_lens),
                      route_offset=router_string_lens[0],
                      route_string=router_string)

        if self.options.verbose:
            p.show2()

        # Send the request and grab the response
        response = router.sr(p)

        if SAPRouter in response:
            response = response[SAPRouter]
            if router_is_pong(response):
                print("[*] Route request accepted !")
                self.routed = True
            elif router_is_error(response) and response.return_code == -94:
                print("[*] Route request not accepted !")
                print(response.err_text_value)
                raise SAPRouteException("Route request not accepted")
            else:
                print("[*] Router send error")
                print(response.err_text_value)
                raise Exception("Router error: %s", response.err_text_value)
        else:
            print("[*] Wrong response received !")
            raise Exception("Wrong response received")

        return router


# Main function
def main():
    options = parse_options()

    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)

    print("[*] Setting a proxy between %s:%d and remote SAP Router %s:%d (talk mode %s)" % (options.local_host,
                                                                                            options.local_port,
                                                                                            options.remote_host,
                                                                                            options.remote_port,
                                                                                            options.talk_mode))

    options.talk_mode = {"raw": 1,
                         "ni": 0}[options.talk_mode]

    proxy = SAPRouterNativeProxy(options.local_host, options.local_port,
                                 options.remote_host, options.remote_port,
                                 SAPRouterNativeRouterHandler,
                                 keep_alive=False,
                                 options=options)

    try:
        while (True):
            try:
                proxy.handle_connection()
            except SocketError as e:
                print("[*] Socket Error %s" % e)

    except KeyboardInterrupt:
        print("[*] Cancelled by the user !")
    except SAPRouteException as e:
        print("[*] Closing routing do to error %s" % e)


if __name__ == "__main__":
    main()
