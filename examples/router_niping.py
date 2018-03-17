#!/usr/bin/env python
# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# Copyright (C) 2012-2018 by Martin Gallo, Core Security
#
# The library was designed and developed by Martin Gallo from
# Core Security's CoreLabs team.
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
from datetime import datetime
from optparse import OptionParser, OptionGroup
from socket import socket, SHUT_RDWR, error as SocketError
# External imports
from scapy.packet import Raw
from scapy.config import conf
# Custom imports
import pysap
from pysap.SAPNI import SAPNIStreamSocket
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

    if options.client and not (options.host or options.route_string):
        parser.error("Remote host is required for starting a client")

    return options


def client_mode(options):
    """"Implements the niping client running mode

    :param options: option set from the command line
    :type options: Values
    """

    times = []
    p = Raw("EYECATCHER" + "\x00" * (options.buffer_size - 10))

    try:
        # Establish the connection
        conn = SAPRoutedStreamSocket.get_nisocket(options.host,
                                                  options.port,
                                                  options.route_string)
        print("")
        print(datetime.today().ctime())
        print("connect to server o.k.")

        # Send the messages
        for i in range(options.loops):

            # Send the packet and grab the response
            start_time = datetime.now()
            r = conn.sr(p)
            end_time = datetime.now()

            # Check the response
            if str(r.payload) != str(p):
                print("[-] Response on message {} differs".format(i))

            # Calculate and record the elapsed time
            times.append(end_time - start_time)

        # Close the connection properly
        conn.send(Raw())
        conn.close()

    except SocketError:
        print("[*] Connection error")
    except KeyboardInterrupt:
        print("[*] Cancelled by the user")

    if times:
        print("")
        print(datetime.today().ctime())
        print("send and receive {} messages (len {})".format(len(times), options.buffer_size))

        # Calculate the stats
        times = [x.total_seconds() * 1000 for x in times]
        times_min = min(times)
        times_max = max(times)
        times_avg = float(sum(times)) / max(len(times), 1)
        times_tr = float(options.buffer_size * len(times)) / float(sum(times))

        times2 = [x for x in times if x not in [times_min, times_max]]
        times2_avg = float(sum(times2)) / max(len(times2), 1)
        times2_tr = float(options.buffer_size * len(times2)) / float(sum(times2))

        # Print the stats
        print("")
        print("------- times -----")
        print("avg  {:8.3f} ms".format(times_avg))
        print("max  {:8.3f} ms".format(times_max))
        print("min  {:8.3f} ms".format(times_min))
        print("tr   {:8.3f} kB/s".format(times_tr))

        print("excluding max and min:")
        print("av2  {:8.3f} ms".format(times2_avg))
        print("tr2  {:8.3f} kB/s".format(times2_tr))
        print("")


def server_mode(options):
    """"Implements the niping server running mode

    :param options: option set from the command line
    :type options: Values
    """

    if not options.host:
        options.host = "0.0.0.0"

    sock = socket()
    try:
        sock.bind((options.host, options.port))
        sock.listen(0)
        print("")
        print(datetime.today().ctime())
        print("ready for connect from client ...")

        while True:
            sc, sockname = sock.accept()
            client = SAPNIStreamSocket(sc)

            print("")
            print(datetime.today().ctime())
            print("connect from host '{}', client hdl {} o.k.".format(sockname[0], client.fileno()))

            try:
                while True:
                    r = client.recv()
                    client.send(r.payload)

            except SocketError:
                pass

            finally:
                print("")
                print(datetime.today().ctime())
                print("client hdl {} disconnected ...".format(client.fileno()))

    except SocketError:
        print("[*] Connection error")
    except KeyboardInterrupt:
        print("[*] Cancelled by the user")

    finally:
        sock.shutdown(SHUT_RDWR)
        sock.close()


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
        client_mode(options)
    # Server running mode
    elif options.server:
        server_mode(options)


if __name__ == "__main__":
    main()
