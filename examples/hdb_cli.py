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
import socket
import logging
from binascii import unhexlify
from optparse import OptionParser, OptionGroup
# External imports
from scapy.config import conf
# Custom imports
import pysap
from pysap.SAPHDB import (SAPHDBConnection, SAPHDBTLSConnection, SAPHDBConnectionError,
                          SAPHDBAuthenticationError, saphdb_auth_methods)


# Set the verbosity to 0
conf.verb = 0


# Command line options parser
def parse_options():

    description = "This example script is an experimental implementation of the HANA's hdbcli tool."

    epilog = "pysap %(version)s - %(url)s - %(repo)s" % {"version": pysap.__version__,
                                                         "url": pysap.__url__,
                                                         "repo": pysap.__repo__}

    usage = "Usage: %prog [options] -d <remote host>"

    parser = OptionParser(usage=usage, description=description, epilog=epilog)

    target = OptionGroup(parser, "Target")
    target.add_option("-d", "--remote-host", dest="remote_host",
                      help="Remote host")
    target.add_option("-p", "--remote-port", dest="remote_port", type="int", default=39015,
                      help="Remote port [%default]")
    target.add_option("--route-string", dest="route_string",
                      help="Route string for connecting through a SAP Router")
    target.add_option("--tls", dest="tls", action="store_true", default=False,
                      help="Use TLS/SSL [%default]")
    parser.add_option_group(target)

    auth = OptionGroup(parser, "Authentication")
    auth.add_option("-m", "--method", dest="method", default="SCRAMSHA256",
                    help="Authentication method. Supported methods: SCRAMSHA256, SCRAMPBKDF2SHA256, SessionCookie [%default]")
    auth.add_option("--username", dest="username", help="User name")
    auth.add_option("--password", dest="password", help="Password")
    auth.add_option("--session-cookie", dest="session_cookie", help="Session Cookie")
    auth.add_option("--pid", dest="pid", default="pysap", help="Process ID")
    auth.add_option("--hostname", dest="hostname", help="Hostname")
    parser.add_option_group(auth)

    misc = OptionGroup(parser, "Misc options")
    misc.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False,
                    help="Verbose output [%default]")
    parser.add_option_group(misc)

    (options, _) = parser.parse_args()

    if not options.remote_host:
        parser.error("Remote host is required")

    if options.method not in saphdb_auth_methods:
        parser.error("Invalid authentication method")
    if options.method in ["SCRAMSHA256", "SCRAMPBKDF2SHA256"] and (not options.username or not options.password):
        parser.error("Username and password need to be provided")
    if options.method == "SessionCookie" and (not options.username or not options.session_cookie):
        parser.error("Username and session cookie need to be provided")

    return options


# Main function
def main():
    options = parse_options()

    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)

    # Initiate the connection
    connection_class = SAPHDBConnection
    if options.tls:
        connection_class = SAPHDBTLSConnection

    # Select the desired authentication method
    print("[*] Using authentication method %s" % options.method)
    auth_method_cls = saphdb_auth_methods[options.method]
    if options.method in ["SCRAMSHA256", "SCRAMPBKDF2SHA256"]:
        auth_method = auth_method_cls(options.username, options.password)
    elif options.method == "SessionCookie":
        auth_method = auth_method_cls(options.username, options.session_cookie, options.pid, options.hostname)
    else:
        print("[-] Unsupported authentication method")
        return

    # Create the connection
    hdb = connection_class(options.remote_host,
                           options.remote_port,
                           auth_method=auth_method,
                           route=options.route_string)

    try:
        hdb.connect()
        print("[*] Connected to HANA database %s:%d" % (options.remote_host, options.remote_port))
        hdb.initialize()
        print("[*] HANA database version %d/protocol version %d" % (hdb.product_version,
                                                                    hdb.protocol_version))
        hdb.authenticate()
        print("[*] Authenticated against HANA database server")

        hdb.close()
        print("[*] Connection with HANA database server closed")

    except SAPHDBAuthenticationError as e:
        print("[-] Authentication error: %s" % e.message)
    except SAPHDBConnectionError as e:
        print("[-] Connection error: %s" % e.message)
    except KeyboardInterrupt:
        print("[-] Connection canceled")


if __name__ == "__main__":
    main()
