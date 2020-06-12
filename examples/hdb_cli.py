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
import datetime
from argparse import ArgumentParser
# External imports
from scapy.config import conf
# Custom imports
import pysap
from pysap.SAPHDB import (SAPHDBConnection, SAPHDBTLSConnection, SAPHDBConnectionError,
                          SAPHDBAuthenticationError, saphdb_auth_methods)
# Optional imports
try:
    import jwt as py_jwt
except ImportError:
    py_jwt = None


# Set the verbosity to 0
conf.verb = 0


# Command line options parser
def parse_options():

    description = "This example script is an experimental implementation of the HANA's hdbcli tool."

    usage = "%(prog)s [options] -d <remote host>"

    parser = ArgumentParser(usage=usage, description=description, epilog=pysap.epilog)

    target = parser.add_argument_group("Target")
    target.add_argument("-d", "--remote-host", dest="remote_host",
                        help="Remote host")
    target.add_argument("-p", "--remote-port", dest="remote_port", type=int, default=39015,
                        help="Remote port [%(default)d]")
    target.add_argument("--route-string", dest="route_string",
                        help="Route string for connecting through a SAP Router")
    target.add_argument("--tls", dest="tls", action="store_true",
                        help="Use TLS/SSL")

    auth = parser.add_argument_group("Authentication")
    auth.add_argument("-m", "--method", dest="method", default="SCRAMSHA256",
                      help="Authentication method. Supported methods: {} [%(default)s]".format(",".join(saphdb_auth_methods.keys())))
    auth.add_argument("--username", dest="username", help="User name")
    auth.add_argument("--password", dest="password", help="Password")
    auth.add_argument("--jwt-file", dest="jwt_file", metavar="FILE",
                      help="File to read a signed JWT from")
    auth.add_argument("--jwt-cert", dest="jwt_cert", metavar="FILE",
                      help="File to read the private key to sign the JWT")
    auth.add_argument("--jwt-issuer", dest="jwt_issuer", help="JWT signature issuer")
    auth.add_argument("--jwt-claim", dest="jwt_claim", default="user_name",
                      help="Name of the JWT claim to map username [%(default)s]")
    auth.add_argument("--saml-assertion", dest="saml_assertion", metavar="FILE",
                      help="File to read a signed SAML 2.0 bearer assertion from")
    auth.add_argument("--session-cookie", dest="session_cookie", help="Session Cookie")
    auth.add_argument("--pid", dest="pid", default="pysap", help="Process ID [%(default)s]")
    auth.add_argument("--hostname", dest="hostname", help="Hostname")

    misc = parser.add_argument_group("Misc options")
    misc.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Verbose output")

    options = parser.parse_args()

    if not options.remote_host:
        parser.error("Remote host is required")

    if options.method not in saphdb_auth_methods:
        parser.error("Invalid authentication method")
    if not options.username and options.method not in ["SAML"]:
        parser.error("Username needs to be provided")

    if options.method == "JWT":
        if not (options.jwt_file or (options.jwt_cert and options.jwt_issuer)):
            parser.error("JWT file or a signing certificate and issuer need to be provided for JWT authentication")
        if options.jwt_cert and not py_jwt:
            parser.error("JWT crafting requires the PyJWT library installed")

    if options.method == "SAML" and not options.saml_assertion:
        parser.error("SAML bearer assertion file need to be provided for SAML authentication")

    if options.method in ["SCRAMSHA256", "SCRAMPBKDF2SHA256"] and not options.password:
        parser.error("Password need to be provided for SCRAM-based authentication")

    if options.method == "SessionCookie" and not options.session_cookie:
        parser.error("Session cookie need to be provided for SessionCookie authentication")

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
    if options.method == "SAML":
        with open(options.saml_assertion, 'r') as saml_assertion_fd:
            auth_method = auth_method_cls("", saml_assertion_fd.read(),
                                          pid=options.pid, hostname=options.hostname)
    elif options.method == "JWT":
        if options.jwt_file:
            with open(options.jwt_file, 'r') as jwt_fd:
                auth_method = auth_method_cls(options.username, jwt_fd.read(),
                                              pid=options.pid, hostname=options.hostname)
        elif options.jwt_cert:
            with open(options.jwt_cert, 'r') as jwt_cert_fd:
                jwt_raw = {options.jwt_claim: options.username,
                           "iss": options.jwt_issuer,
                           "nbf": datetime.datetime.utcnow() - datetime.timedelta(seconds=30),
                           "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=30),
                           }
                jwt_signed = py_jwt.encode(jwt_raw, jwt_cert_fd.read(), algorithm="RS256")
                auth_method = auth_method_cls(options.username, jwt_signed,
                                              pid=options.pid, hostname=options.hostname)
    elif options.method in ["SCRAMSHA256", "SCRAMPBKDF2SHA256"]:
        auth_method = auth_method_cls(options.username, options.password,
                                      pid=options.pid, hostname=options.hostname)
    elif options.method == "SessionCookie":
        auth_method = auth_method_cls(options.username, options.session_cookie,
                                      pid=options.pid, hostname=options.hostname)
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
