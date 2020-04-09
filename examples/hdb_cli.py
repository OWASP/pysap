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
from scapy.packet import Raw
from scapy.config import conf
from scapy.supersocket import StreamSocket
# Custom imports
import pysap
from pysap.SAPHDB import (SAPHDB, SAPHDBInitializationRequest, SAPHDBInitializationReply, SAPHDBPart, SAPHDBSegment,
                          SAPHDBPartAuthentication, SAPHDBPartAuthenticationField, SAPHDBConnection)


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
    parser.add_option_group(target)

    misc = OptionGroup(parser, "Misc options")
    misc.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False,
                    help="Verbose output [%default]")
    parser.add_option_group(misc)

    (options, _) = parser.parse_args()

    if not options.remote_host:
        parser.error("Remote host is required")

    return options


# Main function
def main():
    options = parse_options()

    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)

    # Initiate the connection
    hdb = SAPHDBConnection(options.remote_host,
                           options.remote_port,
                           options.route_string)
    print("[*] Connected to HANA database %s:%d" % (options.remote_host, options.remote_port))

    # Send Initialization Request packet
    p = SAPHDBInitializationRequest()
    logging.debug("[*] Sending init request:")
    hdb._connection.send(p)
    response = SAPHDBInitializationReply(str(hdb._connection.recv(8)))

    logging.debug("[*] Received init reply:")
    logging.debug(response.summary())

    # Manually craft a JWT
    import jwt
    from base64 import b64encode
    signed_jwt = ".".join([b64encode('{"alg":"RS256"}'),
                           b64encode('{"iss":"https://jwtprovider/"}'),
                           b64encode('Signature')])

    # Craft a JWT using jwt
    key = open('JWT/JWT-RS256-2048.key').read()
    claim = {"iss": "https://jwtprovider/"}
    signed_jwt = jwt.encode(claim, key, algorithm='RS256')
    print(signed_jwt)

    # Send authentication packet
    auth_fields = SAPHDBPartAuthentication(fields=[SAPHDBPartAuthenticationField(value="MARTIN"),
                                                   #SAPHDBPartAuthenticationField(value="SCRAMMD5"),
                                                   #SAPHDBPartAuthenticationField(value="A" * 64),
                                                   #SAPHDBPartAuthenticationField(value="SCRAMPBKDF2SHA256"),
                                                   #SAPHDBPartAuthenticationField(value="A" * 64),
                                                   #SAPHDBPartAuthenticationField(value="SCRAMSHA256"),
                                                   #SAPHDBPartAuthenticationField(value="A" * 64),
                                                   SAPHDBPartAuthenticationField(value="JWT"),
                                                   SAPHDBPartAuthenticationField(value=signed_jwt),
                                                   ])
    auth_part = SAPHDBPart(partkind=33, argumentcount=1, buffer=auth_fields)
    auth_segm = SAPHDBSegment(messagetype=65, parts=[auth_part])
    auth_pkt = SAPHDB(segments=[auth_segm])
    auth_pkt.show2()
    hdb._connection.send(auth_pkt)

    response = hdb._connection.recv()
    response.show()


if __name__ == "__main__":
    main()
