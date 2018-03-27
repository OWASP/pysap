#!/usr/bin/env python
# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# Copyright (C) 2012-2018 by Martin Gallo, Core Security
#
# Example script by Yvan Genuer
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
from optparse import OptionParser, OptionGroup
# External imports
from scapy.config import conf
# Custom imports
import pysap
from pysap.SAPIGS import SAPIGS
from pysap.SAPRouter import SAPRoutedStreamSocket

# Set the verbosity to 0
conf.verb = 0


# Command line options parser
def parse_options():

    description = "This example script convert provided jpg file to png 100x100 file " \
                  "using IGS interpreter IMGCONV through HTTP listener."

    epilog = "pysap %(version)s - %(url)s - %(repo)s" % {"version": pysap.__version__,
                                                         "url": pysap.__url__,
                                                         "repo": pysap.__repo__}

    usage = "Usage: %prog [options] -d <remote host> -i <input image>"

    parser = OptionParser(usage=usage, description=description, epilog=epilog)

    target = OptionGroup(parser, "Target")
    target.add_option("-d", "--remote-host", dest="remote_host",
                      help="Remote host")
    target.add_option("-p", "--remote-port", dest="remote_port", type="int", default=40080,
                      help="Remote port [%default]")
    target.add_option("--route-string", dest="route_string",
                      help="Route string for connecting through a SAP Router")
    parser.add_option_group(target)

    misc = OptionGroup(parser, "Misc options")
    misc.add_option("-i", "--image", dest="input_image", metavar="FILE", default="poc.jpg",
                    help="Image to convert [%default]")
    misc.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False,
                    help="Verbose output [%default]")
    parser.add_option_group(misc)

    (options, _) = parser.parse_args()

    if not (options.remote_host or options.route_string):
        parser.error("Remote host or route string is required")

    return options


# Main function
def main():
    options = parse_options()

    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)

    # Open image to convert
    try:
        with open(options.input_image, "rb") as f:
            image = f.read()
    except IOError:
        print("Error reading image file !")
        exit(0)

    print("[*] Testing IGS IMGCONV on http://%s:%d" % (options.remote_host,
                                                       options.remote_port))

    # Initiate the connection
    conn = SAPRoutedStreamSocket.get_nisocket(options.remote_host,
                                              options.remote_port,
                                              options.route_string,
                                              talk_mode=1)

    # XML file request
    # JPEG to PNG size 100x100
    xml = '''<?xml version="1.0" encoding="UTF-8"?>
    <IMAGE>
      <WIDTH>100</WIDTH>
      <HEIGTH>100</HEIGTH>
      <INPUT>image/jpeg</INPUT>
      <OUTPUT>image/png</OUTPUT>
    </IMAGE>
    '''

    # build http packet
    files = {"xml": ("xml", xml), "img": ("img", image)}
    p = SAPIGS.http(options.remote_host, options.remote_port, 'IMGCONV', files)

    # Send request
    print("[*] Send packet to IGS...")
    conn.send(p)
    print("[*] Response :")
    response = conn.recv(1024)
    response.show()

    # Extract picture url from response
    print("[*] Generated file(s) :")
    for url in str(response).split('href='):
        if "output" in url:
            print("http://%s:%d%s" % (options.remote_host,
                                      options.remote_port,
                                      url.split('"')[1]))


if __name__ == "__main__":
    main()
