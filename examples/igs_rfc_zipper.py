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
from pysap.SAPIGS import SAPIGS, SAPIGSTable
from pysap.SAPRouter import SAPRoutedStreamSocket


# Set the verbosity to 0
conf.verb = 0


# Command line options parser
def parse_options():

    description = "This example script send provided file to IGS ZIPPER interpreter " \
                  "using RFC Listener "

    epilog = "pysap %(version)s - %(url)s - %(repo)s" % {"version": pysap.__version__,
                                                         "url": pysap.__url__,
                                                         "repo": pysap.__repo__}

    usage = "Usage: %prog [options] -d <remote host>"

    parser = OptionParser(usage=usage, description=description, epilog=epilog)

    target = OptionGroup(parser, "Target")
    target.add_option("-d", "--remote-host", dest="remote_host",
                      help="Remote host")
    target.add_option("-p", "--remote-port", dest="remote_port", type="int", default=40000,
                      help="Remote port [%default]")
    target.add_option("--route-string", dest="route_string",
                      help="Route string for connecting through a SAP Router")
    parser.add_option_group(target)

    param = OptionGroup(parser, "Parameters")
    param.add_option("-i", dest="file_input", default='poc.txt', metavar="FILE",
                     help="File to zip [%default]")
    param.add_option("-a", dest="file_path", default='',
                     help="Path in zip file [%default]")
    parser.add_option_group(param)

    misc = OptionGroup(parser, "Misc options")
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

    print("[*] Testing IGS ZIPPER interpreter on %s:%d" % (options.remote_host,
                                                           options.remote_port))
    # open input file
    try:
        with open(options.file_input, 'rb') as f:
            file_input_content=f.read()
    except IOError:
        print("[!] Error reading %s file." % options.file_input)
        exit(2)

    # Initiate the connection
    conn = SAPRoutedStreamSocket.get_nisocket(options.remote_host,
                                              options.remote_port,
                                              options.route_string,
                                              base_cls=SAPIGS)

    # the xml request for zipper interpreter 
    xml = '<?xml version="1.0"?><REQUEST><COMPRESS type="zip"><FILES>'
    xml += '<FILE name="{}" '.format(options.file_input)
    xml += 'path="{}" '.format(options.file_path)
    xml += 'size="{}"/>'.format(len(file_input_content))
    xml += '</FILES></COMPRESS></REQUEST>'

    # create tables descriptions
    # table with xml content
    table_xml = SAPIGSTable.add_entry('XMLDESC', 1, len(xml), 1,
                                      'XMLDESC', len(xml)
                                      )
    # table with file content
    table_file = SAPIGSTable.add_entry('FILE1', 1, len(file_input_content), 1,
                                       'FILE1', len(file_input_content)
                                       )

    # get the futur offset where table entries begin
    offset = (len(table_xml) + len(table_file))

    # filling tables 
    content_xml = xml
    content_file = file_input_content

    # total size of packet
    # total_size need to be a multiple of 1024
    total_size = offset + 244 # 244 IGS header size
    total_size += 1023
    total_size -= (total_size % 1024)

    # Put all together
    p = SAPIGS(function='ZIPPER', listener='L', offset_content=str(offset), packet_size=str(total_size))
    p = p / table_xml / table_file / content_xml / content_file

    # Send the IGS packet
    print("[*] Send %s to ZIPPER interpreter..." % options.file_input)
    conn.send(p)
    print("[*] File sent.")


if __name__ == "__main__":
    main()
