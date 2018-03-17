#!/usr/bin/env python
# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# Copyright (C) 2012-2018 by Martin Gallo, Core Security
#
# Example script by Yvan Genuer.
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
import re
from optparse import OptionParser, OptionGroup
import logging
# External imports
from scapy.config import conf
# Custom imports
import pysap
from pysap.SAPRouter import SAPRoutedStreamSocket
from pysap.SAPMS import SAPMS, SAPMSAdmRecord

# Set the verbosity to 0
conf.verb = 0


# Command line options parser
def parse_options():

    description = "This example script is a subset of ms_dump_info.py." \
                  " For each parameter provide in file, it retrieve value and check the result." \
                  " Access of the internal Message Server port is required." \
                  " Due to the wide of parameters type in SAP System, it's not perfect, and false positive could exist."

    epilog = "pysap %(version)s - %(url)s - %(repo)s" % {"version": pysap.__version__,
                                                         "url": pysap.__url__,
                                                         "repo": pysap.__repo__}

    usage = "Usage: %prog [options] -d <remote host> -f <parameters_file>"

    parser = OptionParser(usage=usage, description=description, epilog=epilog)

    target = OptionGroup(parser, "Target")
    target.add_option("-d", "--remote-host", dest="remote_host",
                      help="Remote host")
    target.add_option("-p", "--remote-port", dest="remote_port", type="int", default=3900,
                      help="Remote port [%default]")
    target.add_option("--route-string", dest="route_string",
                      help="Route string for connecting through a SAP Router")
    parser.add_option_group(target)

    param = OptionGroup(parser, "Parameter")
    param.add_option("-f", "--parameter-file", dest="file_param", metavar="FILE",
                     help="parameters file (<SAP parameter>:<Check type>:<expected_value>)")
    parser.add_option_group(param)

    misc = OptionGroup(parser, "Misc options")
    misc.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False,
                    help="Verbose output [%default]")
    misc.add_option("-c", "--client", dest="client", default="pysap's-getparam",
                    help="Client name [%default]")
    parser.add_option_group(misc)

    (options, _) = parser.parse_args()

    if not (options.remote_host or options.route_string):
        parser.error("Remote host or route string is required")
    if not options.file_param:
        parser.error("Parameters file is required")

    return options


# Main
#------
def main():
    options = parse_options()
    
    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)
    
    # initiate the connection :
    print("[*] Initiate connection to message server %s:%d" % (options.remote_host, options.remote_port))
    try:
        conn = SAPRoutedStreamSocket.get_nisocket(options.remote_host,
                                                  options.remote_port,
                                                  options.route_string,
                                                  base_cls=SAPMS)
    except Exception as e:
        print(e)
        print ("Error during MS connection. Is internal ms port %d reachable ?" % options.remote_port)
    else:
        print ("[*] Connected. I check parameters...")
        client_string = options.client
        # Send MS_LOGIN_2 packet
        p = SAPMS(flag=0x00, iflag=0x08, toname=client_string, fromname=client_string)
        print("[*] Sending login packet:")
        response = conn.sr(p)[SAPMS]
        print("[*] Login OK, Server string: %s\n" % response.fromname)
        server_string = response.fromname

        try:
            with open(options.file_param) as list_param:
                for line in list_param.readlines():
                    line = line.strip()

                    # Check for comments or empty lines
                    if len(line) == 0 or line.startswith("#"):
                        continue

                    # Get parameters, check type and expected value
                    # param2c = the SAP parameter to check
                    # check_type = EQUAL, SUP, INF, REGEX, <none>
                    # value2c = the expect value for 'ok' status
                    (param2c, check_type, value2c) = line.split(':')
                    status = '[!]'

                    # create request
                    adm = SAPMSAdmRecord(opcode=0x1, parameter=param2c)
                    p = SAPMS(toname=server_string, fromname=client_string, version=4, flag=0x04, iflag=0x05,
                              adm_records=[adm])

                    # send request
                    respond = conn.sr(p)[SAPMS]
                    value = respond.adm_records[0].parameter.replace(respond.adm_records[0].parameter.split('=')[0] +
                                                                     '=', '')

                    # Verify if value match with expected value
                    if value == '':
                        value = 'NOT_EXIST'
                        status = '[ ]'
                    elif check_type == 'EQUAL':
                        if value.upper() == str(value2c).upper():
                            status = '[+]'
                    elif check_type == 'REGEX':
                        if re.match(value2c.upper(), value.upper()) and value2c != 'NOT_EXIST':
                            status = '[+]'
                    elif check_type == 'SUP':
                        if float(value) >= float(value2c):
                            status = '[+]'
                    elif check_type == 'INF':
                        if float(value) <= float(value2c):
                            status = '[+]'
                    else:
                            status = '[ ]'

                    # display result
                    print ("%s %s = %s" % (status, param2c, value))
                   
        except IOError:
            print("Error reading parameters file !")
            exit(0)
        except ValueError:
            print("Invalid parameters file format !")
            exit(0)


if __name__ == '__main__':
    main()
