#!/usr/bin/env python
# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# Copyright (C) 2012-2016 by Martin Gallo, Core Security
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
from optparse import OptionParser




# Main function
def main():
    # Parse command line options
    description = \
    """This example script extract SAP's Download Manager stored passwords.
    """

    usage = "Usage: %prog [options] -f <config filename>"

    parser = OptionParser(usage=usage, description=description)

    parser.add_option("-f", "--filename", dest="filename", help="DLManager config filename", metavar="FILE")
    parser.add_option("-e", "--encrypted", dest="encrypted", help="If passwords are stored encrypted (version >= 2.1.140a)",
                      action="store_true")
    parser.add_option("-s", "--serial-number", dest="serial_number", help="The machine's BIOS serial number")
    parser.add_option("-r", "--retrieve-serial-number", dest="retrieve", help="If the script should try to retrieve the "
                      "serial number from the machine and use it for decryption", action="store_true")
    (options, args) = parser.parse_args()

    if not options.filename:
        parser.error("[-] DLManager config filename required !")

    if options.retrieve:
        print("[*] Trying to retrieve the machine's serial number")
        options.serial_number = retrieve_serial_number()
        options.encrypted = True
        print("[*] Retrieved serial number: %s" % options.serial_number)

    if options.encrypted and AES is None:
        parser.error("[-] pyCrypto library required to decrypt not found !")

    parse_config_file(options.filename, options.encrypted, options.serial_number)


if __name__ == "__main__":
    main()
