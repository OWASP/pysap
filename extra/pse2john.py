#!/usr/bin/env python2
# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# The library was designed and developed by Martin Gallo from
# the SecureAuth's Innovation Labs team.
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
from os import path
from sys import stdout
from binascii import hexlify
from argparse import ArgumentParser
# Custom imports
import pysap
from pysap.SAPPSE import (SAPPSEFile, PKCS12_ALGORITHM_PBE1_SHA_3DES_CBC)


# Command line options parser
def parse_options():

    description = "This script can be used to parse PSE files and extract encrypted material and data in a format that" \
                  "John the Ripper or other cracking tools can use to look for the decryption PIN."

    usage = "%(prog)s <input_file>"

    parser = ArgumentParser(usage=usage, description=description, epilog=pysap.epilog)
    parser.add_argument("-o", "--output", help="Filename to write the output to [stdout]")

    options, args = parser.parse_known_args()

    return options, args


def parse_pse(filename):
    """Parses a PSE file and produces """
    with open(filename, "rb") as fp:
        data = fp.read()

    pse_file = SAPPSEFile(data)

    if pse_file.enc_cont.algorithm_identifier.alg_id == PKCS12_ALGORITHM_PBE1_SHA_3DES_CBC:
        pbe_algo = 1
        salt = hexlify(pse_file.enc_cont.algorithm_identifier.parameters.salt.val)
        salt_size = len(pse_file.enc_cont.algorithm_identifier.parameters.salt.val)
        iterations = pse_file.enc_cont.algorithm_identifier.parameters.iterations.val
        iv = ""
        iv_size = len(iv)
    else:
        raise Exception("Unsupported encryption algorithm")

    encrypted_pin = hexlify(pse_file.enc_cont.encrypted_pin.val)
    encrypted_pin_length = len(pse_file.enc_cont.encrypted_pin.val)

    return "{}:$pse${}${}${}${}${}${}${}${}:::::\n".format(
        path.basename(filename), pbe_algo, iterations, salt_size, salt, iv_size, iv,
        encrypted_pin_length, encrypted_pin)


if __name__ == "__main__":
    options, args = parse_options()

    # Select the output file to write
    if options.output:
        f = open(options.output, "w")
    else:
        f = stdout

    # Parse all the files and write output
    for i in range(0, len(args)):
        line = parse_pse(args[i])
        f.write(line)

    # Close the file descriptor
    if options.output:
        f.close()
