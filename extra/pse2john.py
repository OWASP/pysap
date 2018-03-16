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
import sys
from binascii import hexlify
# Custom imports
import pysap
from pysap.SAPPSE import (SAPPSEFile, PKCS12_ALGORITHM_PBE1_SHA_3DES_CBC)


def parse_pse(filename):
    with open(filename, "rb") as f:
        data = f.read()

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

    line = "{}:$pse${}${}${}${}${}${}${}${}:::::\n".format(
        filename, pbe_algo, iterations, salt_size, salt, iv_size, iv, encrypted_pin_length, encrypted_pin,
    )

    sys.stdout.write(line)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <.pse file(s)>\n" % sys.argv[0])

    for i in range(1, len(sys.argv)):
        parse_pse(sys.argv[1])
