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
from binascii import unhexlify
from os import path


def data_filename(filename):
    return path.join(path.dirname(__file__), 'data', filename)


def read_data_file(filename, unhex=True):
    filename = data_filename(filename)
    with open(filename, 'rb') as f:
        data = f.read()

    data = data.replace(b'\n', b' ').replace(b' ', b'')
    if unhex:
        data = unhexlify(data)

    return data
