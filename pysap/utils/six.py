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

# All custom general purpose Python 2/3 compatibility should go here

from __future__ import absolute_import

import six


def unicode(string):
    """
    Convert given string to unicode string
    :param string: String to convert
    :type string: bytes | str | unicode
    :return: six.text_type
    """
    string_type = type(string)
    if string_type == six.binary_type:
        return string.decode()
    elif string_type == six.text_type:
        return string
    raise ValueError("Expected bytes or str, got {}".format(string_type))
