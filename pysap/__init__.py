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

"""
pysap
=====

[pysap](https://www.coresecurity.com/corelabs-research/open-source-tools/pysap)
is an open source Python library that provides modules for crafting and sending packets
using SAP's NI, Diag, Enqueue, Router, Message Server, SNC and IGS protocols. In addition,
support for creating and parsing different proprietary file formats is included. The
modules are built on top of [Scapy](http://www.secdev.org/projects/scapy/) and are
based on information acquired at researching the different protocols, file formats
and services.


Features
--------

* Dissection and crafting of the following network protocols:

    * SAP Network Interface (NI)
    * SAP Diag
    * SAP Enqueue
    * SAP Router
    * SAP Message Server (MS)
    * SAP Secure Network Connection (SNC)
    * SAP Internet Graphic Server (IGS)

* Client interfaces for handling the following file formats:

    * SAP SAR archive files
    * SAP PSE (Personal Security Environment) files
    * SAP SSO Credential (Credv2) files

* Library implementing SAP's LZH and LZC compression algorithms.

* Automatic compression/decompression of payloads with SAP's algorithms.

* Client, proxy and server classes implemented for some of the protocols.

* Example scripts to illustrate the use of the different modules and protocols.


:copyright: (c) 2012-2018 by Martin Gallo, Core Security.
:license: GNU General Public License v2 or later (GPLv2+).
"""

__title__ = 'pysap'
"""The title of the library"""

__version__ = '0.1.16'
"""The version of pysap"""

__url__ = "https://www.coresecurity.com/corelabs-research/open-source-tools/pysap"
"""The URL for pysap's homepage"""

__repo__ = "https://github.com/CoreSecurity/pysap"
"""The URL for pysap's repository"""

__license__ = "GNU General Public License v2 or later (GPLv2+)"
"""The license governing the use and distribution of pysap"""
