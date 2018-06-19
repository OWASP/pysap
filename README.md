pysap - Python library for crafting SAP's network protocols packets
===================================================================

[![Build Status](https://travis-ci.org/CoreSecurity/pysap.svg?branch=master)](https://travis-ci.org/CoreSecurity/pysap)
[![Build status](https://ci.appveyor.com/api/projects/status/189ohb2wsqjwgkbw?svg=true)](https://ci.appveyor.com/project/CoreSecurity/pysap)
[![Code Health](https://landscape.io/github/CoreSecurity/pysap/master/landscape.svg)](https://landscape.io/github/CoreSecurity/pysap/master)
[![Latest Version](https://img.shields.io/pypi/v/pysap.svg)](https://pypi.python.org/pypi/pysap/)
[![Documentation Status](http://readthedocs.org/projects/pysap/badge/?version=latest)](http://pysap.readthedocs.io/en/latest/?badge=latest)

Copyright (C) 2012-2018 by Martin Gallo, Core Security

Version 0.1.16 (June 2018)


Overview
--------

[SAP Netweaver](https://www.sap.com/platform/netweaver/index.epx) and
[SAP HANA](https://www.sap.com/products/hana.html) are technology platforms for
building and integrating SAP business applications. Communication between components
uses different network protocols and some services and tools make use of custom file
formats as well. While some of them are standard and well-known protocols, others
are proprietaries and public information is not available.

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


Installation
------------

To install pysap simply run:

    $ pip install pysap


Documentation
-------------

Documentation is available at [Read the Docs](https://pysap.readthedocs.io/en/latest/).


License
-------

This library is distributed under the GPLv2 license. Check the `COPYING` file for
more details.


Authors
-------

The library was designed and developed by Martin Gallo from Core Security's CoreLabs.

### Contributors ###

Contributions made by:

  * Florian Grunow ([@0x79](https://twitter.com/0x79))
  * Scott Walsh ([@invisiblethreat](https://github.com/invisiblethreat))
  * Joris van de Vis ([@jvis](https://twitter.com/jvis))
  * Victor Portal Gonzalez
  * Dmitry Yudin ([@ret5et](https://github.com/ret5et))
  * Hans-Christian Esperer ([@hce](https://github.com/hce))
  * Vahagn Vardanyan ([@vah13](https://github.com/vah13))
  * Mathieu Geli ([@gelim](https://github.com/gelim))
  * Yvan Genuer ([@iggy38](https://github.com/iggy38))
  * Malte Heinzelmann ([@hnzlmnn](https://github.com/hnzlmnn))
  * Albert Zedlitz


Contact
-------

Whether you want to report a bug or give some suggestions on this package, drop
us a few lines at `oss@coresecurity.com` or contact the author email
`mgallo@coresecurity.com`.
