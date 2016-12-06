pysap - Python library for crafting SAP's network protocols packets
===================================================================

[![Build Status](https://travis-ci.org/CoreSecurity/pysap.svg?branch=master)](https://travis-ci.org/CoreSecurity/pysap)
[![Build status](https://ci.appveyor.com/api/projects/status/v9ys2sxl4rbehb98?svg=true)](https://ci.appveyor.com/project/martingalloar/pysap)
[![Code Health](https://landscape.io/github/CoreSecurity/pysap/master/landscape.svg)](https://landscape.io/github/CoreSecurity/pysap/master)
[![Code Issues](http://www.quantifiedcode.com/api/v1/project/53b997e2c9054c5ab44782614c572358/badge.svg)](http://www.quantifiedcode.com/app/project/53b997e2c9054c5ab44782614c572358)
[![Latest Version](https://img.shields.io/pypi/v/pysap.svg)](https://pypi.python.org/pypi/pysap/)
[![Documentation Status](http://readthedocs.org/projects/pysap/badge/?version=latest)](http://pysap.readthedocs.io/en/latest/?badge=latest)

Copyright (C) 2012-2016 by Martin Gallo, Core Security

Version 0.1.12.dev0 (XXX 2016)


Overview
--------

[SAP Netweaver](https://www.sap.com/platform/netweaver/index.epx) is a 
technology platform for building and integrating SAP business applications.
Communication between components uses different network protocols. While
some of them are standard and well-known protocols, others are proprietaries
and public information is not available.

[pysap](https://www.coresecurity.com/corelabs-research/open-source-tools/pysap)
is a Python library that provides modules for crafting and sending packets
using SAP's NI, Message Server, Router, RFC, SNC, Enqueue and Diag protocols.
The modules are build on top of [Scapy](http://www.secdev.org/projects/scapy/)
and are based on information acquired at researching the different protocols
and services.


Features
--------

* Dissection and crafting of the following network protocols:

    * SAP Network Interface (NI)
    * SAP Diag
    * SAP Enqueue
    * SAP Router
    * SAP Message Server (MS)
    * SAP SNC

* Client interfaces for handling the following file formats:

    * SAP SAR archive files

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

The library was designed and developed by Martin Gallo from the Security
Consulting Services team of Core Security.

### Contributors ###

Contributions made by:

  * Florian Grunow
  * Scott Walsh ([@invisiblethreat](https://github.com/invisiblethreat))
  * Joris van de Vis ([@jvis](https://twitter.com/jvis))
  * Victor Portal Gonzalez 
  * Dmitry Yudin ([@ret5et](https://github.com/ret5et))
  * Hans-Christian Esperer ([@hce](https://github.com/hce))
  * Vahagn Vardanyan ([@vah13](https://github.com/vah13))


Contact
-------

Whether you want to report a bug or give some suggestions on this package, drop
us a few lines at `oss@coresecurity.com` or contact the author email 
`mgallo@coresecurity.com`.
