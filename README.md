pysap - Python library for crafting SAP's network protocols packets
===================================================================

[![Build and test pysap](https://github.com/SecureAuthCorp/pysap/workflows/Build%20and%20test%20pysap/badge.svg)](https://github.com/SecureAuthCorp/pysap/actions?query=workflow%3A%22Build+and+test+pysap%22)
[![Latest Version](https://img.shields.io/pypi/v/pysap.svg)](https://pypi.python.org/pypi/pysap/)
[![Documentation Status](http://readthedocs.org/projects/pysap/badge/?version=latest)](http://pysap.readthedocs.io/en/latest/?badge=latest)

SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.

Version 0.1.19 (April 2021)


Overview
--------

[SAP Netweaver](https://www.sap.com/platform/netweaver/index.epx) and
[SAP HANA](https://www.sap.com/products/hana.html) are technology platforms for
building and integrating SAP business applications. Communication between components
uses different network protocols and some services and tools make use of custom file
formats as well. While some of them are standard and well-known protocols, others
are proprietaries and public information is generally not available.

[pysap](https://www.secureauth.com/labs/open-source-tools/pysap)
is an open source Python 2 library that provides modules for crafting and sending packets
using SAP's `NI`, `Diag`, `Enqueue`, `Router`, `MS`, `SNC`, `IGS`, `RFC` and `HDB`
protocols. In addition, support for creating and parsing different proprietary file
formats is included. The modules are built on top of [Scapy](https://scapy.net/) and are
based on information acquired at researching the different protocols, file formats
and services.


Features
--------

* Dissection and crafting of the following network protocols:

    * SAP Network Interface (`NI`)
    * SAP `Diag`
    * SAP `Enqueue`
    * SAP `Router`
    * SAP Message Server (`MS`)
    * SAP Secure Network Connection (`SNC`)
    * SAP Internet Graphic Server (`IGS`)
    * SAP Remote Function Call (`RFC`)
    * SAP HANA SQL Command Network (`HDB`)

* Client interfaces for handling the following file formats:

    * SAP [`SAR` archive files](https://www.iana.org/assignments/media-types/application/vnd.sar)
    * SAP Personal Security Environment (`PSE`) files
    * SAP SSO Credential (`Credv2`) files
    * SAP Secure Storage in File System (`SSFS`) files

* Library implementing SAP's `LZH` and `LZC` compression algorithms.

* Automatic compression/decompression of payloads with SAP's algorithms.

* Client, proxy and server classes implemented for some of the protocols.

* Example scripts to illustrate the use of the different modules and protocols.


Installation
------------

To install pysap simply run:

    $ pip install pysap

pysap is compatible and tested with Python 2.7. A Python 2/3 compatible version
is [in the workings](https://github.com/SecureAuthCorp/pysap/tree/python2-3) but
it's [not finalized yet](https://github.com/SecureAuthCorp/pysap/projects/1).

Documentation
-------------

Documentation is available at [Read the Docs](https://pysap.readthedocs.io/en/latest/).


License
-------

This library is distributed under the GPLv2 license. Check the `COPYING` file for
more details.


Disclaimer
----------

The spirit of this open source initiative is hopefully to help the community to
alleviate some of the hindrances associated with the implementation of
networking protocols and stacks, aiming at speeding up research and educational
activities. By no means this package is meant to be used in production
environments / commercial products. If so, we would advise to include it into a
proper SDLC process.


Authors
-------

The library was designed and developed by Martin Gallo from [SecureAuth's Innovation
Labs](https://www.secureauth.com/labs/) team, with the help of a large number of
contributors.

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
  * [@cclauss](https://github.com/cclauss)
  * [@okuuva](https://github.com/okuuva)
  * Dmitry Chastuhin ([@_chipik](https://twitter.com/_chipik))
  * fabhap
  * Andreas Hornig
  * Jennifer Hornig ([@gloomicious](https://github.com/gloomicious))


Contact
-------

Whether you want to report a bug or give some suggestions on this package, drop
us a few lines at `oss@secureauth.com` or contact the author email
`mgallo@secureauth.com`.
