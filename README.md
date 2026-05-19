pysap - Python library for crafting SAP's network protocols packets
===================================================================

[![Build and test pysap](https://github.com/OWASP/pysap/workflows/Build%20and%20test%20pysap/badge.svg)](https://github.com/OWASP/pysap/actions?query=workflow%3A%22Build+and+test+pysap%22)
[![Latest Version](https://img.shields.io/pypi/v/pysap.svg)](https://pypi.python.org/pypi/pysap/)
[![Documentation Status](http://readthedocs.org/projects/pysap/badge/?version=latest)](http://pysap.readthedocs.io/en/latest/?badge=latest)

Version 0.2.0.dev0 (in development)

The master branch runs on Python 3.

Overview
--------

[SAP Netweaver](https://www.sap.com/platform/netweaver/index.epx) and
[SAP HANA](https://www.sap.com/products/hana.html) are technology platforms for
building and integrating SAP business applications. Communication between components
uses different network protocols and some services and tools make use of custom file
formats as well. While some of them are standard and well-known protocols, others
are proprietaries and public information is generally not available.

[pysap](https://www.secureauth.com/labs/open-source-tools/pysap)
is an open source Python library that provides modules for crafting and sending packets
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

    $ python3 -m pip install pysap

pysap requires Python 3.10 or newer.


Roadmap
-------

### Python 3 project

As time passed, and Python 2 lost relevance, we decided to start a new effort to complete the project and move it to Python 3 only. The main reason is to avoid the introduction of backwards compatibility libraries that add complexity to the code and are not relevant in the current state of the Python project.

This project is actively being worked on by the OWASP CBAS project as part of the [master branch](https://github.com/OWASP/pysap/tree/master). The project now runs on Python 3. Testing support by the community is highly appreciated

### Further efforts

  * Update documentation and PyPi release
  * [Replace pysapcompress old C-code](https://github.com/OWASP/pysap/issues/73)
  * [Port SAP Credv2 file format](https://github.com/OWASP/pysap/issues/64)
  * Update depending OWASP projects such as honeysap & SAP attack surface monitoring



Documentation
-------------

Documentation is available at [Read the Docs](https://pysap.readthedocs.io/en/latest/).

The development documentation includes a short testing guide at
[docs/dev/testing.rst](docs/dev/testing.rst). It describes the unit and
integration suites, the test harness, and the recommended `tox` and `pytest`
commands.


License
-------

This library is distributed under the GPLv2 license. Check the [COPYING](COPYING)
file for more details.


Authors
-------

he tool was initially designed and developed by Martin Gallo wile working at
[SecureAuth's Innovation Labs](https://www.secureauth.com/labs/) team, with the
help of many contributors. The code was then contributed by SecureAuth to the
OWASP CBAS Project in October 2022.

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
  * [@codeHorse87](https://github.com/codeHorse87)
  * Albert Zedlitz
  * [@cclauss](https://github.com/cclauss)
  * [@okuuva](https://github.com/okuuva)
  * Dmitry Chastuhin ([@_chipik](https://twitter.com/_chipik))
  * fabhap
  * Andreas Hornig
  * Jennifer Hornig ([@gloomicious](https://github.com/gloomicious))
  * RedRays Security Team
  * Vincent Berg
  * WaseemAjrab ([@default-eshu](https://github.com/default-eshu))

Disclaimer
----------

The spirit of this Open Source initiative is to help security researchers,
and the community, speed up research and educational activities related to
the implementation of networking protocols and stacks.

The information in this repository is for research and educational purposes
only and is not intended to be used in production environments and/or as part
of commercial products.

If you desire to use this tool or some part of it for your own uses, we
recommend applying proper security development life cycle and secure coding
practices, as well as generate and track the respective indicators of
compromise according to your needs.


Contact Us
----------

Whether you want to report a bug, send a patch, or give some suggestions
on this package, drop a few lines to
[OWASP CBAS' project leaders](https://owasp.org/www-project-core-business-application-security/#leaders).

For security-related questions check our [security policy](SECURITY.md).
