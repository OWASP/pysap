pysap - Python library for crafting SAP's network protocols packets
===================================================================

[![Build and test pysap](https://github.com/OWASP/pysap/actions/workflows/build_and_test.yml/badge.svg)](https://github.com/OWASP/pysap/actions/workflows/build_and_test.yml)
[![PyPI Version](https://img.shields.io/pypi/v/pysap?logo=pypi)](https://pypi.org/project/pysap/)
[![Read the Docs](https://img.shields.io/readthedocs/pysap?logo=readthedocs)](https://pysap.readthedocs.io/)
[![Discord](https://img.shields.io/discord/710814201358319676?logo=discord&label=Discord)](https://discord.com/channels/710814201358319676/1155823687329660948)

Version 0.2.1.dev0 (in dev)

Overview
--------

[SAP Netweaver](https://www.sap.com/platform/netweaver/index.epx) and
[SAP HANA](https://www.sap.com/products/hana.html) are technology platforms for
building and integrating SAP business applications. Communication between components
uses different network protocols and some services and tools make use of custom file
formats as well. While some of them are standard and well-known protocols, others
are proprietaries and public information is generally not available.

[pysap](https://github.com/OWASP/pysap) is an open source Python library that provides
modules for crafting and sending packets using SAP's `NI`, `Diag`, `Enqueue`, `Router`,
`MS`, `SNC`, `IGS`, `RFC`, `NWRFC` and `HDB` protocols. In addition, support for creating and
parsing different proprietary file formats is included. The modules are built on top of
[Scapy](https://scapy.net/) and are based on information acquired at researching the
different protocols, file formats and services.


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
    * SAP Netweaver RFC SDK (`NWRFC`)
    * SAP HANA SQL Command Network (`HDB`)

* Client interfaces for handling the following file formats:

    * SAP [`SAR` archive files](https://www.iana.org/assignments/media-types/application/vnd.sar)
    * SAP Personal Security Environment (`PSE`) files
    * SAP SSO Credential (`Credv2`) files
    * SAP Secure Storage in File System (`SSFS`) files

* Library implementing SAP's `LZH` and `LZC` compression algorithms.

* Automatic compression/decompression of payloads with SAP's algorithms.

* Client, proxy and server classes implemented for some of the protocols.

* Command-line tools for offline work with SAP archive, PSE, Credv2, and SSFS
  files.

* Example scripts to illustrate the use of the different modules and protocols.


Installation
------------

To install pysap simply run:

    $ python3 -m pip install pysap

pysap requires Python 3.10 or newer.


Roadmap
-------

### Python 3 project

After a long time and thanks to a great community effort, the project has been just ported to Python 3.
The project now runs on Python 3, but bugs are still expected to raise as more functionality is tested
and evaluated. Testing support by the community is highly appreciated.

In addition, some of the recent Python 3 capabilities are not yet fully adapted, such as static typing,
native concurrency and others.

### Further efforts

  * Bug fixing all over the place
  * Increment unit test coverage
  * Incorporate static typing and other Python 3.10+ features
  * Protocol completeness (e.g. `NWRFC`, `RFC`, `Diag`, `HDB`)
  * Create more stable tools mimicking SAP' native ones (e.g. `genpse`, `dpmon`, `gwmon`)
  * Update depending OWASP projects such as `honeysap` & SAP attack surface monitoring



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
  * Waseem Ajrab ([@default-eshu](https://github.com/default-eshu))
  * [@randomstr1ng](https://github.com/randomstr1ng)
  * Tyrox ([@DominikHolzapfel](https://github.com/DominikHolzapfel))
  * Hackbarth

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
