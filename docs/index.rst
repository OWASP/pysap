.. pysap documentation master file, created by
   sphinx-quickstart on Mon Nov 30 19:17:45 2015.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

pysap - Python library for crafting SAP's network protocols packets
===================================================================

Version v\ |release| (:ref:`installation`)


Overview
--------

`SAP Netweaver <https://www.sap.com/platform/netweaver/index.epx>`_ and
`SAP HANA <https://www.sap.com/products/hana.html>`_ are technology platforms for
building and integrating SAP business applications. Communication between components
uses different network protocols and some services and tools make use of custom file
formats as well. While some of them are standard and well-known protocols, others
are proprietaries and public information is not available.

`pysap <https://www.coresecurity.com/corelabs-research/open-source-tools/pysap>`_
is an open source Python library that provides modules for crafting and sending packets
using SAP's NI, Diag, Enqueue, Router, Message Server, SNC and IGS protocols. In addition,
support for creating and parsing different proprietary file formats is included. The
modules are built on top of `Scapy <http://www.secdev.org/projects/scapy/>`_ and are
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


Content
=======

.. toctree::
   :maxdepth: 3

   user/index
   protocols/index
   fileformats/index
   examples/index
   api/index
   dev/index

.. examples/examples


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
