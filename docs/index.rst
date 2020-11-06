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
are proprietaries and public information is generally not available.

`pysap <https://www.secureauth.com/labs/open-source-tools/pysap>`_
is an open source Python 2 library that provides modules for crafting and sending packets
using SAP's ``NI``, ``Diag``, ``Enqueue``, ``Router``, ``MS``, ``SNC``, ``IGS``, ``RFC``
and ``HDB`` protocols. In addition, support for creating and parsing different proprietary
file formats is included. The modules are built on top of `Scapy <https://scapy.net/>`_ and
are based on information acquired at researching the different protocols, file formats
and services.


Features
--------

* Dissection and crafting of the following network protocols:

    * SAP Network Interface (``NI``)
    * SAP ``Diag``
    * SAP ``Enqueue``
    * SAP ``Router``
    * SAP Message Server (``MS``)
    * SAP Secure Network Connection (``SNC``)
    * SAP Internet Graphic Server (``IGS``)
    * SAP Remote Function Call (``RFC``)
    * SAP HANA SQL Command Network (``HDB``)

* Client interfaces for handling the following file formats:

    * SAP ``SAR`` archive files
    * SAP Personal Security Environment (``PSE``) files
    * SAP SSO Credential (``Credv2``) files

* Library implementing SAP's ``LZH`` and ``LZC`` compression algorithms.

* Automatic compression/decompression of payloads with SAP's algorithms.

* Client, proxy and server classes implemented for some of the protocols.

* Example scripts to illustrate the use of the different modules and protocols.


User guide
----------

.. toctree::
   :maxdepth: 3

   user/index
   protocols/index
   fileformats/index
   examples/index

Development guide
-----------------

.. toctree::
   :maxdepth: 3

   dev/index
   api/index


Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
