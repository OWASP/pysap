
.. User guide frontend

User guide
==========

The following parts of the documentation contains some background information about
`pysap <https://www.secureauth.com/labs/open-source-tools/pysap>`_, as well as some
step-by-step instructions for installing, configuring and using pysap.


Projects using pysap
--------------------

The following projects, tools and repositories are known to be using pysap:

* `HoneySAP <https://github.com/SecureAuthCorp/HoneySAP>`_: HoneySAP is a
  low-interaction research-focused honeypot specific for SAP services. HoneySAP uses
  pysap as a library in order to craft and parse different protocol network packets.

* `SAP dissection plug-in for Wireshark <https://github.com/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark>`_:
  This Wireshark plugin provides dissection of SAP's ``NI``, Message Server,
  ``Router``, ``Diag``, ``Enqueue``, ``IGS``, ``SNC`` and ``HDB`` protocols. The Wireshark
  plug-in makes use of pysap in order to craft packets used during unit tests.

* `SAP Message Server research <https://github.com/gelim/sap_ms>`_: Exploit proof of
  concept code for two attacks against the Message Server service:

  * Logon Group (transparent) Hijacking
  * BeTrusted

* `SAP Gateway RCE exploit PoCs <https://github.com/chipik/SAP_GW_RCE_exploit>`_:
  Exploit proof of concept code for ACL misconfigurations in the SAP Gateway that
  leads to a Remote Command Execution (RCE).

* `John the Ripper's pse2john script <https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/run/pse2john.py>`_:
  Script to export PSE's encryption PIN into a format that can be cracked with
  John the Ripper.


.. _installation:

Installation
------------

This section of the documentation covers the installation process of pysap.


Installation with pip
~~~~~~~~~~~~~~~~~~~~~

Installing pysap is simple with `pip <https://pip.pypa.io/>`_, just run the
following command on a terminal::

    $ pip install pysap

Some example scripts has additional required libraries:

- ``tabulate``
- ``netaddr``
- ``cryptography``
- ``requests``
- `wxPython <https://www.wxpython.org/>`_
- `fau_timer <https://github.com/seecurity/mona-timing-lib>`_

Some of those extra libraries can be installed with `pip`_ running the following
command::

    $ pip install pysap[examples]


Manual installation
~~~~~~~~~~~~~~~~~~~

The tool relays on the `Scapy <https://scapy.net/>`_ library for crafting
packets. To install the required libraries use::

    $ pip install -r requirements.txt

Once you have downloaded pysap's sources, you can install it easily using
the Python's ``setuptools`` script provided:

1) ``python setup.py test``

2) ``python setup.py install``


Scapy installation
~~~~~~~~~~~~~~~~~~

- For installing `Scapy`_, see the official `installation documentation <https://scapy.readthedocs.io/en/latest/installation.html>`_ for each platform:

  - `Linux <https://scapy.readthedocs.io/en/latest/installation.html#installing-scapy-v2-x>`_.
  - `macOS <http://scapy.readthedocs.io/en/latest/installation.html#mac-os-x>`_.
  - `Windows <https://scapy.readthedocs.io/en/latest/installation.html#windows>`_.


References
----------

Additional information about the protocols and the research can be found at different publications:

* `Uncovering SAP vulnerabilities: reversing and breaking the Diag protocol <https://www.coresecurity.com/corelabs-research/publications/uncovering-sap-vulnerabilities-reversing-and-breaking-diag-protocol>`_

* `SAP’s Network Protocols Revisited <https://www.coresecurity.com/corelabs-research/publications/sap-network-protocols-revisited>`_

* `HoneySAP: Who really wants your money <https://www.coresecurity.com/corelabs-research/publications/honeysap-who-really-wants-your-money>`_

* `Deep-dive into SAP archive file formats <https://www.coresecurity.com/corelabs-research/publications/deep-dive-sap-archive-file-formats>`_

* `Intercepting SAP SNC-protected traffic <https://www.coresecurity.com/publication/intercepting-sap-snc-protected-traffic>`_

* `SAPCAR Heap Buffer Overflow: From crash to exploit <https://www.coresecurity.com/blog/sapcar-heap-buffer-overflow-crash-exploit>`_

* `Hunting crypto secrets in SAP systems <https://www.coresecurity.com/publication/hunting-crypto-secrets-sap-systems>`_

* `Revisiting the Old and Looking at New Potential SAP Vulnerabilities <https://www.secureauth.com/blog/revisiting-old-and-looking-new-potential-sap-vulnerabilities>`_

* Exploring the SAP HANA SQL Command Network Protocol Blog post series:

  * `Protocol Basics and Authentication <https://www.secureauth.com/blog/exploring-sap-hana-sql-command-network-protocol-protocol-basics-and-authentication/>`_

  * `Password-based Authentication and TLS <https://www.secureauth.com/blog/exploring-sap-hana-sql-command-network-protocol-password-based-authentication-and-tls/>`_

  * `Federated Authentication <https://www.secureauth.com/blog/exploring-the-sap-hana-sql-command-network-protocol-federated-authentication/>`_

And advisories:

* `SAP Netweaver Dispatcher Multiple Vulnerabilities <https://www.coresecurity.com/content/sap-netweaver-dispatcher-multiple-vulnerabilities>`_

* `SAP Netweaver Message Server Multiple Vulnerabilities <https://www.coresecurity.com/content/SAP-netweaver-msg-srv-multiple-vulnerabilities>`_

* `SAP Router Password Timing Attack <https://www.coresecurity.com/advisories/sap-router-password-timing-attack>`_

* `SAP Netweaver Enqueue Server Trace Pattern Denial of Service Vulnerability <https://www.coresecurity.com/advisories/sap-netweaver-enqueue-server-trace-pattern-denial-service-vulnerability>`_

* `SAP LZC LZH Compression Multiple Vulnerabilities <https://www.coresecurity.com/advisories/sap-lzc-lzh-compression-multiple-vulnerabilities>`_

* `SAP Download Manager Password Weak Encryption <https://www.coresecurity.com/advisories/sap-download-manager-password-weak-encryption>`_

* `SAP CAR Multiple Vulnerabilities <https://www.coresecurity.com/advisories/sap-car-multiple-vulnerabilities>`_

* `SAP SAPCAR Heap Based Buffer Overflow Vulnerability <https://www.coresecurity.com/advisories/sap-sapcar-heap-based-buffer-overflow-vulnerability>`_

* `SAP Note Assistant Insecure Handling of SAP Notes Signature Vulnerability <https://www.coresecurity.com/advisories/sap-note-assistant-insecure-handling-sap-notes-signature-vulnerability>`_

* `SAP HANA SAML Assertion Improper Validation Vulnerability <https://www.secureauth.com/advisories/sap-hana-saml-assertion-improper-validation-authentication/>`_

  * `Associated Blog Post SecureAuth uncovers SAML validation weakness in SAP HANA <https://www.secureauth.com/blog/secureauth-uncovers-saml-validation-weakness-in-sap-hana/>`_

Initial research about the SAP CAR file format was performed by Martin Gallo and published in `Deep-dive into SAP archive file formats <https://www.coresecurity.com/corelabs-research/publications/deep-dive-sap-archive-file-formats>`_
at the `Troopers 2016 Security Conference <https://www.troopers.de/troopers16/agenda/>`_. Additional research was
performed by `Hans-Christian Esperer <https://github.com/hce>`_ and published in the
`Hascar <https://github.com/VirtualForgeGmbH/hascar>`_ tool.

Documentation on the SAP `SAR <https://www.iana.org/assignments/media-types/application/vnd.sar>`_ archive file format
is available in SAP's `Virus Scan Interface (NW-VSI) <https://archive.sap.com/documents/docs/DOC-7838>`_
specification document. An example implementation can be also found in the `Virus Scan Adapter SDK`, which is
available upon request.

Initial research about the ``IGS`` protocol was performed by Yvan Genuer and published in `SAP IGS : The 'vulnerable' forgotten component <https://www.troopers.de/troopers18/agenda/3r38lr/>`_.

Additional research about the Message Server (``MS``) and Remote Function Call (``RFC``) protocols was performed by
Dmitry Chastuhin and Mathieu Geli and published in `(SAP) Gateway to Heaven <https://github.com/comaeio/OPCDE/tree/master/2019/Emirates/(SAP)%20Gateway%20to%20Heaven%20-%20Dmitry%20Chastuhin%2C%20Mathieu%20Geli>`_.

The specifications of the ``HDB`` protocol are published in the `SAP HANA SQL Command Network Protocol Reference <https://help.sap.com/viewer/7e4aba181371442d9e4395e7ff71b777/2.0.03/en-US>`_
guide.
