.. User guide frontend

User guide
==========

The following parts of the documentation contains some background information about pysap, as well as some
step-by-step instructions for installing, configuring and using pysap.


References
----------

Additional information about the protocols and the research can be found at different publications:

* `Uncovering SAP vulnerabilities: reversing and breaking the Diag protocol <https://www.coresecurity.com/corelabs-research/publications/uncovering-sap-vulnerabilities-reversing-and-breaking-diag-protocol-brucon2012>`_

* `SAP’s Network Protocols Revisited <https://www.coresecurity.com/corelabs-research/publications/sap-network-protocols-revisited>`_

* `HoneySAP: Who really wants your money <https://www.coresecurity.com/corelabs-research/publications/honeysap-who-really-wants-your-money>`_

* `Deep-dive into SAP archive file formats <https://www.coresecurity.com/corelabs-research/publications/deep-dive-sap-archive-file-formats>`_

And advisories:

* `SAP Netweaver Dispatcher Multiple Vulnerabilities <https://www.coresecurity.com/content/sap-netweaver-dispatcher-multiple-vulnerabilities>`_

* `SAP Netweaver Message Server Multiple Vulnerabilities <https://www.coresecurity.com/content/SAP-netweaver-msg-srv-multiple-vulnerabilities>`_

* `SAP Router Password Timing Attack <https://www.coresecurity.com/advisories/sap-router-password-timing-attack>`_

* `SAP Netweaver Enqueue Server Trace Pattern Denial of Service Vulnerability <https://www.coresecurity.com/advisories/sap-netweaver-enqueue-server-trace-pattern-denial-service-vulnerability>`_

* `SAP LZC LZH Compression Multiple Vulnerabilities <https://www.coresecurity.com/advisories/sap-lzc-lzh-compression-multiple-vulnerabilities>`_

Initial research about the SAP CAR file format was performed by Martin Gallo and published in `Deep-dive into SAP archive file formats <https://www.coresecurity.com/corelabs-research/publications/deep-dive-sap-archive-file-formats>`_
at the `Troopers 2016 Security Conference <https://www.troopers.de/troopers16/agenda/>`_. Additional research was
performed by `Hans-Christian Esperer <https://github.com/hce>`_ and published in the
`Hascar <https://github.com/VirtualForgeGmbH/hascar>`_ tool.

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
- `wxPython <https://www.wxpython.org/>`_
- `fau_timer <https://github.com/seecurity/mona-timing-lib>`_

Some of those extra libraries can be installed with `pip`_ running the following
command::

    $ pip install pysap[examples]

`Sphinx <https://sphinx-doc.org/>`_ is also required for building the API
documentation. For installing it use::

    $ pip install pysap[docs]


Manual installation
~~~~~~~~~~~~~~~~~~~

The tool relays on the `Scapy <http://www.secdev.org/projects/scapy/>`_ version 2.3.2
library for crafting packets. To install the required libraries use::

    $ pip install -r requirements.txt

Once you have downloaded pysap's sources, you can install it easily using
the Python's ``setuptools`` script provided:

1) ``python setup.py test``

2) ``python setup.py install``


Scapy installation
~~~~~~~~~~~~~~~~~~

- For installing `Scapy`_ on Windows, see some guidance `here <https://github.com/secdev/scapy/blob/master/doc/scapy/installation.rst#windows>`_.

- Some scapy installations also requires the following steps:

    Edit the file ``supersocket.py`` (located for example on
    	``/usr/local/lib/python2.7/dist-packages/scapy/supersocket.py``)

    Add the line ``from scapy.packet import Padding``

