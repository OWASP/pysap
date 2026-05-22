.. Download Manager example scripts

Download Manager scripts
========================

``dlmanager_decrypt``
---------------------

This example script extracts SAP Download Manager stored passwords. For SAP Download Manager
versions before ``2.1.140a``, stored passwords were kept unencrypted. For versions between
``2.1.140a`` and ``2.1.142``, the script should be able to decrypt the password given possible
to obtain the machine serial number.

The input of the script is the file stored by the SAP Download Manager program, which uses the
Java serialization encoding.

The script can attempt to retrieve the machine serial number when running on Windows, if
provided with the ``--retrieve-serial-number`` option. For other platforms it must need to be
provided by the ``--serial-number`` parameter.

Example usage:

.. code-block:: console

    $ examples/dlmanager_decrypt.py -f dlmanager.conf
    $ examples/dlmanager_decrypt.py -f dlmanager.conf --encrypted --serial-number <serial-number>
    $ examples/dlmanager_decrypt.py -f dlmanager.conf --encrypted --retrieve-serial-number

For more details on the encryption mechanism see
`CVE-2016-3685 <https://www.cve.org/CVERecord?id=CVE-2016-3685>`_ and
`CVE-2016-3684 <https://www.cve.org/CVERecord?id=CVE-2016-3684>`_ documented in the
`SAP Download Manager Password Weak Encryption security advisory <https://www.coresecurity.com/advisories/sap-download-manager-password-weak-encryption>`_.


``dlmanager_infector``
----------------------

The SAP Download Manager infector script is a proof of concept to demonstrate the risk of not
validating SAR file signatures. The script can be used to infect a given ``SAR`` ``v2.00`` or
``v2.01`` file by means of adding new files to it. Each file to infect is specified by a pair:
``filename`` (original filename) and ``archive filename`` (the name we want inside the archive).
The script can also be used to dynamically infect ``SAR`` files being downloaded using ``mitmproxy``.
In that case, the scripts takes the files to inject as parameters, performs an ``SSLStrip``-like
MitM and when identifies a ``SAR`` file that is going to be offered as a download it infects it.

For more details about the exemplified attack vector see the `Deep-dive into SAP
archive file formats <https://troopers.de/events/troopers16/628_deep-dive_into_sap_archive_file_formats/>`_
presentation at Troopers' 2016.

Example usage for a local SAR archive:

.. code-block:: console

    $ examples/dlmanager_infector.py -f package.SAR payload.sh usr/sap/payload.sh
