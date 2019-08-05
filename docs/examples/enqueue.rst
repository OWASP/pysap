.. Enqueue example scripts

Enqueue Example scripts
=======================

``enqueue_dos_exploit``
-----------------------

This example script can be used to tests against a Denial of Service vulnerability affecting
the Enqueue service (`CVE-2016-4015 <https://cve.mitre.org/cgi-bin/cvename.cgi?name=2016-4015>`_).
For more details about the vulnerability see
`ERPScan's Security Advisory <https://erpscan.com/advisories/erpscan-16-019-sap-netweaver-enqueue-server-dos-vulnerability/>`_.

This example script was contributed by `Vahagn Vardanyan <https://github.com/vah13>`_.


``enqueue_monitor``
-------------------

This script is an example implementation of SAP's Enqueue Server Monitor program (``ens_mon``).
It allows the monitoring of a Enqueue Server service and allows sending different admin commands
and opcodes. Includes some commands not available on the ``ensmon`` program.

The script implements a console-like interface that can be used to specify the operations to
perform on the Enqueue Server. A list of implemented commands can be obtained by running ``help``.
