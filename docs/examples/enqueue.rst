.. Enqueue example scripts

Enqueue Example scripts
=======================

``enqueue_dos_exploit``
-----------------------

This example script can be used to test against a Denial of Service vulnerability affecting
the Enqueue service (`CVE-2016-4015 <https://www.cve.org/CVERecord?id=CVE-2016-4015>`_).
For more details about the vulnerability see
`ERPScan's Security Advisory mirror <https://seclists.org/fulldisclosure/2016/Jul/44>`_.

This example script was contributed by `Vahagn Vardanyan <https://github.com/vah13>`_.


``enqueue_monitor``
-------------------

This script is an example implementation of SAP's Enqueue Server Monitor program (``ens_mon``).
It allows the monitoring of an Enqueue Server service and allows sending different admin commands
and opcodes. It includes some commands not available on the ``ensmon`` program.

The script implements a console-like interface that can be used to specify the operations to
perform on the Enqueue Server. It connects with ``--remote-host`` and ``--remote-port`` (default
``3200``), or through a SAP Router route string with ``--route-string``. The client name can be
changed with ``--client``. Packet logs can be written with ``--log-file``, console output can be
written with ``--console-log``, and commands can be loaded from a file with ``--script``. A list of
implemented commands can be obtained by running ``help`` inside the console.

Example usage:

.. code-block:: console

    $ examples/enqueue_monitor.py -d <enqueue-host> -p 3200 --script enqueue_commands.txt
