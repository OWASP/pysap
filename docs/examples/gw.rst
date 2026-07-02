.. Gateway example scripts

Gateway Example scripts
=======================

``gw_monitor``
--------------

This script is an example implementation of SAP's Gateway monitor program
(``gwmon``). It allows monitoring a Gateway service and sending admin commands
and opcodes through a console-like interface. Some commands require the Gateway
service to allow monitor access.

The monitor connects to the target Gateway with ``--remote-host`` and
``--remote-port`` (default ``3300``), or through a SAP Router route string with
``--route-string``. The Gateway protocol version can be selected with
``--version`` and defaults to ``3``. The client name sent by the monitor can be
changed with ``--client``.

The script can write packet logs with ``--log-file`` and console output with
``--console-log``. It can also execute commands from a file with ``--script``.
After connecting, run ``help`` inside the console to list the implemented
commands.

Example usage:

.. code-block:: console

    $ examples/gw_monitor.py -d <gateway-host> -p 3300 --client pysap-monitor --log-file gw.log
