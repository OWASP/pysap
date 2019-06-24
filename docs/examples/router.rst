.. Router example scripts

Router Example scripts
======================

``router_admin``
----------------

This example script connects to a SAP Router instance and allows to perform administrative tasks.
The commands available and their syntaxis is similar to the one found on the ``saprouter`` program.
The operation codes and commands are documented in the SAP's help pages for the SAP Router.
In addition to those commands found in the ``saprouter`` program, the scripts includes undocumented
operations codes.

In order for administrative tasks to be run, the script need to be run from the same system where the
SAP Router instance is running (connections identified as "local" by the Network Interface (``NI``)
protocol), or the SAP Router needs to be configured as to allow remote connections to the SAP Router
port. An example of such a routing table to allow this access is as follows:

.. code-block::

    * * 127.0.0.1 3299

The undocumented commands implemented by the script are the following ones:

* ``set-peer-trace``:
    Takes an address mask as an argument and sets the tracing of peers matching that address mask.
* ``clear-peer-trace``:
    Take san address mask as an argument and clears the tracing of peers matching that address mask.
* ``trace-connection``:
    Takes a client identifier as an argument and enables a trace for that connection. The list of
    clients being traced can be observed using the ``router-info`` commands.


``router_fingerprint``
----------------------

It was found out that SAP Router instances include certain information in error messages when
processing certain type of malformed packets or when certain fault situations are reached. The
information contained in those error messages includes details such as the SAP Router's release
number, name of the source code file where the error is thrown, and in some cases the line where
the error was identified. As the source file numbers are frequently changing between one version
of the program an another, it can be very precise as to potentially identify build numbers and
pinpoint particular version numbers. This information can be valuable as to determine
potential security risk in case of running old and potentially vulnerable versions of the SAP
Router service.

This example script is an experimental attempt at performing SAP Router version fingerprinting by
triggering those error conditions and matching the information provided in the error messages with
a previously generated database. A fingerprint database is maintained and located in the
``examples/router_fingerprints.json`` file.

The following is an example result of running the script against a version of SAP Router already
in the database:

.. code-block::

    XXX

As can be observed, by matching the information in the error message with the fingerprint database
it's possible to narrow down the version to a build number.

The following is an example result of running the script against a version of SAP Router that is
not found in the database:

.. code-block::

    XXX

In this case, as the information contained in the error messages wasn't found in the database,
the script output contains the stepts and information required to incorporate that version in the
database as a new record. This can be done by using the ``--add-fingerprint`` option on the script
and providing the ``json`` record.

The following example command line options can be used to add the missing version number to the
database:

.. code-block::

    XXX

Fingerprints for missing versions can be contributed in the form of GitHub issues reporting the
version and build numbers or in the form of pull requests with the addition of new records to the
database.


``router_niping``
-----------------

XXX

``router_password_check``
-------------------------

XXX

``router_portfw``
-----------------

XXX

``router_scanner``
------------------

XXX
