.. Router example scripts

Router Example scripts
======================

``router_admin``
----------------

This example script connects to a SAP Router instance and allows to perform administrative tasks.
The commands available and their syntax is similar to the one found on the ``saprouter`` program.
The operation codes and commands are documented in the SAP's help pages for the SAP Router.
In addition to those commands found in the ``saprouter`` program, the scripts includes undocumented
operations codes.

In order for administrative tasks to be run, the script need to be run from the same system where the
SAP Router instance is running (connections identified as "local" by the Network Interface (``NI``)
protocol), or the SAP Router needs to be configured as to allow remote connections to the SAP Router
port. An example of such a routing table to allow this access is as follows:

.. code-block:: none

    P * 127.0.0.1 3299

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

.. code-block:: none

    $ python router_fingerprint.py -d <hostname>
    [*] Loading fingerprint database
    [*] Trying to fingerprint version using 13 packets
    [*] (1/13) Fingerprint for packet 'No route one entry'
    [*] (1/13) Fingerprint for packet 'No route one entry' matched !
    [*] (2/13) Fingerprint for packet 'Timeout'
    [*] (2/13) Fingerprint for packet 'Timeout' matched !
    ..
    ..
    [*] (13/13) Fingerprint for packet 'No route invalid length' matched !

    [*] Matched fingerprints (13/13):
    [+] Request: No route one entry
    [+] Request: Timeout
    [+] Request: No route
    [+] Request: Empty route invalid offset
    [+] Request: Non existent domain old version
    [+] Request: Valid domain invalid service
    [+] Request: Invalid control opcode
    [+] Request: Network packet too big
    [+] Request: Empty route invalid length
    [+] Request: Non existent domain
    [+] Request: Empty route valid length
    [+] Request: Empty route null offset
    [+] Request: No route invalid length

    [*] Probable versions (1):
    [*]	Hits: 13 Version: version: "40" release: "749" patch_number: "200" source_id: "0.200" update_level: "0" platform: "linux-x86-64" submitted_by: "mgallo@secureauth.com"


As can be observed, by matching the information in the error message with the fingerprint database
it's possible to narrow down the version to a build number.

The following is an example result of running the script against a version of SAP Router that is
not found in the database:

.. code-block:: none

    $ ./router_fingerprint.py -d <hostname>
    [*] Loading fingerprint database
    [*] Trying to fingerprint version using 13 packets
    [*] (1/13) Fingerprint for packet 'No route one entry'
    [*] (1/13) Fingerprint for packet 'No route one entry' not matched
    [*] (2/13) Fingerprint for packet 'Timeout'
    [*] (2/13) Fingerprint for packet 'Timeout' not matched
    ..
    ..
    [*] (13/13) Fingerprint for packet 'No route invalid length'
    [*] (13/13) Fingerprint for packet 'No route invalid length' not matched

    [*] Non matched fingerprints (13/13):
    [-] Request: No route one entry
    [-] Request: Timeout
    [-] Request: No route
    [-] Request: Empty route invalid offset
    [-] Request: Non existent domain old version
    [-] Request: Valid domain invalid service
    [-] Request: Invalid control opcode
    [-] Request: Network packet too big
    [-] Request: Empty route invalid length
    [-] Request: Non existent domain
    [-] Request: Empty route valid length
    [-] Request: Empty route null offset
    [-] Request: No route invalid length

    [-] Some error values where not found in the fingerprint database. If you want to contribute submit a issue to https://github.com/SecureAuthCorp/pysap or write an email to mgallo@secureauth.com with the following information along with the SAP Router file information and how it was configured.


    New fingerprint saved to: saprouter_new_fingerprints.json


    Version information to complete and submit:
    {
        "comment": "",
        "submitted_by": "",
        "update_level": "",
        "patch_number": "",
        "file_version": "",
        "platform": "",
        "source_id": ""
    }

In this case, as the information contained in the error messages wasn't found in the database,
the script output contains the steps and information required to incorporate that version in the
database as a new record. This can be done by using the ``--add-fingerprint`` option on the script
and providing the ``json`` record.

The following example command line options can be used to add the missing version number to the
database:

.. code-block:: none

    $ ./router_fingerprint.py -a saprouter_new_fingerprints.json -i '{
    >     "comment": "A new comment to add to the fingerprint",
    >     "submitted_by": "email or contact of the submitter",
    >     "update_level": "update level",
    >     "patch_number": "patch number",
    >     "file_version": "file vesion",
    >     "platform": "linux_x86_64",
    >     "source_id": "source id number"
    > }'
    [*] Loading fingerprint database
    [*] Adding a new entry to the fingerprint database
    [*]	Added a new entry for the target No route one entry
    [*]	Added a new entry for the target Timeout
    [*]	Added a new entry for the target No route
    [*]	Added a new entry for the target Empty route invalid offset
    [*]	Added a new entry for the target Non existent domain old version
    [*]	Added a new entry for the target Valid domain invalid service
    [*]	Added a new entry for the target Invalid control opcode
    [*]	Added a new entry for the target Network packet too big
    [*]	Added a new entry for the target Empty route invalid length
    [*]	Added a new entry for the target Non existent domain
    [*]	Added a new entry for the target Empty route valid length
    [*]	Added a new entry for the target Empty route null offset
    [*]	Added a new entry for the target No route invalid length

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
