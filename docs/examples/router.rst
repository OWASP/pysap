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
    Takes an address mask as an argument and clears the tracing of peers matching that address mask.
* ``trace-connection``:
    Takes a client identifier as an argument and enables a trace for that connection. The list of
    clients being traced can be observed using the ``router-info`` commands.


``router_fingerprint``
----------------------

It was found out that SAP Router instances include some information in error messages when
processing certain type of malformed packets or when certain fault situations are reached. The
information contained in those error messages includes details such as the SAP Router's release
number, name of the source code file where the error is thrown, and in some cases the code line
where the error was identified. As the source file numbers are frequently changing between one
version of the program an another, it can be very precise as to potentially identify build
numbers and pinpoint particular version numbers. This information can be valuable as to determine
potential security risk in case of running old and potentially vulnerable versions of the SAP
Router service.

This example script is an experimental attempt at performing remote SAP Router version
fingerprinting by triggering those error conditions and matching the information provided in the
error messages with a previously generated database. A fingerprint database is maintained and
located in the ``examples/router_fingerprints.json`` file.

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
database as a new record. This can be done by using the ``--add-fingerprint`` or ``-a`` option on the script
and providing the ``json`` record with the option ``--new-fingerprints-file``.

The following example command line options can be used to add the missing version number to the
database:

.. code-block:: none

    $ ./router_fingerprint.py -a --new-fingerprints-file saprouter_new_fingerprints.json -i '{
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

This example scripts is a very basic implementation of the ``niping`` tool available with SAP kernel
distributions and the ``saprouter`` program. The ``niping`` utility establishes a communication
between two ends (a "client" and a "server") and uses the ``NI`` protocol to send payloads. The tool
is offered as a way to perform troubleshooting and network diagnostics, and it can help determining
network speed and identify connectivity issues. Due to the implementation of the ``NI`` protocol is
also used to validate SAP Router configurations and ACLs.


``router_password_check``
-------------------------

This example and proof of concept script connects with a SAP Router service and makes an information
request using a provided password. It then records the time the remote service takes to respond to
the request. Further analysis of the time records could be performed in order to identify whether
the server is vulnerable to a timing attack on the password check
(`CVE-2014-0984 <https://cve.mitre.org/cgi-bin/cvename.cgi?name=2014-0984>`_).
More details about the vulnerability can be found in the
`SAP Router Password Timing Attack security advisory <https://www.coresecurity.com/advisories/sap-router-password-timing-attack>`_.

The script make use of the fau_timer library for measuring the timing of server's responses, which
can be installed from the `mona-timing-lib repository in GitHub <https://github.com/seecurity/mona-timing-lib>`_.


``router_portfw``
-----------------

This example script establishes a connection to a target host and port through a SAP Router service.
It works by binding a local port (specified by ``--local-port``) on a local IP address (provided by
``--local-host``) and requesting the SAP Router (specified with ``--remote-host`` and ``--remote-port``)
to route a connection to the specified target port (``--target-port``) and host (``--target-host``).
A route password can be optionally provided as well (with the ``--target-pass`` parameter).

The script can be used to route traffic to a remote destination through the SAP Router, for either
testing ACLs or accessing internal resources exposed through it. It's worth mentioning that as the
implementation relies on the use of a "proxy" pattern, the route is only requested to the SAP Router
when there's traffic received on the local port binded.

The script is based on a similar functionality implemented in BizPloit's ``saprouterNative`` script.
More information can be found in Onapsis' blogpost series about testing SAP Router security with
BizPloit, `part I <https://blog.onapsis.com/blog/assessing-a-saprouters-security-with-onapsis-bizploit-part-i/>`_
and `part II <https://blog.onapsis.com/blog/assessing-a-saprouters-security-with-onapsis-bizploit-part-ii/>`_.


``router_scanner``
------------------

This example script performs a scan of a given set of target hosts (specified with ``--target-hosts``)
and ports (provided with ``--target-ports``) via a SAP Router instance (specified with ``--remote-host``
and ``--remote-port``). By requesting a connection to be routed to a given host/port combination and
looking to the SAP Router response, it's possible to determine if the aforementioned host/port is open
to the SAP Router. The script can be also used to discover and validate ACLs configured in the SAP
Router instance.

The list of hosts can be provided to the ``--target-hosts`` parameter as a comma-separated list of
hostnames or IP addresses (e.g. ``10.0.0.1,10.0.0.10``), or if the Python's ``netaddr`` library is
installed in ``CIDR`` representation (e.g. ``10.0.0.1/24``). In the same way, the ports to scan for
can be provided in the ``--target-ports`` parameter using a commma-separated list (e.g. ``3200,3300``)
or a range (e.g. ``3200-3299``).

The script is based on a similar functionality implemented in BizPloit's ``saprouterSpy`` script.
More information can be found in Onapsis' blogpost series about testing SAP Router security with
BizPloit, `part I <https://blog.onapsis.com/blog/assessing-a-saprouters-security-with-onapsis-bizploit-part-i/>`_
and `part II <https://blog.onapsis.com/blog/assessing-a-saprouters-security-with-onapsis-bizploit-part-ii/>`_.
