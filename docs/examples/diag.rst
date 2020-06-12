.. Diag example scripts

Diag Example scripts
====================

``diag_capturer``
-----------------

This example script can be used to grab SAP GUI login credentials from a ``pcap`` file or by
directly sniffing on a network interface. The SAP Diag protocol packets are parsed and
processed to obtain login credentials from the login form submissions. Identification of the
password field is performed by means of looking at the "invisible" property used by SAP to
denote password or other sensitive fields that should be masked by the SAP GUI.


``diag_dos_exploit``
--------------------

This example script can be used to tests against Denial of Service vulnerabilities affecting the
Dispatcher service. Currently 5 different vulnerabilities can be triggered:

- `CVE-2012-2612 <https://cve.mitre.org/cgi-bin/cvename.cgi?name=2012-2612>`_
- `CVE-2012-2511 <https://cve.mitre.org/cgi-bin/cvename.cgi?name=2012-2511>`_
- `CVE-2012-2512 <https://cve.mitre.org/cgi-bin/cvename.cgi?name=2012-2512>`_
- `CVE-2012-2513 <https://cve.mitre.org/cgi-bin/cvename.cgi?name=2012-2513>`_
- `CVE-2012-2514 <https://cve.mitre.org/cgi-bin/cvename.cgi?name=2012-2514>`_


``diag_interceptor``
--------------------

This example script is aimed at demonstrating the use of the ``SAPNIProxy`` and ``SAPNIProxyHandler``
interfaces. It can be used to establish a proxy between a SAP GUI client and a SAP Netweaver
Application Server and inspect the traffic via the ``filter_client`` and ``filter_server`` functions.

The given example implements a simple function that grabs input fields sent by the client and prints
them.


``diag_login_brute_force``
--------------------------

This example script can be used to perform a brute force attack against a SAP Netweaver
application server. The scripts performs a login through the Diag protocol, by submitting
username and passwords to the login screen. It can also be used to discover available clients.

Usernames, passwords and SAP clients to test can be provided as individual files (using
``--usernames``, ``--passwords`` and ``--clients`` command line options), in which case the
script will calculate and test the combination of those, or provided in a credentials file
(via the ``--credentials`` parameter). The credential file is expected to have a format
containing ``username:password:client`` and blank lines or lines starting with the ``#`` are
ignored.

Clients discovery can be also performed as a firs step of the brute-force attack, by specifying
the ``--discovery`` option and providing a list of clients to test using the ``--discovery-range``
parameter.

Testing of the credentials can be performed using multiple parallel threads using the ``--threads``
parameter as a way to increase performance.

A list of default credentials and their associated default clients is also provided in the
``examples/default_sap_credentials`` file. This credentials file can be used to perform basic
checks.

Note that as error responses might vary across versions it might be possible that the script
generates false positive. In addition, it should be noted that there's no mechanism implemented
to prevent the lockout of user accounts if the server is configured with a lockout policy. Use
with care and at your own risk.

Finally, the ``login/show_detailed_errors`` parameter can be configured to ``FALSE`` in the SAP
Application Server to avoid disclosing information about whether a client exists or not, and
to avoid returning information about existent users. For more information see
`SAP Security Note 1823687 <https://launchpad.support.sap.com/#/notes/1823687>`_.

If the parameter is configured to ``FALSE``, the results of the discovery will be flawed, with
probably a large set (if not all) of clients invalidly reported as existent. The same false
positives will be reported for user names validity. The finding of valid credentials is not
affected thought.


``diag_login_screen_info``
--------------------------

This example script can be used to gather information provided by a SAP Netweaver Application
Server during the login process. This information includes generally hostname, instance, database
name, language and other technical information about the application server.


``diag_render_login_screen``
----------------------------

This example script is a proof of concept of how the library can be used to obtain and interpret
the screen components and fields provided by an SAP Netweaver Application Server. It takes the
login screen presented by the application server and renders it using ``wxPython`` widgets and user
interface components. Take into account that not all field types and Diag protocol packets
are completely implemented in the library, and that those change from version to version.


``diag_rogue_server``
---------------------

This example script is a proof of concept that implements a rogue server using the SAP Diag protocol.
It offers users a customizable login screen and gathers credentials provided by the clients
connecting to it. A basic interaction is implemented that allows for the user to introduce the
credentials and then returns a generic error message.

Tested with SAP Gui for Java 7.20 Patch Level 5 running on Ubuntu.
