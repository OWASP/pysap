.. Message Server example scripts

Message Server Example scripts
==============================


``ms_change_param``
-------------------

This example script changes a parameter using SAP Message Server Administration requests. In order to
be able to change a parameter the Message Server should be configured in monitoring mode
(``ms/monitor=1``, see corresponding `help <https://help.sap.com/saphelp_nw70/helpdata/en/4e/cffdb69d10424e97eb1d993b1e2cfd/content.html>`_
for more details) and the internal port should be reachable. Keep in mind that some of the
parameters are not "dynamic" and can't be changed using this method. If the parameter value is not
specified, the script retrieve the current value.


``ms_dos_exploit``
------------------

This example script can be used to tests a Denial of Service vulnerability
affecting the Message Server (`CVE-2017-5997 <://cve.mitre.org/cgi-bin/cvename.cgi?name=2017-5997>`_).
For more details about the vulnerability see
`ERPScan's Security Advisory <https://erpscan.com/advisories/erpscan-16-038-sap-message-server-http-remote-dos/>`_
and SAP `Security Note 2358972 <https://launchpad.support.sap.com/#/notes/2358972>`_.

This example script was contributed by `Vahagn Vardanyan <https://github.com/vah13>`_ and
`Mathieu Geli <ttps://github.com/gelim>`_.


``ms_dump_info``
----------------

This example script provides a way to dump different type of configuration and parameters about an SAP's instance
made available via the Message Server service. The script connects to the internal port of the ``MS`` service
(by default ``39NN``) and by running the ``dump`` command it will obtain the configuration values.

The following is an example result of running the command:

.. code-block:: none

    $ examples/ms_dump_info.py -d XXX.XXX.XXX.XXX -p 3901
    [*] Connected to the message server XXX.XXX.XXX.XXX:3901
    [*] Sending login packet:
    [*] Login OK, Server string: MSG_SERVER
    ('[*] Sending dump info', 'MS_DUMP_CON')
    -------------------------- dump of mscon table -----------------------------
      NR ADDRESS > Unique key                      FIHDL NEXTREQ NEXTREP
    ----------------------------------------------------------------------------

    #entries = 0


    ('[*] Sending dump info', 'MS_DUMP_PARAMS')

    Release = 753
    Release no = 7530
    Build version = 753.2017.08.01
    System name = SYS
    Instance name = ASCS01
    Trace level = 1
    Trace logging = active (52428800)
    Trace logging string = on, 50 m
    comment = message server SYS
    start time = Fri May  3 07:14:19 2019
    start time (seconds) = 1556892859
    up time = 0:30:35 (1835 secs)
    build time = Aug 18 2017 23:27:38
    build with Unicode = TRUE
    build with Threads = TRUE
    system type = AMD/Intel x86_64 with Linux
    system id = 0x186
    server host = sapserver
    server host (fqn) = sapserver
    server addr = XXX.XXX.XXX.XXX
    server service = sapmsSYS
    server port = 3601
    server service (internal) = 3901
    server port (internal) = 3901
    use unix domain sockets = TRUE
    J2EE send notification = message/request
    J2EE advanced login = on
    J2EE broadcast time = 0/Wed Dec 31 16:00:00 1969
    J2EE reconnect support = 1
    ms/timeout = 5000
    ms/timeout2 = 10000
    ms/conn_timeout = 300
    ms/max_sleep = 20
    ms/sapevt_lb = 0
    ms/keepalive = 300
    ms/max_clients = 600
    ms/ext_client_quota = 50
    #clients = 2
    #clients external = 0
    ms/max_counter = 100
    ms/max_vhost = 16
    ms/audit = LOGIN/OUT  (0x1)
    statistic activated
    ms/max_queue = 600
    ms/warn_queue = 5
    ms/cache_check = 900
    cache count = 0
    cache size = 10
    allocated buffer = 2
    ms/max_open_requests = 10000
    #max_open_requests = 0
    ms/server_port_0 = PROT=HTTP,PORT=8101,TIMEOUT=20,PROCTIMEOUT=60
    ms/http_port = 8101
    http state = LISTEN
    ms/https_port =
    https state = INIT
    ms/http_lookup = 1
    ms/http_domain = TRUE
    ms/http_timeout = 20
    ms/http_proctime = 60
    ms/http_bufferln = 65536
    ms/redirect_version = 1
    ms/http_max_clients = 500
    ms/http_max_ports = 20
    ms/http_enable_handler = TRUE
    ms/http_handler_retry = 10
    ms/http_handler_timeout = 60
    ms/http_was_required = FALSE
    ms/url_fqn = 1
    is/HTTP/default_root_hdl = abap
    is/instname_encoding = none
    #http client = 0
    #https client = 0


``ms_dump_param``
-----------------

This example script connects to the internal Message Server port and retrieves the SAP's instance profile parameters
configured and available to the service. While similar to ``ms_dump_info``, instead of just dumping the values it will
allow for performing checks against a defined set of expected values. The list of expected parameters and their values
should be provided in a file with the following format:


.. code-block:: none

    #<SAP parameter>:<check type in [FILE|EQUAL|NOTEQUAL|INF|SUP|REGEX]>:<expected value>


The supported check types are:

* ``FILE``: The parameter defines an external configuration file.
* ``EQUAL``: The parameter is compared with an expected value and checked if equal.
* ``NOTEQUAL``: The parameter is compared with an expected value and checked if not equal.
* ``INF``: The parameter is compared with an expected integer value and checked if inferior.
* ``SUP``: The parameter is compared with an expected integer value and checked if superior.
* ``REGEX``: The parameter is compared against a regular expression and expected to be matched.


A set of of default recommended values is provided in ``examples/list_sap_parameters`` but each user should create their
own set of expected values. The script can be used then to create a baseline configuration and automate the validation
of a set of Application Servers against it. It's worth noting that due to the way parameters are stored and made
available to the Message Server service there might be false positives. Additionally, configuration stored in external
files (e.g. ACL files, ``secinfo``, ``reginfo``) need to be checked by other means as the script will only point out
the location of the file but not it's content. Other ``dump`` commands might be helpful as to obtain those values
programmatically, check the output of ``ms_dump_info`` for more details.

The following is an example result of running the command:

.. code-block:: none

    $ examples/ms_dump_param.py -d XXX.XXX.XXX.XXX -p 3901 -f examples/list_sap_parameters
    [*] Initiate connection to message server XXX.XXX.XXX.XXX:3901
    [*] Connected. I check parameters...
    [*] Sending login packet:
    [*] Login OK, Server string: MSG_SERVER

    [+] auth/no_check_in_some_cases = Y
    [+] auth/rfc_authority_check = 1
    [ ] dbms/type = syb
    [ ] DIR_AUDIT = /usr/sap/SYS/ASCS01/log
    [ ] FN_AUDIT = audit_++++++++
    [+] gw/acl_mode = 1
    [+] gw/logging = ACTION=Ss LOGFILE=gw_log-%y-%m-%d SWITCHTF=day MAXSIZEKB=100
    [+] gw/monitor = 1
    [ ] gw/proxy_check = *
    [ ] gw/prxy_info = /usr/sap/SYS/ASCS01/data/prxyinfo
    [ ] gw/reg_info = /usr/sap/SYS/ASCS01/data/reginfo
    [!] gw/reg_no_conn_info = 1
    [ ] gw/sec_info = /usr/sap/SYS/SYS/global/secinfo
    [+] gw/sim_mode = 0
    [!] icm/HTTP/logging_0 = *
    [!] icm/HTTP/logging_1 = *
    [!] icm/HTTP/logging_2 = *
    [!] icm/HTTP/logging_3 = *
    [!] icm/HTTP/logging_4 = *
    [ ] icm/server_port_0 = PROT=HTTP,PORT=0,TIMEOUT=60,PROCTIMEOUT=60
    [ ] icm/server_port_1 = PROT=SMTP,PORT=0,TIMEOUT=120,PROCTIMEOUT=120
    [ ] icm/server_port_2 = NOT_EXIST
    [ ] icm/server_port_3 = NOT_EXIST
    [ ] icm/server_port_4 = NOT_EXIST
    [ ] INSTANCE_NAME = ASCS01
    [ ] j2ee/dbname = SYS
    [ ] j2ee/dbtype = syb
    [+] login/fails_to_user_lock = 5
    [!] login/min_password_lng = 6
    [+] login/no_automatic_user_sapstar = 1
    [!] login/password_compliance_to_current_policy = 0
    [+] login/password_downwards_compatibility = 0
    [ ] login/system_client = 001
    [ ] ms/acl_file_admin = NOT_EXIST
    [ ] ms/acl_file_extbnd = NOT_EXIST
    [ ] ms/acl_file_ext = NOT_EXIST
    [ ] ms/acl_file_int = NOT_EXIST
    [ ] ms/acl_info = /usr/sap/SYS/SYS/global/ms_acl_info
    [+] ms/admin_port = 0
    [+] ms/audit = 1
    [!] ms/http_logging = PREFIX=/,LOGFILE=dev_ms_logging,LOGFORMAT=SAPMSG
    [+] ms/monitor = 0
    [ ] rdisp/extbnd_port = *
    [!] rdisp/msserv = sapmsSYS
    [+] rdisp/msserv_internal = 3901
    [!] rec/client = OFF
    [!] rsau/enable = 0
    [+] rsau/ip_only = *
    [+] rsau/max_diskspace/local = 1000000000
    [+] rsau/max_diskspace/per_day = 0
    [+] rsau/max_diskspace/per_file = 0
    [+] rsdb/ssfs_connect = 1
    [ ] rslg/local/file = /usr/sap/SYS/ASCS01/log/SLOG01
    [+] rslg/max_diskspace/local = 10000000
    [ ] SAPDBHOST = sapserver
    [ ] SAPFQDN = NOT_EXIST
    [ ] SAPSYSTEM = 01
    [ ] SAPSYSTEMNAME = SYS
    [ ] service/http/acl_file = NOT_EXIST
    [ ] service/https/acl_file = NOT_EXIST
    [+] service/protectedwebmethods = SDEFAULT
    [!] snc/enable = 0
    [!] system/secure_communication = OFF
    [ ] system/type = ABAP


The script's output will contain a ``[+]`` mark if the value obtained from the Message Server matched the expected one
in the provided file or a ``[!]`` mark if that's not the case. Other parameters not checked will have an empty mark
``[ ]``.

This example script was contributed by `Ivan Genuer <https://twitter.com/_1ggy>`_. The recommended values and
parameters related to the Gateway and Message Server services were obtained from the
`May 2019 Security Notes Webinar <https://support.sap.com/content/dam/support/en_us/library/ssp/offerings-and-programs/support-services/sap-security-optimization-services-portfolio/SAP_Security_Notes_Webinar.pdf>`_
by Frank Buchholz.


``ms_impersonator``
-------------------

This example script is a proof of concept that connects with the Message Server service of
a SAP Netweaver Application Server and impersonates an application server registering as a
Dialog instance server.


``ms_listener``
---------------

This example script connects with the Message Server service and listen for messages coming
from the server. Along with the ``ms_messenger`` script, it can be used as an example for
using the Message Server as a messenger service and send packets from one client to
another connected to the service.


``ms_messenger``
----------------

This example script connects with the Message Server service and sends a message to another
client connected to it. Along with the ``ms_listener`` script, it can be used as an example
for using the Message Server as a messenger service and send packets from one client to
another connected to the service.


``ms_monitor``
--------------

This script is an example implementation of SAP's Message Server Monitor program (``msmon``).
It allows the monitoring of a Message Server service and allows sending different commands and
opcodes. Includes some commands not available on the ``msmon`` program. Some commands requires the
server running in monitor mode, while most of them requires access to the Message Server internal port.

The script implements a console-like interface that can be used to specify the operations to
perform on the Message Server. A list of implemented commands can be obtained by running ``help``.


``ms_observer``
---------------

This example script connects with the Message Server service of a SAP Netweaver Application Server
and monitors the clients to identify new application servers. As the Message Server broadcast
the addition, removal or change of clients to all the clients connected to it, it's possible to
identify those state changes and print them. Similar to SAP's ``msprot`` tool.
