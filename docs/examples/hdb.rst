.. HDB example scripts

HANA SQL Command Network Protocol Example scripts
=================================================

``hdb_discovery``
-----------------

This example script can be used to perform discovery of HANA database tenants. The script connects
to a given HANA instance, usually the ``SYSTEMDB``, and tries a list of tenant database names. The
list can be provided either directly from the command line or from a file, and the script will return
the result from sending a ``DBCONNECTINFO`` packet. If the database tenant exists, it will include
the IP address and the port number, in addition to whether the tenant is connected to the master index
server or not.

Example usage:

.. code-block:: console

    $ examples/hdb_discovery.py -d <hana-host> -p 39013 -t SYSTEMDB,TENANT1 -o tenants.json
    $ examples/hdb_discovery.py -d <hana-host> -p 39013 --dictionary tenants.txt --tls --tls-check-hostname


``hdb_auth``
------------

This example script is an experimental implementation of the HANA's ``hdbsql`` tool. It focuses on
the authentication and connection to the HANA server, and it is not meant to implement the full
capabilities offered by ``hdbsql`` or any other HDB client interface.

The supported authentication mechanisms are:

* ``SCRAMSHA256``: username and password should be provided.
* ``SCRAMPBKDF2SHA256``: username and password should be provided.
* ``JWT``: a JWT can be provided as an input file or a ``JWT`` can be generated if a certificate
  file and an issuer is provided via command line. Generating a ``JWT`` requires the ``PyJWT``
  library to be installed.
* ``SAML``: a SAML bearer assertion can be provided as an input file.
* ``SessionCookie``: a session cookie obtained from a previous ``SAML`` authentication can be
  provided.

In addition, the connection can optionally be established using ``TLS``. When ``TLS`` is enabled,
by default the server's certificate is trusted and hostname validation is not performed. Those
options can be enabled using the ``--tls-no-trust-cert`` and ``--tls-check-hostname`` parameters.
The tool will try to use the operating system certificate store, as available to
Python's ``ssl`` library, but a custom certificate file can be provided via the
``--tls-cert-file`` parameter.

Example usage:

.. code-block:: console

    $ examples/hdb_auth.py -d <hana-host> -p 39015 -m SCRAMSHA256 --username SYSTEM --password <password>
    $ examples/hdb_auth.py -d <hana-host> -p 39015 -m JWT --username <user> --jwt-file token.jwt
    $ examples/hdb_auth.py -d <hana-host> -p 39015 -m JWT --username <user> --jwt-key private.key --jwt-issuer <issuer>
    $ examples/hdb_auth.py -d <hana-host> -p 39015 -m SAML --saml-assertion assertion.xml
    $ examples/hdb_auth.py -d <hana-host> -p 39015 -m SessionCookie --username <user> --session-cookie <cookie>
    $ examples/hdb_auth.py -d <hana-host> -p 39015 --tls --tls-no-trust-cert --tls-cert-file server.pem --tls-check-hostname -m SCRAMPBKDF2SHA256 --username <user> --password <password>
