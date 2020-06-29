.. HDB example scripts

HANA SQL Command Network Protocol Example scripts
=================================================

``hdb_discovery``
-----------------

This example script can be used to perform discovery of HANA database tenants. The scripts connects
to a given HANA instance, usually the ``SYSTEMDB``, and tries a list of tenant database names. The
list can be provided either directly from the command line or from a file, and the script will return
the result from sending a ``DBCONNECTINFO`` packet. If the database tenant exists, it will include
the IP address and the port number, in addition to whether the tenant is connected to the master index
server or not.
