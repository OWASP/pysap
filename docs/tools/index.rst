.. Command-line tools frontend

Command-line tools
==================

pysap installs a small set of command-line tools for offline work with SAP file
formats. These are persistent utilities, not example scripts. They are installed
with the package and operate on local files supplied by the user.

The tools are experimental and focused on pysap-supported formats. Use the
module APIs directly when an application needs stricter error handling or a
stable integration contract.


``pysapcar``
------------

``pysapcar`` works with SAP ``SAR`` archive files through the
:mod:`pysap.SAPCAR` module. It can create, append, list, and extract archives.

List archive contents::

    $ pysapcar -t -f archive.sar

Extract an archive into a directory::

    $ pysapcar -x -f archive.sar -o output-dir

Create an archive from local files::

    $ pysapcar -c -f archive.sar file1.txt file2.txt

Append a file to an existing archive::

    $ pysapcar -a -f archive.sar file3.txt

Relevant options include ``-v`` for verbose output,
``--enforce-checksum`` to stop extraction of files with invalid checksums, and
``--break-on-error`` to stop processing after an extraction error.


``pysapgenpse``
---------------

``pysapgenpse`` provides offline helpers for SAP Personal Security Environment
(``PSE``) and SSO Credential (``Credv2``) files through :mod:`pysap.SAPPSE` and
:mod:`pysap.SAPCredv2`.

List credentials stored in a Credv2 file::

    $ pysapgenpse -c seclogin -l -f cred_v2

Decrypt a credential PIN with a known user name::

    $ pysapgenpse -c seclogin -d -f cred_v2 -u username

Export a certificate from a plain PSE as DER::

    $ pysapgenpse -c get_pse_certs -f local.pse -o output.der

Encrypted PSE files require the PIN::

    $ pysapgenpse -c get_pse_certs -f encrypted.pse -x pin -o output.der

Use ``-n`` to select which certificate to export. Certificate numbering is
zero-based; by default the first certificate is exported.

If the PIN is not known, encrypted PSE files can be converted to a format
accepted by John the Ripper using the ``extra/pse2john.py`` helper script::

    $ python3 extra/pse2john.py encrypted.pse > pse.hash
    $ john pse.hash

The converter writes hashes for supported encrypted PSE files and reports
unsupported files on standard error while continuing with the remaining input
files.

If ``-f`` is omitted for ``seclogin`` and ``SECUDIR`` is set, the tool looks for
``cred_v2`` in that directory. The ``-u`` option controls the user name used for
credential decryption; otherwise ``USER`` or ``USERNAME`` is used when present.


``pysaphdbuserstore``
---------------------

``pysaphdbuserstore`` inspects SAP HANA client secure user store files backed by
SSFS key/data files through :mod:`pysap.SAPSSFS`.

List records in an SSFS data file::

    $ pysaphdbuserstore -c list -d SSFS_HDB.DAT

Show a record without decrypting encrypted content::

    $ pysaphdbuserstore -c get -d SSFS_HDB.DAT HDB/KEYNAME/DB_USER

Decrypt an encrypted record when the matching key file is available::

    $ pysaphdbuserstore -c get -d SSFS_HDB.DAT -k SSFS_HDB.KEY --decrypt HDB/KEYNAME/DB_PASSWORD

If ``-d`` or ``-k`` is omitted, the tool uses the default HANA client secure
store paths under ``$HOME/.hdb/<hostname>/``. Use ``--deleted`` to include
records marked as deleted.
