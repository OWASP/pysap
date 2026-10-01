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

Manifest validation
~~~~~~~~~~~~~~~~~~~

Archives containing ``SIGNATURE.SMF``, ``MANIFEST.MF``, or ``MANIFEST`` can be
checked before listing or extraction. Integrity validation verifies declared
members, sizes, and content digests::

    $ pysapcar -t -f archive.sar --validate-manifest
    $ pysapcar -x -f archive.sar -o output-dir --validate-manifest

Use ``--strict-manifest`` when a valid trusted signature is also required and
each missing, unexpected, malformed, unsafe, or mismatched member should be
reported. By default, verification uses the same embedded SAP signer and
timestamp certificates used for native-compatible operation. A trust store or
certificate directory overrides those defaults::

    $ pysapcar -t -f archive.sar --strict-manifest \
        --manifest-trust-store trusted-certificates.pem

Trust checking supports a direct signer certificate or direct issuer match. It
does not perform complete PKI path construction, certificate-policy checking,
or revocation checking.

An archive without a recognized manifest reports ``not-present``; strict mode
fails because it cannot establish a trusted signature. Archives with multiple
recognized manifest files are rejected as ambiguous so unsigned content cannot
be merged into the scope of a different signature. Archive member paths are
validated before extraction regardless of manifest presence.

A detached PKCS#7 manifest can be created with a caller-owned certificate and
unencrypted RSA private key::

    $ pysapcar -c -f archive.sar payload.bin \
        --sign-manifest signer.crt --signing-key signer.key

Signing does not establish trust by itself. Validate the resulting archive
against an independently configured trust store. The timestamp token is
generated locally; it proves possession of the configured key, not a timestamp
from an independent authority. The library crafting API defaults to safe member
validation but accepts ``strict=False`` for deliberate malformed or tampered
research cases. Test-only keys must be clearly identified and must never be
reused outside the deterministic test fixtures; proprietary archives must not
be committed as fixtures.


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
