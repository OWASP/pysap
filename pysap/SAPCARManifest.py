# encoding: utf-8
# pysap - Python library for crafting SAP's network protocols packets
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# Author:
#   Martin Gallo (@martingalloar)
#
# Parser and validation helpers for SAP archive manifests.
# SAP's ``SIGNATURE.SMF`` is deliberately a small, line-oriented format.  This
# module also accepts the common section/key form used by third-party CAR
# producers; unknown fields are retained so parsing does not discard vendor
# metadata.
#

import base64
import binascii
from datetime import datetime, timezone
import glob
import hashlib
import os
import posixpath
import re
import warnings
from dataclasses import dataclass, field

from cryptography import exceptions, x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from scapy.asn1.asn1 import ASN1_Error

from pysap.utils.fields import asn1_decode_oid, asn1_read_tlv


# SAPCAR carries SAP signer and timestamp certificates. They are used
# only when the caller does not supply an explicit trust store or directory.
SAP_TRUST_CERTIFICATE_PEM = b"""-----BEGIN CERTIFICATE-----
MIIEfzCCA2egAwIBAgIBGzANBgkqhkiG9w0BAQsFADBMMQswCQYDVQQGEwJERTEf
MB0GA1UEChMWU0FQIFRydXN0IENvbW11bml0eSBJSTEcMBoGA1UEAxMTU0FQIENv
ZGUgU2lnbmluZyBDQTAeFw0yNjA1MDUxMzU3MDJaFw0yNzA1MDUxMzU3MDJaMF0x
CzAJBgNVBAYTAkRFMR8wHQYDVQQKExZTQVAgVHJ1c3QgQ29tbXVuaXR5IElJMRUw
EwYDVQQLEwxDb2RlIFNpZ25pbmcxFjAUBgNVBAMTDUNvZGVTaWduZXIwMTgwggGi
MA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQC33I98ZUoXY9oleMZad3EkQQst
a4IygZZFBPnsn73vyR7xJVIS5tkj6DiZRE4nzMI3HPIoZ5nVjQ6g2drHPpt36jAM
lcUPQN+Pp8vhW7pBJB6srSrXHyZNbPmH40xzBQr+0ldaogPZF4HmQZf4nQvMPnBQ
zG7Z9dNZNng3XRnB9vI4SejhHQ60AjqUGM5v7aypxcQI5CiCd5cajXW3pTqwoGYY
IrBu5X6BIVH/15etKrhO7gk4a8+2+sErHuKHTC74/Eiwxe7JLUk97IlMKt5m1+Bj
4XG4FRJVBlGT+uXq3lwZRbXe0o1OLcl63+dIcAYS791GgFtt9Yvuoc1/Wv/kiVXO
G9xwgQZf642hrwbLxbFqUCQ5LGdJ2n7CoHIRpQF/LtPfaG3QgxV4oP3xNjOzErjw
TXVeHAVQxk34VyXGdk7KZ78aI/7PipUKXfbnIVobrsLehw/omtz8sHMHX43LfqUl
xSNeCMsCGUNyOCIg3Sh4twO55X/qy4hOZ0aHCz0CAwEAAaOB2jCB1zBQBgNVHR8E
STBHMEWgQ6BBhj9odHRwczovL3Rjcy5teXNhcC5jb20vY3JsL1RydXN0Q29tbXVu
aXR5SUkvU0FQQ29kZVNpZ25pbmdDQS5jcmwwDAYDVR0TAQH/BAIwADAlBgNVHRIE
HjAchhpodHRwOi8vc2VydmljZS5zYXAuY29tL1RDUzAOBgNVHQ8BAf8EBAMCBsAw
HQYDVR0OBBYEFPJU3bpmxlaU7BsudtsUAg8W2++GMB8GA1UdIwQYMBaAFNYAhhc5
p6zRneglXvdDpW+NkmLKMA0GCSqGSIb3DQEBCwUAA4IBAQASY7TwpPrgZIwN4wEf
texkvbq8uVW8C/as7gghGtxETQe8lhKY3ovndeNofrcoF54q+cjBP0xK9oq73BKJ
uQbNAeAv5EYtTKONyo+hTX12WvT0a3xmsgBtPr9cwS4U1Bc1jkIZNNisDnxwxqas
t3G1l67bXY5BxAeMUSjBikBY4mK2MYmbM4KnoHQSD19ZoBYxLeWrJMuo8WTvBoG6
Mnhiag0ya8BmCBErGJX7VJnbWLTUMLwkUwHAjgd3r/q5EeH78iO0mxmmdSel76za
qQ/b12hFy1i9DUj/4nPW6as8l4L2nn1w7bduaftxOy7YZ+axxvuNJ5upMA9gn5G/
GuC7
-----END CERTIFICATE-----
"""

SAP_TSA_CERTIFICATE_PEM = b"""-----BEGIN CERTIFICATE-----
MIIEFjCCAv6gAwIBAgIBBzANBgkqhkiG9w0BAQsFADBMMQswCQYDVQQGEwJERTEf
MB0GA1UEChMWU0FQIFRydXN0IENvbW11bml0eSBJSTEcMBoGA1UEAxMTU0FQIENv
ZGUgU2lnbmluZyBDQTAeFw0xMjEwMDUxNDE1MjNaFw00MDA3MTgxMDAwMDBaMFwx
CzAJBgNVBAYTAkRFMR8wHQYDVQQKExZTQVAgVHJ1c3QgQ29tbXVuaXR5IElJMRYw
FAYDVQQLEw1UaW1lIFN0YW1waW5nMRQwEgYDVQQDEwtTQVAgVFNBIDEwMzCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKepdMctd5kBTSJmK0FmWXzv3OEN
FOyKH6RWGm98rMqOci23WiUXT/r2R6cl130s3yVwm0QJ1fSLQMZqaKeRLuCwYX81
4i0d8AEG7NBu4FTrHyvrXUdDjWUx9eL2DGzsECn1sUbelqHZGCIuxqa0gQlLDOIB
Sx+8FBdfU5ADxrODBTOpW0flDz++oPlyRwopkC5Kl50aiR/aJL80EKTjeP36l07j
b/OoVXTgM4Oi0w1LMajhF2AD3cyqJZ6aHyBQZahc/H/FuP9O9IWeqQpUtzG5IcDJ
kNa1yWJNPCmy2ZMh8J7JLJd+Fgs8T7yvjKYt/O6pz1j1AD8VQiZTEkfc758CAwEA
AaOB8jCB7zBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwczovL3Rjcy5teXNhcC5jb20v
Y3JsL1RydXN0Q29tbXVuaXR5SUkvU0FQQ29kZVNpZ25pbmdDQS5jcmwwDAYDVR0T
AQH/BAIwADAlBgNVHRIEHjAchhpodHRwOi8vc2VydmljZS5zYXAuY29tL1RDUzAO
BgNVHQ8BAf8EBAMCBsAwHQYDVR0OBBYEFP4eTaQw0BPOv/SBJBPEJ20MelXBMB8G
A1UdIwQYMBaAFNYAhhc5p6zRneglXvdDpW+NkmLKMBYGA1UdJQEB/wQMMAoGCCsG
AQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IBAQC0LthEF1mUPkBPPrfiiijYwkhSREpa
I+tpLwN/Hch6hPMFZ+y4EwHNqMuqVdUeGtF6AaKs3dW7K1MR+RhMhMIv2PNiyg/Z
3841b3ayV546EK7lsH/ybe3SrcvstQ5SHyPzptWlKSvBengd/NOZOy6pY6J2hMy2
H9lI315WoL4+tc8mmHt/9zRvQesKZXLqpT+Zg+qUjNgKkY3M4y7pjqS8H7yZqoft
//AzLlDaY2V09Q9LKNQ8ed7z0pKdhpUY0xpDI3+fCsBgUWA+c7B+fLNaBhNbBEYh
2x46NwCPWYgsDhNoT65vcrHrbrn+NG17pKjpRwYfmZPdrR0KfrORwaX9
-----END CERTIFICATE-----
"""


class SAPCARManifestError(ValueError):
    """Raised when a manifest is malformed or unsafe."""


def load_signing_material(certificate, private_key):
    """Load a certificate and private key from paths or return supplied objects."""
    if isinstance(certificate, (str, os.PathLike)):
        with open(certificate, "rb") as fd:
            certificate = fd.read()
    if isinstance(certificate, bytes):
        try:
            certificate = x509.load_pem_x509_certificate(certificate)
        except ValueError:
            certificate = x509.load_der_x509_certificate(certificate)
    if isinstance(private_key, (str, os.PathLike)):
        with open(private_key, "rb") as fd:
            private_key = fd.read()
    if isinstance(private_key, bytes):
        private_key = serialization.load_pem_private_key(private_key, password=None)
    if not isinstance(certificate, x509.Certificate):
        raise SAPCARManifestError("invalid signing certificate")
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise SAPCARManifestError("manifest crafting currently requires an RSA private key")
    return certificate, private_key


def create_signed_manifest(entries, certificate, private_key,
                           timestamp_certificate=None, timestamp_private_key=None,
                           strict=True):
    """Create a SAP manifest with a detached PKCS#7 signature.

    The timestamp token is generated locally with either the timestamp key or
    the signing key. Set ``strict=False`` to retain unsafe or duplicate entry names.
    """
    certificate, private_key = load_signing_material(certificate, private_key)
    lines = ["SAP-MANIFEST", "Version: 1.0", "Hash: SHA256",
             "Signature: PKCS7-TSTAMP", "Body: Digest | Name-Length | Name", ""]
    prepared = []
    seen = set()
    for filename, data in entries:
        filename = normalize_manifest_path(filename) if strict else _text_name(filename)
        if strict and filename in seen:
            raise SAPCARManifestError("duplicate manifest entry: %s" % filename)
        seen.add(filename)
        prepared.append((filename, data))
    for filename, data in sorted(prepared, key=lambda item: item[0]):
        filename_bytes = filename.encode("utf-8")
        lines.append("%s %04x %s" % (hashlib.sha256(data).hexdigest(),
                                     len(filename_bytes), filename))
    # SAPCAR separates the manifest body from the detached signature
    # block with an empty line; the separator is part of the signed data.
    signed_data = ("\n".join(lines) + "\n\n").encode("utf-8")
    signature = pkcs7.PKCS7SignatureBuilder().set_data(signed_data).add_signer(
        certificate, private_key, hashes.SHA256()).sign(
            serialization.Encoding.DER,
            [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary])
    signature = _add_local_timestamp_token(signature, certificate, private_key,
                                           timestamp_certificate, timestamp_private_key)
    manifest = signed_data + b"-----BEGIN SIGNATURE-----\n"
    manifest += base64.encodebytes(signature)
    manifest += b"-----END SIGNATURE-----\n"
    return manifest


def _text_name(value):
    """Convert a research-crafted manifest name without applying safety rules."""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


_OID_DATA = "1.2.840.113549.1.7.1"
_OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
_OID_SHA256 = "2.16.840.1.101.3.4.2.1"
_OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
_OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
_OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
_OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
_OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
_OID_TIMESTAMP_TOKEN = "1.2.840.113549.1.9.16.2.14"
_OID_SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12"


def _der_encode_length(length):
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der_encode(tag, value):
    return bytes([tag]) + _der_encode_length(len(value)) + value


def _der_encode_oid(value):
    parts = [int(part) for part in value.split(".")]
    encoded = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunks = [part & 0x7f]
        part >>= 7
        while part:
            chunks.append(0x80 | (part & 0x7f))
            part >>= 7
        encoded += bytes(reversed(chunks))
    return _der_encode(0x06, encoded)


def _der_sequence(*values):
    return _der_encode(0x30, b"".join(values))


def _der_set(*values):
    return _der_encode(0x31, b"".join(sorted(values)))


def _der_integer(value):
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return _der_encode(0x02, encoded)


def _der_algorithm_identifier(oid):
    return _der_sequence(_der_encode_oid(oid), _der_encode(0x05, b""))


def _der_attribute(oid, value):
    return _der_sequence(_der_encode_oid(oid), _der_set(value))


def _certificate_issuer_and_serial(certificate):
    certificate_der = certificate.public_bytes(serialization.Encoding.DER)
    tbs = _der_children(_der_tlv(certificate_der)[1])[0][1]
    fields = _der_children(tbs)
    index = 1 if fields[0][0] == 0xa0 else 0
    issuer = fields[index + 2][2]
    serial = int.from_bytes(fields[index][1], "big")
    return issuer, serial, certificate_der


def _timestamp_token(cms_signature, certificate, private_key,
                     timestamp_certificate=None, timestamp_private_key=None):
    """Create a local RFC3161-shaped token."""
    content_info = _der_tlv(cms_signature)[1]
    signed_data = _der_tlv(_der_children(content_info)[1][1])[1]
    signer_set = _der_children(signed_data)[-1]
    signer_info = _der_children(_der_children(signer_set[1])[0][1])
    signer_signature = next(item[1] for item in reversed(signer_info) if item[0] == 0x04)
    if timestamp_certificate is None or timestamp_private_key is None:
        tsa_certificate, tsa_key = certificate, private_key
    else:
        tsa_certificate, tsa_key = load_signing_material(timestamp_certificate, timestamp_private_key)
    issuer, serial, certificate_der = _certificate_issuer_and_serial(tsa_certificate)
    imprint = hashlib.sha256(signer_signature).digest()
    generated = datetime.now(timezone.utc)
    generalized_time = generated.strftime("%Y%m%d%H%M%SZ").encode("ascii")
    tst_info = _der_sequence(
        _der_integer(1),
        _der_encode_oid("1.3.6.1.4.1.694.2.2.1.1"),
        _der_sequence(_der_algorithm_identifier(_OID_SHA256), _der_encode(0x04, imprint)),
        _der_integer(int.from_bytes(os.urandom(8), "big")),
        _der_encode(0x18, generalized_time),
    )
    certificate_hash = hashlib.sha1(certificate_der).digest()
    signed_attributes = _der_set(
        _der_attribute(_OID_CONTENT_TYPE, _der_encode_oid(_OID_TST_INFO)),
        _der_attribute(_OID_MESSAGE_DIGEST, _der_encode(0x04, hashlib.sha256(tst_info).digest())),
        _der_attribute(_OID_SIGNING_TIME, _der_encode(0x18, generalized_time)),
        _der_attribute(_OID_SIGNING_CERTIFICATE,
                       _der_sequence(_der_sequence(_der_encode(0x04, certificate_hash)))),
    )
    token_signature = tsa_key.sign(
        signed_attributes, padding.PKCS1v15(), hashes.SHA256())
    token_signer = _der_sequence(
        _der_integer(1), _der_sequence(issuer, _der_integer(serial)),
        _der_algorithm_identifier(_OID_SHA256),
        _der_encode(0xa0, _der_tlv(signed_attributes)[1]),
        _der_algorithm_identifier(_OID_RSA_ENCRYPTION),
        _der_encode(0x04, token_signature),
    )
    token_signed_data = _der_sequence(
        _der_integer(3), _der_set(_der_algorithm_identifier(_OID_SHA256)),
        _der_sequence(_der_encode_oid(_OID_TST_INFO),
                      _der_encode(0xa0, _der_encode(0x04, tst_info))),
        _der_encode(0xa0, certificate_der),
        _der_set(token_signer),
    )
    return _der_sequence(_der_encode_oid(_OID_SIGNED_DATA),
                         _der_encode(0xa0, token_signed_data))


def _add_local_timestamp_token(cms_signature, certificate, private_key,
                               timestamp_certificate=None, timestamp_private_key=None):
    """Add a local RFC3161 token to a detached CMS signature."""
    content_info = _der_tlv(cms_signature)[1]
    content_children = _der_children(content_info)
    signed_data = _der_tlv(content_children[1][1])[1]
    signed_children = _der_children(signed_data)
    signer_set = signed_children[-1]
    signer_info = _der_children(_der_children(signer_set[1])[0][1])
    token = _timestamp_token(cms_signature, certificate, private_key,
                             timestamp_certificate, timestamp_private_key)
    timestamp_attribute = _der_attribute(_OID_TIMESTAMP_TOKEN, token)
    unsigned_attributes = _der_encode(0xa1, timestamp_attribute)
    updated_signer = _der_sequence(*(tuple(item[2] for item in signer_info) + (unsigned_attributes,)))
    updated_signers = _der_encode(0x31, updated_signer)
    updated_signed_data = _der_sequence(
        *(tuple(item[2] for item in signed_children[:-1]) + (updated_signers,)))
    return _der_sequence(content_children[0][2], _der_encode(0xa0, updated_signed_data))


def normalize_manifest_path(value):
    """Return a safe, POSIX-normalized archive path."""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SAPCARManifestError("manifest path is not UTF-8") from exc
    if not isinstance(value, str) or not value or "\x00" in value:
        raise SAPCARManifestError("invalid manifest path")
    value = value.replace("\\", "/")
    if value.startswith("/") or re.match(r"^[A-Za-z]:/", value):
        raise SAPCARManifestError("unsafe absolute manifest path")
    normalized = posixpath.normpath(value)
    if normalized in ("", ".") or normalized == ".." or normalized.startswith("../"):
        raise SAPCARManifestError("unsafe manifest path")
    return normalized


@dataclass
class ManifestEntry:
    filename: str
    size: int = None
    digest_algorithm: str = None
    digest: str = None
    metadata: dict = field(default_factory=dict)
    signature: dict = None

    def as_dict(self):
        return {"filename": self.filename, "size": self.size,
                "digest_algorithm": self.digest_algorithm, "digest": self.digest,
                "metadata": dict(sorted(self.metadata.items())),
                "signature": self.signature}


@dataclass
class SAPCARManifest:
    name: str = None
    version: str = None
    digest_algorithm: str = None
    entries: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    signature: dict = None
    raw: bytes = b""
    signed_data: bytes = b""
    signature_data: bytes = b""

    @classmethod
    def from_bytes(cls, data, name=None):
        """Parse manifest bytes into a manifest instance."""
        return _parse_manifest(data, name, manifest_class=cls)

    def verify_signature(self, trust_store=None, certificate_dir=None):
        """Verify the detached signature using explicit or embedded trust."""
        if not self.signature_data or not self.signed_data:
            return "unsupported"
        return _verify_pkcs7(
            self, trust_store=trust_store, certificate_dir=certificate_dir)

    def as_dict(self):
        return {"name": self.name, "version": self.version,
                "digest_algorithm": self.digest_algorithm,
                "metadata": dict(sorted(self.metadata.items())),
                "entries": [entry.as_dict() for entry in self.entries],
                "signature": self.signature}


_DIGEST_NAMES = {"md5": "md5", "sha1": "sha1", "sha-1": "sha1",
                 "sha256": "sha256", "sha-256": "sha256", "sha512": "sha512",
                 "sha-512": "sha512"}


def _algorithm(value):
    value = str(value).strip().lower().replace("_", "-")
    value = value.replace("sha-", "sha") if value.startswith("sha-") else value
    if value not in ("md5", "sha1", "sha256", "sha512"):
        raise SAPCARManifestError("unsupported digest algorithm: %s" % value)
    return value


def _digest(value, algorithm):
    value = value.strip().lower()
    expected = hashlib.new(algorithm).digest_size * 2
    if len(value) != expected or not re.match(r"^[0-9a-f]+$", value):
        raise SAPCARManifestError("invalid %s digest" % algorithm)
    return value


def _entry_from_mapping(mapping, default_algorithm=None, section=None):
    lower = {str(k).strip().lower(): str(v).strip() for k, v in mapping.items()}
    filename = (lower.get("filename") or lower.get("name") or lower.get("path") or
                (section if section and section.lower() not in ("manifest", "metadata") else None))
    if not filename:
        raise SAPCARManifestError("manifest section has no filename")
    filename = normalize_manifest_path(filename)
    size = lower.get("size") or lower.get("length")
    if size is not None:
        try:
            size = int(size, 0)
            if size < 0:
                raise ValueError
        except ValueError as exc:
            raise SAPCARManifestError("invalid size for %s" % filename) from exc
    algorithm = lower.get("digest-algorithm") or lower.get("algorithm") or default_algorithm
    digest = lower.get("digest")
    for key, value in lower.items():
        if key in _DIGEST_NAMES:
            algorithm, digest = _DIGEST_NAMES[key], value
            break
    if digest is not None:
        if not algorithm:
            algorithm = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}.get(len(digest))
        if not algorithm:
            raise SAPCARManifestError("digest algorithm is missing for %s" % filename)
        algorithm = _algorithm(algorithm)
        digest = _digest(digest, algorithm)
    known = {"filename", "name", "path", "size", "length", "digest",
             "digest-algorithm", "algorithm", "md5", "sha1", "sha-1",
             "sha256", "sha-256", "sha512", "sha-512"}
    return ManifestEntry(filename, size, algorithm, digest,
                         {k: v for k, v in lower.items() if k not in known})


def _parse_manifest(data, name=None, manifest_class=SAPCARManifest):
    """Parse SAP-MANIFEST or section/key manifest bytes."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not isinstance(data, bytes):
        raise SAPCARManifestError("manifest must be bytes")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SAPCARManifestError("manifest is not UTF-8") from exc
    lines = text.splitlines()
    manifest = manifest_class(name=name, raw=data)
    if lines and lines[0].strip().upper() == "SAP-MANIFEST":
        headers = {}
        body = False
        for line in lines[1:]:
            stripped = line.strip()
            if not stripped:
                body = True
                continue
            if not body and ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
                continue
            if stripped.startswith("-----BEGIN SIGNATURE-----"):
                marker = "-----BEGIN SIGNATURE-----"
                before, after = text.split(marker, 1)
                encoded = after.split("-----END SIGNATURE-----", 1)[0]
                try:
                    manifest.signature_data = base64.b64decode("".join(encoded.split()), validate=True)
                except (ValueError, binascii.Error) as exc:
                    raise SAPCARManifestError("invalid signature encoding") from exc
                manifest.signed_data = before.encode("utf-8")
                manifest.signature = {"status": "unsupported", "format": "PKCS7"}
                break
            fields = stripped.split(None, 2)
            if len(fields) != 3 or not re.match(r"^[0-9a-fA-F]+$", fields[0]):
                raise SAPCARManifestError("malformed SAP manifest entry")
            digest, length, filename = fields
            try:
                if int(length, 16) != len(filename.encode("utf-8")):
                    raise SAPCARManifestError("manifest name length mismatch")
            except ValueError as exc:
                raise SAPCARManifestError("invalid manifest name length") from exc
            algorithm = _algorithm(headers.get("hash", "sha256"))
            manifest.entries.append(ManifestEntry(normalize_manifest_path(filename),
                                                  None, algorithm, _digest(digest, algorithm)))
        manifest.version = headers.get("version")
        manifest.digest_algorithm = _algorithm(headers.get("hash", "sha256"))
        if headers.get("signature"):
            manifest.signature = {"status": "unsupported",
                                  "format": headers["signature"]}
        manifest.metadata = {k: v for k, v in headers.items()
                             if k not in ("version", "hash", "signature", "body")}
    else:
        sections, current, values = [], None, {}
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith(";"):
                continue
            if stripped.startswith("["):
                if not stripped.endswith("]"):
                    raise SAPCARManifestError("malformed manifest section")
                if current is not None:
                    sections.append((current, values))
                current, values = stripped[1:-1].strip(), {}
            elif "=" in line or ":" in line:
                separator = "=" if "=" in line else ":"
                key, value = line.split(separator, 1)
                if not key.strip() or key.strip().lower() in values:
                    raise SAPCARManifestError("duplicate manifest key")
                values[key.strip()] = value.strip()
            else:
                raise SAPCARManifestError("malformed manifest line")
        if current is not None:
            sections.append((current, values))
        for section, values in sections:
            lower = {k.lower(): v for k, v in values.items()}
            if section.lower() in ("manifest", "metadata"):
                manifest.version = lower.get("version", manifest.version)
                manifest.digest_algorithm = lower.get("digest-algorithm", lower.get("algorithm", manifest.digest_algorithm))
                manifest.metadata.update(values)
            else:
                entry = _entry_from_mapping(values, manifest.digest_algorithm, section)
                manifest.entries.append(entry)
    seen = set()
    for entry in manifest.entries:
        if entry.filename in seen:
            raise SAPCARManifestError("duplicate manifest entry: %s" % entry.filename)
        seen.add(entry.filename)
    return manifest


_OID_DIGESTS = {
    "1.2.840.113549.2.5": hashes.MD5,
    "1.3.14.3.2.26": hashes.SHA1,
    "2.16.840.1.101.3.4.2.1": hashes.SHA256,
    "2.16.840.1.101.3.4.2.3": hashes.SHA512,
}
_OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"


def _der_tlv(data, offset=0):
    try:
        tag, start, body_start, body_end, end = asn1_read_tlv(data, offset)
    except (ASN1_Error, IndexError, TypeError) as exc:
        raise SAPCARManifestError("invalid DER value: %s" % exc) from exc
    return tag, data[body_start:body_end], data[start:end], end


def _der_children(data):
    children = []
    offset = 0
    while offset < len(data):
        tag, body, encoded, offset = _der_tlv(data, offset)
        children.append((tag, body, encoded))
    return children


def _der_oid(data):
    try:
        return asn1_decode_oid(_der_encode(0x06, data))
    except (ASN1_Error, IndexError, TypeError) as exc:
        raise SAPCARManifestError("invalid DER OID: %s" % exc) from exc


def _load_certificates(filename=None, directory=None, implicit_certificate=None):
    sources = []
    if filename:
        sources.append(filename)
    if directory:
        sources.extend(sorted(glob.glob(os.path.join(directory, "*"))))
    certificates = []
    if not sources and implicit_certificate:
        certificates.append(x509.load_pem_x509_certificate(implicit_certificate))
    for source in sources:
        try:
            with open(source, "rb") as fd:
                data = fd.read()
        except OSError:
            continue
        chunks = re.findall(br"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.DOTALL)
        if chunks:
            for chunk in chunks:
                try:
                    certificates.append(x509.load_pem_x509_certificate(chunk))
                except ValueError:
                    continue
        else:
            try:
                certificates.append(x509.load_der_x509_certificate(data))
            except ValueError:
                continue
    return certificates


def _certificate_signature_valid(child, issuer):
    try:
        key = issuer.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(child.signature, child.tbs_certificate_bytes,
                       padding.PKCS1v15(), child.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(child.signature, child.tbs_certificate_bytes,
                       ec.ECDSA(child.signature_hash_algorithm))
        else:
            return False
    except (ValueError, TypeError, exceptions.InvalidSignature):
        return False
    return True


def _trusted_certificate(signer, trust):
    for anchor in trust:
        if signer.fingerprint(hashes.SHA256()) == anchor.fingerprint(hashes.SHA256()):
            return True
        if signer.issuer == anchor.subject and _certificate_signature_valid(signer, anchor):
            return True
    return False


def _verify_timestamp_token(token, signature, trust):
    """Verify the RFC3161 token attached to a SAPCAR CMS signature."""
    try:
        token_content = _der_tlv(token)[1]
        token_signed_data = _der_tlv(_der_children(token_content)[1][1])[1]
        token_parts = _der_children(token_signed_data)
        token_content_info = _der_children(token_parts[2][1])
        if _der_oid(token_content_info[0][1]) != "1.2.840.113549.1.9.16.1.4":
            return "invalid"
        tst_info_encoded = _der_tlv(_der_tlv(token_content_info[1][1])[1])[2]
        tst_info = _der_tlv(tst_info_encoded)[1]
        tst_parts = _der_children(tst_info)
        imprint_parts = _der_children(tst_parts[2][1])
        digest_oid = _der_oid(_der_children(imprint_parts[0][1])[0][1])
        if digest_oid not in _OID_DIGESTS:
            return "invalid"
        digest_type = _OID_DIGESTS[digest_oid]
        digest = hashes.Hash(digest_type())
        digest.update(signature)
        if digest.finalize() != imprint_parts[1][1]:
            return "invalid"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            certificates = pkcs7.load_der_pkcs7_certificates(token)
        certificate_set = next(item for item in token_parts if item[0] == 0xa0)
        if not certificates or not certificate_set:
            return "invalid"
        token_signer_info = _der_children(_der_children(token_parts[-1][1])[0][1])
        signer_identifier = _der_children(token_signer_info[1][1])
        serial = int.from_bytes(signer_identifier[1][1], "big")
        signer = next(cert for cert in certificates if cert.serial_number == serial)
        attributes = next(item for item in token_signer_info if item[0] == 0xa0)
        signed_attributes = _der_encode(0x31, attributes[1])
        message_digest = None
        for attribute in _der_children(attributes[1]):
            attribute_parts = _der_children(attribute[1])
            if _der_oid(attribute_parts[0][1]) == _OID_MESSAGE_DIGEST:
                message_digest = _der_children(attribute_parts[1][1])[0][1]
                break
        digest = hashes.Hash(digest_type())
        digest.update(tst_info_encoded)
        if message_digest != digest.finalize():
            return "invalid"
        token_signature = next(item[1] for item in reversed(token_signer_info) if item[0] == 0x04)
        signer.public_key().verify(token_signature, signed_attributes,
                                   padding.PKCS1v15(), digest_type())
        return "valid" if _trusted_certificate(signer, trust) else "unverified"
    except (IndexError, StopIteration, ValueError, TypeError,
            exceptions.UnsupportedAlgorithm, exceptions.InvalidSignature):
        return "invalid"


def _verify_pkcs7(manifest, trust_store=None, certificate_dir=None):
    """Verify SAP's detached CMS signature using cryptography primitives."""
    try:
        content_info = _der_tlv(manifest.signature_data)[1]
        content = _der_children(content_info)[1][1]
        signed_data = _der_tlv(content)[1]
        signed_children = _der_children(signed_data)
        encap_index = 2
        signer_set = next(item for item in reversed(signed_children) if item[0] == 0x31)
        certificate_set = next((item for item in signed_children[encap_index + 1:]
                                if item[0] == 0xa0), None)
        if certificate_set is None:
            return "unsupported"
        certificates = pkcs7.load_der_pkcs7_certificates(manifest.signature_data)
        signer_info = _der_children(signer_set[1])[0]
        signer_parts = _der_children(signer_info[1])
        signer_identifier = _der_children(signer_parts[1][1])
        serial = int.from_bytes(signer_identifier[1][1], "big")
        signer = next((cert for cert in certificates if cert.serial_number == serial), None)
        if signer is None:
            return "unsupported"
        digest_algorithm = _der_children(signer_parts[2][1])[0]
        digest_type = _OID_DIGESTS.get(_der_oid(digest_algorithm[1]))
        if digest_type is None:
            return "unsupported"
        attributes = next((item for item in signer_parts if item[0] == 0xa0), None)
        if attributes is None:
            return "unsupported"
        # Re-tag the IMPLICIT [0] attribute set as a universal SET while
        # retaining its exact DER ordering and encoding.
        attr_length = len(attributes[1])
        if attr_length < 0x80:
            signed_attributes = bytes([0x31, attr_length]) + attributes[1]
        else:
            encoded_length = attr_length.to_bytes((attr_length.bit_length() + 7) // 8, "big")
            signed_attributes = bytes([0x31, 0x80 | len(encoded_length)]) + encoded_length + attributes[1]
        message_digest = None
        for attribute in _der_children(attributes[1]):
            parts = _der_children(attribute[1])
            if _der_oid(parts[0][1]) == _OID_MESSAGE_DIGEST:
                message_digest = _der_children(parts[1][1])[0][1]
                break
        digest = hashes.Hash(digest_type())
        digest.update(manifest.signed_data)
        if message_digest != digest.finalize():
            return "invalid"
        signature_index = next(index for index, item in enumerate(signer_parts)
                               if item[0] == 0x30 and index > 2)
        signature = signer_parts[signature_index + 1][1]
        key = signer.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, signed_attributes, padding.PKCS1v15(), digest_type())
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, signed_attributes, ec.ECDSA(digest_type()))
        else:
            return "unsupported"
        timestamp_attribute = None
        unsigned_attributes = next((item for item in signer_parts if item[0] == 0xa1), None)
        if unsigned_attributes is not None:
            for attribute in _der_children(unsigned_attributes[1]):
                attribute_parts = _der_children(attribute[1])
                if _der_oid(attribute_parts[0][1]) == _OID_TIMESTAMP_TOKEN:
                    timestamp_attribute = _der_children(attribute_parts[1][1])[0][2]
                    break
        if timestamp_attribute is None:
            return "invalid"
        timestamp_trust = _load_certificates(
            trust_store, certificate_dir, SAP_TSA_CERTIFICATE_PEM)
        if not timestamp_trust:
            return "unverified"
        timestamp_status = _verify_timestamp_token(
            timestamp_attribute, signature, timestamp_trust)
        if timestamp_status == "invalid":
            return "invalid"
        if timestamp_status != "valid":
            return "unverified"
    except (IndexError, StopIteration, ValueError, TypeError,
            exceptions.UnsupportedAlgorithm, exceptions.InvalidSignature):
        return "invalid"
    trust = _load_certificates(
        trust_store, certificate_dir, SAP_TRUST_CERTIFICATE_PEM)
    if not trust:
        return "unverified"
    return "valid" if _trusted_certificate(signer, trust) else "unverified"


def is_manifest_name(filename):
    name = filename.decode("utf-8", "replace") if isinstance(filename, bytes) else filename
    return name.replace("\\", "/").rsplit("/", 1)[-1].upper() in ("MANIFEST", "MANIFEST.MF", "SIGNATURE.SMF")
