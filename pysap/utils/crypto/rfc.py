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
#   Code contributed by SecureAuth to the OWASP CBAS project
#

"""SAP RFC ab_scramble password obfuscation.

SAP's RFC layer uses a symmetric XOR-based obfuscation scheme called
*ab_scramble* to encode passwords on the wire in unencrypted (non-SNC)
RFC/CPIC connections.  The scheme is **not** a cryptographic hash — it is
fully reversible given only the ciphertext.

Wire format
-----------
The password field is always::

    [ 4-byte little-endian seed ][ obfuscated password bytes ]

The seed is chosen by the client at connection time.

Encoding variants
-----------------
Two client-side encodings are observed in practice:

* **ASCII** (classic SAPRFC / pyrfc): the plaintext password is encoded as
  ASCII bytes before obfuscation.  The descrambled result is decoded with
  ``"ascii"``.

* **UTF-16LE** (NetWeaver RFC SDK / npl_rfc / SAP JCo): the plaintext
  password is encoded as UTF-16LE before obfuscation.  The descrambled
  result must be decoded with ``"utf-16-le"``.  Callers must pass
  ``encoding="utf-16-le"`` explicitly.

References
----------
* Reverse-engineered from libsapnwrfc (SAP NWRFC SDK).
* Confirmed against live PCAP captures of pyrfc and npl_rfc clients.
"""

# Standard imports
import os
import struct


# 64-byte XOR lookup table extracted from libsapnwrfc (ab_scramble routine).
# This table is the sole secret of the scheme; it is static and embedded in
# every SAP client SDK that implements RFC.
_TABLE = bytes([
    0xf0, 0xed, 0x53, 0xb8, 0x32, 0x44, 0xf1, 0xf8,
    0x76, 0xc6, 0x79, 0x59, 0xfd, 0x4f, 0x13, 0xa2,
    0xc1, 0x51, 0x95, 0xec, 0x54, 0x83, 0xc2, 0x34,
    0x77, 0x49, 0x43, 0xa2, 0x7d, 0xe2, 0x65, 0x96,
    0x5e, 0x53, 0x98, 0x78, 0x9a, 0x17, 0xa3, 0x3c,
    0xd3, 0x83, 0xa8, 0xb8, 0x29, 0xfb, 0xdc, 0xa5,
    0x55, 0xd7, 0x02, 0x77, 0x84, 0x13, 0xac, 0xdd,
    0xf9, 0xb8, 0x31, 0x16, 0x61, 0x0e, 0x6d, 0xfa,
])

# Minimum field size: 4-byte seed + at least 1 password byte
_MIN_FIELD_SIZE = 5

# Maximum observed password length (SAP enforces 40 chars; UTF-16LE doubles bytes)
_MAX_PASSWORD_BYTES = 80


def ab_descramble(raw, encoding="ascii"):
    """Descramble an SAP RFC ab_scramble password field.

    Args:
        raw (bytes): Full password field — ``[4-byte LE seed][obfuscated bytes]``.
        encoding (str): Character encoding of the obfuscated payload.
            Use ``"ascii"`` (default) for classic SAPRFC / pyrfc clients.
            Use ``"utf-16-le"`` for NetWeaver RFC SDK (npl_rfc, JCo) clients.

    Returns:
        str: Plaintext password.

    Raises:
        ValueError: If *raw* is shorter than :data:`_MIN_FIELD_SIZE` bytes.
        UnicodeDecodeError: If the descrambled bytes cannot be decoded with
            the given *encoding*.

    Example::

        >>> from pysap.utils.crypto.rfc import ab_descramble
        >>> ab_descramble(bytes.fromhex("a3b7e05a3384be74606be2de"))
        'secret'
    """
    if len(raw) < _MIN_FIELD_SIZE:
        raise ValueError(
            "ab_scramble field too short: need at least {} bytes, got {}".format(
                _MIN_FIELD_SIZE, len(raw)
            )
        )

    seed = struct.unpack_from("<I", raw, 0)[0]
    data = bytearray(raw[4:])
    _apply_keystream(data, seed)

    if encoding == "utf-16-le":
        # Do NOT rstrip null bytes before decoding UTF-16LE: stripping a single
        # 0x00 byte from an even-length buffer produces an odd-length buffer,
        # which raises UnicodeDecodeError ("truncated data").  Decode first,
        # then strip null/space padding from the resulting string.
        return bytes(data).decode("utf-16-le").rstrip("\x00 ")
    return bytes(data).rstrip(b"\x00").decode(encoding)


def ab_scramble(password, seed=None, encoding="ascii"):
    """Scramble a plaintext password using SAP's ab_scramble algorithm.

    Args:
        password (str): Plaintext password to obfuscate (SAP enforces ≤ 40 chars).
        seed (int | None): 32-bit unsigned seed value.  A cryptographically
            random seed is generated when *seed* is ``None`` (default).
        encoding (str): Character encoding to apply to *password* before
            obfuscation.  Use ``"ascii"`` (default) for classic clients or
            ``"utf-16-le"`` for NetWeaver RFC SDK clients.

    Returns:
        bytes: Full password field — ``[4-byte LE seed][obfuscated bytes]``.

    Raises:
        UnicodeEncodeError: If *password* cannot be encoded with *encoding*.

    Example::

        >>> from pysap.utils.crypto.rfc import ab_scramble, ab_descramble
        >>> raw = ab_scramble("secret", seed=0x12345678)
        >>> ab_descramble(raw)
        'secret'
    """
    if seed is None:
        seed = struct.unpack("<I", os.urandom(4))[0]

    data = bytearray(password.encode(encoding))
    _apply_keystream(data, seed)
    return struct.pack("<I", seed) + bytes(data)


def _apply_keystream(data, seed):
    """Apply the ab_scramble XOR keystream to *data* in-place.

    The keystream is derived from *seed* and the static :data:`_TABLE`.
    The same function is used for both scrambling and descrambling (symmetric).

    Args:
        data (bytearray): Payload bytes to transform in-place.
        seed (int): 32-bit unsigned seed value.
    """
    tmp = (seed ^ (seed >> 5)) & 0xFFFFFFFF
    start_idx = (tmp ^ ((seed << 1) & 0xFFFFFFFF)) & 0xFFFFFFFF

    for i in range(len(data)):
        tidx = (start_idx + i) & 0x3F
        sval = ((seed * i * i) - i) & 0xFFFFFFFF
        data[i] ^= _TABLE[tidx] ^ (sval & 0xFF)
