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

"""SAP NetWeaver RFC (NWRFC) protocol constants and TLV parser.

The NetWeaver RFC SDK (libsapnwrfc) is the modern SAP client library used by
pyrfc, SAP JCo, SAP .NET Connector, and the SAP ABAP kernel's own outbound
RFC stack.  It differs from the classic SAPRFC/CPIC framing (see
:mod:`pysap.SAPRFC`) in two key areas:

1. **Different magic bytes**: NWRFC frames begin with ``\\x06\\xcb\\x02\\x00``
   rather than the classic ``\\x06\\x03\\x02\\x00``.

2. **TLV encoding**: All fields (username, password, function module name,
   client, language, hostname, …) are carried in a Type-Length-Value (TLV)
   stream using 2-byte big-endian tags and 2-byte big-endian lengths.
   Values are encoded in **UTF-16LE**.

Both frame types are transported inside SAP NI framing (4-byte big-endian
payload length prefix) on the same RFC ports (default: TCP/3300).

TLV tag assignments
-------------------
The tag-to-semantic mapping below was determined by analysis of live packet
captures from multiple NWRFC SDK clients (pyrfc 3.x, npl_rfc, SAP ABAP
kernel).  Tags not listed here are observed in captures but their semantics
are not yet confirmed.

.. code-block:: text

    Tag     Semantic                 Encoding    Size (bytes, typ./max.)
    ------  -----------------------  ----------  -----------------------
    0x0006  RFC destination name     UTF-16LE    2 – 40
    0x0007  Client IP address        UTF-16LE    4 – 32
    0x0008  Server hostname          UTF-16LE    8 – 120
    0x0009  Username (tertiary)      UTF-16LE    4 – 48
    0x0100  Program / task name      UTF-16LE    10 – 120
    0x0102  Function module name     UTF-16LE    8 – 80
    0x0111  Username (primary)       UTF-16LE    4 – 48
    0x0114  SAP client number        UTF-16LE    2 – 8   ("001", "100", …)
    0x0117  ab_scramble password     binary      6 – 84  [4B LE seed][UTF-16LE]
    0x0119  Username (secondary)     UTF-16LE    4 – 48
    0x0152  Language key             UTF-16LE    2 – 4   ("E", "D", …)
    0x0201  RFC param name           UTF-16LE    2 – 120
    0x0203  RFC param value          UTF-16LE    variable

Password field (tag 0x0117)
---------------------------
The password TLV value is a raw binary field, **not** a UTF-16LE string::

    [ 4 bytes little-endian seed ][ N×2 bytes ab_scrambled UTF-16LE payload ]

Total field length = 4 + (password_length × 2).  Minimum length is 6 bytes
(seed + one UTF-16LE character).  Use :func:`pysap.utils.crypto.rfc.ab_descramble`
with ``encoding="utf-16-le"`` to recover the plaintext.

Hostname / SID extraction
-------------------------
The server hostname value (tag ``0x0008``) frequently encodes the SAP System
ID (SID) in the pattern ``<hostname>_<SID>_<instance_number>``, for example
``sapnw752_NPL_00``.  The regex :data:`NWRFC_SID_RE` matches this pattern.

References
----------
* Protocol reverse-engineered from libsapnwrfc (SAP NetWeaver RFC SDK).
* TLV tag assignments confirmed from live PCAP captures.
* See also: :mod:`pysap.SAPRFC` for classic RFC/CPIC framing.
"""

# Standard imports
import html
import re
import struct


# ── Frame identification ──────────────────────────────────────────────────────

#: Magic bytes that identify an NWRFC frame (bytes 0-3 of the NI payload).
#: Classic SAPRFC frames use ``b'\\x06\\x03\\x02\\x00'`` instead.
NWRFC_MAGIC = b'\x06\xcb\x02\x00'

#: Magic bytes for classic SAPRFC/CPIC frames, shown here for comparison.
SAPRFC_MAGIC = b'\x06\x03\x02\x00'


# ── TLV structure ─────────────────────────────────────────────────────────────

#: Size of a TLV header in bytes (2-byte tag + 2-byte length, both big-endian).
NWRFC_TLV_HEADER_SIZE = 4

#: Confirmed NWRFC TLV tag assignments.
#: Keys are integer tag values; values are human-readable semantic names.
#: All string values are encoded in UTF-16LE unless noted otherwise.
NWRFC_TAGS = {
    0x0006: "dest",             # RFC destination name
    0x0007: "ip",               # Client IP address (text form)
    0x0008: "hostname",         # Server hostname; contains _SID_NN pattern
    0x0009: "username",         # SAP username (tertiary tag)
    0x0100: "program",          # Program / task handler name
    0x0102: "function_module",  # RFC function module name
    0x0111: "username",         # SAP username (primary logon tag)
    0x0114: "client",           # SAP client number ("001", "100", …)
    0x0117: "password",         # ab_scramble field: [4B seed][UTF-16LE bytes]
    0x0119: "username",         # SAP username (secondary tag)
    0x0152: "language",         # Language key ("E", "D", …)
    0x0201: "param_name",       # RFC call parameter name
    0x0203: "param_value",      # RFC call parameter value
}

#: Username tags, in priority order (highest priority first).
#: When multiple username tags are present the highest-priority non-empty
#: value should be used.
NWRFC_USERNAME_TAGS = (0x0111, 0x0119, 0x0009)

#: Per-tag minimum and maximum *value* length in bytes (before decoding).
#: Used to reject spurious TLV matches during scanning.
NWRFC_TAG_CONSTRAINTS = {
    0x0006: (2,   40),   # dest
    0x0007: (4,   32),   # ip
    0x0008: (4,  120),   # hostname
    0x0009: (4,   48),   # username (tertiary)
    0x0100: (10, 120),   # program
    0x0102: (8,   80),   # function module
    0x0111: (4,   48),   # username (primary)
    0x0114: (2,    8),   # client
    0x0117: (6,   84),   # password (4-byte seed + scrambled UTF-16LE)
    0x0119: (4,   48),   # username (secondary)
    0x0152: (2,    4),   # language
    0x0201: (2,  120),   # param_name
    # 0x0203 (param_value): no constraint, value length varies widely
    # (scalars to large XML table fragments).
}

#: Minimum byte count of the ab_scramble seed prefix inside a password field.
NWRFC_PASSWORD_SEED_SIZE = 4

#: Regex that extracts the SAP System ID (SID) from a server hostname value.
#: Matches the ``_SID_NN`` suffix, e.g. ``sapnw752_NPL_00`` → ``NPL``.
NWRFC_SID_RE = re.compile(r'_([A-Z][A-Z0-9]{2})_\d{2}(?:\s|$)')


# ── TLV parser ────────────────────────────────────────────────────────────────

def parse_tlv(data, tags=None):
    """Parse NWRFC TLV fields from a raw byte buffer.

    Scans *data* for TLV entries whose 2-byte big-endian tag appears in
    *tags* (or in :data:`NWRFC_TAGS` when *tags* is ``None``).  Length
    constraints from :data:`NWRFC_TAG_CONSTRAINTS` are enforced to suppress
    false positives; unrecognised or out-of-range entries are skipped.

    The buffer does **not** need to start at a TLV boundary — the function
    searches forward byte-by-byte, which handles frames where the TLV stream
    is preceded by other header fields.

    Args:
        data (bytes): Raw frame payload (NI payload, without the 4-byte NI
            length header).
        tags (collection | None): Iterable of integer tag values to extract.
            Defaults to all keys in :data:`NWRFC_TAGS`.

    Yields:
        tuple[int, bytes]: ``(tag, raw_value)`` pairs in the order they
        appear in *data*.  The caller is responsible for decoding *raw_value*
        (typically ``raw_value.decode("utf-16-le").rstrip("\\x00")`` for
        string fields, or passing to
        :func:`pysap.utils.crypto.rfc.ab_descramble` for the password tag).

    Example::

        >>> from pysap.SAPNWRFC import parse_tlv, NWRFC_TAGS
        >>> for tag, value in parse_tlv(frame_data):
        ...     print(hex(tag), NWRFC_TAGS.get(tag), value)
    """
    if tags is None:
        tags = set(NWRFC_TAGS)
    else:
        tags = set(tags)

    total = len(data)
    off = 0

    while off + NWRFC_TLV_HEADER_SIZE <= total:
        tag = struct.unpack_from(">H", data, off)[0]
        length = struct.unpack_from(">H", data, off + 2)[0]

        if tag not in tags:
            off += 1
            continue

        constraints = NWRFC_TAG_CONSTRAINTS.get(tag)
        if constraints:
            min_len, max_len = constraints
            if not (min_len <= length <= max_len):
                off += 1
                continue

        end = off + NWRFC_TLV_HEADER_SIZE + length
        if end > total:
            off += 1
            continue

        yield tag, data[off + NWRFC_TLV_HEADER_SIZE: end]
        off = end


def find_tlv_field_by_marker(data, marker, search_start=0):
    """Find a TLV field by its 2-byte tag, scanning byte-by-byte.

    This is an alternative to :func:`parse_tlv` for buffers where the field
    order varies across NWRFC SDK versions and :func:`parse_tlv`'s
    sequential scan may miss a field that is preceded by an unrecognised
    or misaligned entry.  It scans for any 4-byte delimiter of the form
    ``[2-byte end-of-prev][2-byte tag]`` followed by a 2-byte big-endian
    length, i.e.::

        [end-of-prev (2)][tag (2)][length (2)][value (length)]

    Args:
        data (bytes): Raw frame payload to scan.
        marker (int | bytes): Tag to search for, either as an integer (e.g.
            ``0x0117``) or as 2 raw bytes (e.g. ``b"\\x01\\x17"``).
        search_start (int): Offset to start scanning from.

    Returns:
        tuple[bytes | None, int]: ``(value, end_offset)`` if found, where
        *end_offset* is the offset just past the value (suitable as
        *search_start* for a subsequent call); otherwise ``(None,
        search_start)``.
    """
    if isinstance(marker, int):
        marker = struct.pack(">H", marker)

    idx = search_start
    while idx < len(data) - 7:
        if data[idx + 2:idx + 4] == marker:
            length = struct.unpack(">H", data[idx + 4:idx + 6])[0]
            end = idx + 6 + length
            if length > 0 and end <= len(data):
                return data[idx + 6:end], end
        idx += 1
    return None, search_start


def find_tlv_field_by_padd(data, padd):
    """Find a TLV field by its full 4-byte padding marker.

    The 4-byte *padd* value encodes ``[end-of-prev-field (2)][tag (2)]`` and
    only matches when the immediately preceding field is the one the caller
    expects, making this more precise than :func:`find_tlv_field_by_marker`
    when the field order is known and fixed.

    Layout::

        [padd (4)][length (2, big-endian)][value (length)]

    Args:
        data (bytes): Raw frame payload to scan.
        padd (bytes): 4-byte padding marker to search for.

    Returns:
        bytes | None: The value bytes, or ``None`` if not found or invalid.
    """
    idx = data.find(padd)
    if idx < 0:
        return None
    offset = idx + len(padd)
    if offset + 2 > len(data):
        return None
    length = struct.unpack(">H", data[offset:offset + 2])[0]
    if length == 0 or offset + 2 + length > len(data):
        return None
    return data[offset + 2:offset + 2 + length]


def decode_string(raw):
    """Decode a UTF-16LE TLV value, stripping null and space padding.

    Args:
        raw (bytes): Raw TLV value bytes.

    Returns:
        str: Decoded string, or an empty string if decoding fails.
    """
    try:
        return raw.decode("utf-16-le").rstrip("\x00 ")
    except (UnicodeDecodeError, ValueError):
        return ""


def decode_value(raw):
    """Decode a TLV value of unknown encoding, trying UTF-16LE then ASCII.

    Most NWRFC TLV values are UTF-16LE (see :func:`decode_string`), but some
    fields observed in F_SAP_SEND bodies (e.g. CPIC marker fields on older
    SDK versions) are plain ASCII.  This heuristically picks UTF-16LE when
    *raw* "looks like" UTF-16LE (every other byte is ``0x00``, as is the
    case for ASCII-range characters encoded that way), falling back to
    ASCII (with replacement of invalid bytes) otherwise.

    Args:
        raw (bytes | None): Raw TLV value bytes.

    Returns:
        str | None: Decoded string with null/space padding stripped, or
        ``None`` if *raw* is ``None``.
    """
    if raw is None:
        return None

    if len(raw) >= 4 and raw[1:2] == b"\x00" and raw[3:4] == b"\x00":
        try:
            return raw.decode("utf-16-le").strip("\x00 ")
        except (UnicodeDecodeError, ValueError):
            pass

    return raw.decode("ascii", errors="replace").strip("\x00 ")


# ── RFC call payload extraction ─────────────────────────────────────────────

#: Pattern for valid RFC parameter names: alphanumeric plus "_" and "/"
#: (used to reject spurious 0x0201 matches that aren't real parameter names).
_RFC_PARAM_NAME_RE = re.compile(r"^[A-Za-z0-9_/]+$")


def extract_rfc_params(raw):
    """Extract RFC function call parameters from an F_SAP_SEND body.

    Scans for ``0x0201`` (param_name) TLVs carrying a valid identifier, then
    reads the immediately following ``0x0203`` (param_value) TLV via
    :func:`find_tlv_field_by_marker`.

    Args:
        raw (bytes): Raw F_SAP_SEND body to scan.

    Returns:
        dict[str, str]: Mapping of parameter name to decoded value, in the
        order they appear in *raw*.
    """
    name_min, name_max = NWRFC_TAG_CONSTRAINTS[0x0201]
    name_tag = struct.pack(">H", 0x0201)

    params = {}
    idx = 0
    while idx < len(raw) - 7:
        if raw[idx + 2:idx + 4] == name_tag:
            name_len = struct.unpack(">H", raw[idx + 4:idx + 6])[0]
            name_end = idx + 6 + name_len
            if name_min <= name_len <= name_max and name_end <= len(raw):
                name = decode_value(raw[idx + 6:name_end])
                if name and _RFC_PARAM_NAME_RE.match(name):
                    val, _ = find_tlv_field_by_marker(raw, 0x0203, name_end)
                    if val:
                        decoded = decode_value(val)
                        if decoded is not None:
                            params[name] = decoded
        idx += 1
    return params


#: Matches top-level ``<TAG>...</TAG>`` blocks (and nested ``<item>`` blocks)
#: in an RFC call's XML-serialised table/structure parameters.
_XML_TAG_RE = re.compile(r"<([A-Z_/][A-Z0-9_/]*)>(.*?)</\1>", re.DOTALL)
_XML_ITEM_RE = re.compile(r"<item>(.*?)</item>", re.DOTALL)


def extract_xml_data(raw):
    """Extract XML-encoded parameters and table rows from an RFC call body.

    The NetWeaver RFC SDK serialises table/structure parameters as ASCII XML
    fragments embedded in the F_SAP_SEND body, e.g.::

        <IT_MODULE><item><FIELD>value</FIELD></item></IT_MODULE>
        <IV_GUID>base64==</IV_GUID>

    Args:
        raw (bytes): Raw F_SAP_SEND body. Everything before the first ``<``
            is treated as binary and ignored; the remainder is decoded as
            ASCII (XML is always ASCII in NWRFC).

    Returns:
        dict[str, str | list]: Mapping of parameter name to value, where
        value is either a plain string (scalar) or a list of rows (table
        parameter). Table rows are dicts of sub-field name to value, except
        rows of a single unnamed field which are returned as plain strings.
        A sub-field whose value itself contains ``<item>`` entries (nested
        table, e.g. ABAP source lines) is returned as a list of strings —
        but note rows containing a *nested* ``<item>``-bearing sub-field are
        not split correctly, as the non-greedy outer ``<item>`` match ends
        at the first inner ``</item>``.
    """
    result = {}
    raw_bytes = bytes(raw)

    xml_start = raw_bytes.find(b"<")
    if xml_start == -1:
        return result

    try:
        xml_region = raw_bytes[xml_start:].decode("ascii", errors="replace")
    except Exception:
        return result

    for m in _XML_TAG_RE.finditer(xml_region):
        tag, content = m.group(1), m.group(2)
        if len(tag) < 2:
            continue
        content = content.strip()

        if "<item>" in content:
            rows = []
            for item_m in _XML_ITEM_RE.finditer(content):
                item_body = item_m.group(1).strip()
                if "<" in item_body:
                    row = {}
                    for fld in _XML_TAG_RE.finditer(item_body):
                        fname, fval = fld.group(1), fld.group(2)
                        if "<item>" in fval:
                            row[fname] = [html.unescape(li.group(1))
                                          for li in _XML_ITEM_RE.finditer(fval)]
                        else:
                            row[fname] = html.unescape(fval.strip())
                    if row:
                        rows.append(row)
                else:
                    rows.append(html.unescape(item_body))
            if rows:
                result[tag] = rows
        else:
            result[tag] = html.unescape(content)

    return result
