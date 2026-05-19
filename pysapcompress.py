#!/usr/bin/env python3
# encoding: utf-8
# pysapcompress - Pure Python implementation of SAP LZH and LZC compression
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
# This is a port of the TypeScript sapcomp library by Max Jäger (xje4@xje4.dev),
# which itself was derived from the MaxDB compression code by SAP AG.
# Reference: https://git.sr.ht/~xje4/sapcomp
#
# The original C extension used CS_LZC=0x0 and CS_LZH=0x2 as algorithm selector
# constants passed to compress(). Those values are preserved here for API
# compatibility.

import struct
from array import array


# ---------------------------------------------------------------------------
# Public exceptions
# ---------------------------------------------------------------------------

class CompressError(Exception):
    """Raised when compression fails."""


class DecompressError(Exception):
    """Raised when decompression fails."""


# ---------------------------------------------------------------------------
# Algorithm selector constants (CS_LZC / CS_LZH from hpa104CsObject.h)
# ---------------------------------------------------------------------------

ALG_LZC = 0x0   # CS_LZC
ALG_LZH = 0x2   # CS_LZH

# Internal algorithm identifiers stored in the 8-byte compression header
_HDR_ALG_LZC = 1
_HDR_ALG_LZH = 2
_HDR_VERSION  = 1
_HDR_SIZE     = 8
_MAGIC        = b'\x1f\x9d'

# CS_END_OF_STREAM return code (success) from the original C library
_CS_END_OF_STREAM = 1


# ---------------------------------------------------------------------------
# Header helpers
# ---------------------------------------------------------------------------

def _parse_header(data):
    """Return (uncompressed_length, alg_id, alg_version, extra) from an 8-byte header."""
    if len(data) < _HDR_SIZE:
        raise DecompressError("invalid input length: header truncated")
    length = struct.unpack_from('<I', data, 0)[0]
    alg_byte = data[4]
    alg_id      = alg_byte & 0x0f
    alg_version = (alg_byte >> 4) & 0x0f
    magic       = bytes(data[5:7])
    extra       = data[7]
    if magic != _MAGIC:
        raise DecompressError("input not compressed: magic bytes not found")
    return length, alg_id, alg_version, extra


def _build_header(uncompressed_length, alg_id, alg_version, extra):
    """Return a packed 8-byte SAP compression header."""
    hdr = bytearray(_HDR_SIZE)
    struct.pack_into('<I', hdr, 0, uncompressed_length)
    hdr[4] = alg_id | (alg_version << 4)
    hdr[5] = _MAGIC[0]
    hdr[6] = _MAGIC[1]
    hdr[7] = extra & 0xff
    return bytes(hdr)


# ---------------------------------------------------------------------------
# I/O primitives
# ---------------------------------------------------------------------------

class _Reader:
    """Byte/bit reader backed by an immutable bytes-like buffer."""

    __slots__ = ('_data', '_pos', '_bits', '_bits_count')

    def __init__(self, data):
        self._data       = bytes(data)
        self._pos        = 0
        self._bits       = 0
        self._bits_count = 0

    @property
    def bytes_read(self):
        return self._pos

    @property
    def bytes_left(self):
        return len(self._data) - self._pos

    @property
    def end_reached(self):
        return self._pos >= len(self._data)

    @property
    def bits_left(self):
        return self.bytes_left * 8 + self._bits_count

    @property
    def total_length(self):
        return len(self._data)

    def read_byte(self):
        if self._bits_count > 0:
            raise RuntimeError("unfinished bit read pending")
        return self._read_byte()

    def _read_byte(self):
        if self._pos >= len(self._data):
            raise DecompressError("unexpected end of compressed data")
        b = self._data[self._pos]
        self._pos += 1
        return b

    def read(self, length):
        if self._bits_count > 0:
            raise RuntimeError("unfinished bit read pending")
        if self._pos + length > len(self._data):
            raise DecompressError("unexpected end of compressed data")
        chunk = self._data[self._pos:self._pos + length]
        self._pos += length
        return chunk

    def peek_bits(self, length):
        while self._bits_count < length:
            b = self._read_byte()
            self._bits |= b << self._bits_count
            self._bits_count += 8
        return self._bits & ((1 << length) - 1)

    def read_bits(self, length):
        value = self.peek_bits(length)
        self._bits >>= length
        self._bits_count -= length
        return value

    def skip_bits(self, length):
        self.read_bits(length)


class _Writer:
    """Byte/bit writer that accumulates output into a bytearray."""

    __slots__ = ('_buf', '_bits', '_bits_count')

    def __init__(self):
        self._buf        = bytearray()
        self._bits       = 0
        self._bits_count = 0

    @property
    def data(self):
        return bytes(self._buf)

    @property
    def bytes_written(self):
        return len(self._buf)

    def write(self, data):
        if self._bits_count > 0:
            raise RuntimeError("unfinished bit write pending")
        self._buf.extend(data)

    def write_byte(self, byte):
        if self._bits_count > 0:
            raise RuntimeError("unfinished bit write pending")
        self._buf.append(byte & 0xff)

    def _write_byte(self, byte):
        self._buf.append(byte & 0xff)

    def write_bits(self, value, bit_count):
        self._bits |= value << self._bits_count
        self._bits_count += bit_count
        while self._bits_count >= 8:
            self._buf.append(self._bits & 0xff)
            self._bits >>= 8
            self._bits_count -= 8

    def flush_pending_bits(self):
        while self._bits_count > 0:
            self._buf.append(self._bits & 0xff)
            self._bits >>= 8
            self._bits_count = max(self._bits_count - 8, 0)


# ---------------------------------------------------------------------------
# LZC constants
# ---------------------------------------------------------------------------

_LZC_VERSION            = 1
_LZC_MIN_CODE_LENGTH    = 9
_LZC_MAX_CODE_LENGTH    = 16
_LZC_LITERAL_CODE_COUNT = 256
_LZC_CODE_END_BLOCK     = 256
_LZC_RATIO_CHECK_INTERVAL = 4096
_LZC_DEFAULT_CODE_LENGTH_LIMIT = 13
_LZC_DEFAULT_BLOCK_MODE = 1   # MULTI_BLOCK
_LZC_SINGLE_BLOCK = 0
_LZC_MULTI_BLOCK  = 1


# ---------------------------------------------------------------------------
# LZC compress
# ---------------------------------------------------------------------------

class _LZCCompress:

    def __init__(self, data, code_length_limit=_LZC_DEFAULT_CODE_LENGTH_LIMIT,
                 block_mode=_LZC_DEFAULT_BLOCK_MODE):
        self._reader = _Reader(data)
        self._writer = _Writer()
        self._code_length_limit = code_length_limit
        self._code_limit        = 1 << code_length_limit
        self._block_mode        = block_mode
        self._code_length       = _LZC_MIN_CODE_LENGTH
        self._max_code          = (1 << _LZC_MIN_CODE_LENGTH) - 1
        self._code_index        = {}   # sequence_id → code
        self._next_free_code    = -1
        self._latest_ratio      = 0
        self._next_ratio_check  = 0
        # Chunk buffer (NOTE-6)
        self._chunk_buf    = bytearray(_LZC_MAX_CODE_LENGTH)
        self._chunk_cursor = 0
        self._chunk_pending       = 0
        self._chunk_pending_count = 0

    @property
    def _first_sequence_code(self):
        if self._block_mode == _LZC_SINGLE_BLOCK:
            return _LZC_LITERAL_CODE_COUNT
        return _LZC_LITERAL_CODE_COUNT + 1   # +1 for END_BLOCK control code

    def _set_code_length(self, value):
        self._code_length = value
        if value == self._code_length_limit:
            self._max_code = self._code_limit
        else:
            self._max_code = (1 << value) - 1

    def _current_ratio(self):
        br = self._reader.bytes_read
        bw = self._writer.bytes_written
        if bw == 0:
            return 0
        if br <= 0x007fffff:
            return (br << 8) // bw
        if bw < 0x100:
            return 0x7fffffff
        return br // (bw >> 8)

    def _write_code(self, code):
        # NOTE-6: use separate chunk buffer to replicate trash padding bytes
        self._chunk_pending |= code << self._chunk_pending_count
        self._chunk_pending_count += self._code_length
        while self._chunk_pending_count >= 8:
            self._chunk_buf[self._chunk_cursor] = self._chunk_pending & 0xff
            self._chunk_cursor += 1
            self._chunk_pending >>= 8
            self._chunk_pending_count -= 8

    def _finish_chunk(self):
        # NOTE-7: chunk is exactly code_length bytes
        self._flush_chunk(self._code_length)

    def _flush_chunk(self, chunk_size=None):
        if self._chunk_pending_count > 0:
            self._chunk_buf[self._chunk_cursor] = self._chunk_pending & 0xff
            self._chunk_cursor += 1
        end = chunk_size if chunk_size is not None else self._chunk_cursor
        self._writer.write(self._chunk_buf[:end])
        self._chunk_pending       = 0
        self._chunk_pending_count = 0
        self._chunk_cursor        = 0

    def _start_new_block(self):
        self._write_code(_LZC_CODE_END_BLOCK)
        self._finish_chunk()
        self._set_code_length(_LZC_MIN_CODE_LENGTH)
        self._code_index.clear()
        self._next_free_code = self._first_sequence_code
        self._latest_ratio   = 0

    def compress(self):
        extra = self._code_length_limit | (self._block_mode << 7)
        hdr = _build_header(self._reader.total_length, _HDR_ALG_LZC, _LZC_VERSION, extra)
        self._writer.write(hdr)

        if self._reader.end_reached:
            return self._writer.data

        self._next_free_code   = self._first_sequence_code
        self._next_ratio_check = _LZC_RATIO_CHECK_INTERVAL

        next_code = self._reader.read_byte()
        while not self._reader.end_reached:
            next_byte   = self._reader.read_byte()
            sequence_id = (next_byte << self._code_length_limit) | next_code
            sequence_code = self._code_index.get(sequence_id)
            if sequence_code:
                next_code = sequence_code
                continue

            # Emit current code
            self._write_code(next_code)
            if self._chunk_cursor >= self._code_length:   # chunk full
                self._finish_chunk()

            # Increase code length if needed
            if self._next_free_code > self._max_code:
                if self._chunk_cursor > 0 or self._chunk_pending_count > 0:
                    self._finish_chunk()
                self._set_code_length(self._code_length + 1)

            if self._next_free_code < self._code_limit:
                self._code_index[sequence_id] = self._next_free_code
                self._next_free_code += 1
            elif self._block_mode == _LZC_MULTI_BLOCK and self._reader.bytes_read >= self._next_ratio_check:
                ratio = self._current_ratio()
                if ratio > self._latest_ratio:
                    self._latest_ratio = ratio
                else:
                    self._start_new_block()
                self._next_ratio_check = self._reader.bytes_read + _LZC_RATIO_CHECK_INTERVAL

            next_code = next_byte

        # Emit final code
        self._write_code(next_code)
        self._flush_chunk()

        return self._writer.data

    @staticmethod
    def compress_data(data, code_length_limit=_LZC_DEFAULT_CODE_LENGTH_LIMIT,
                      block_mode=_LZC_DEFAULT_BLOCK_MODE):
        return _LZCCompress(data, code_length_limit, block_mode).compress()


# ---------------------------------------------------------------------------
# LZC decompress
# ---------------------------------------------------------------------------

class _LZCDecompress:

    def __init__(self, data, compat_mode=False):
        self._reader      = _Reader(data)
        self._writer      = _Writer()
        self._compat_mode = compat_mode
        # Parsed from header
        self._block_mode        = _LZC_DEFAULT_BLOCK_MODE
        self._code_length_limit = _LZC_DEFAULT_CODE_LENGTH_LIMIT
        self._code_limit        = 1 << _LZC_DEFAULT_CODE_LENGTH_LIMIT
        self._code_length       = _LZC_MIN_CODE_LENGTH
        self._max_code          = (1 << _LZC_MIN_CODE_LENGTH) - 1
        self._next_free_code    = -1
        self._chunk_reader      = None   # _Reader for current chunk

    @property
    def _first_sequence_code(self):
        if self._block_mode == _LZC_SINGLE_BLOCK:
            return _LZC_LITERAL_CODE_COUNT
        return _LZC_LITERAL_CODE_COUNT + 1

    def _set_code_length(self, value):
        self._code_length = value
        if value == self._code_length_limit:
            self._max_code = self._code_limit
        else:
            self._max_code = (1 << value) - 1

    def _read_header(self):
        length, alg_id, alg_version, extra = _parse_header(self._reader.read(_HDR_SIZE))
        if alg_id != _HDR_ALG_LZC:
            raise DecompressError("unknown algorithm: expected LZC algorithm identifier")
        block_mode        = extra >> 7
        code_length_limit = extra & 0x1f
        if not (_LZC_MIN_CODE_LENGTH <= code_length_limit <= _LZC_MAX_CODE_LENGTH):
            raise DecompressError("invalid header: code_length_limit out of range")
        self._block_mode        = block_mode
        self._code_length_limit = code_length_limit
        self._code_limit        = 1 << code_length_limit
        return length

    def _start_new_chunk(self):
        read_size = min(self._code_length, self._reader.bytes_left)
        if read_size == 0:
            self._chunk_reader = None
            return
        # Read whatever bytes are available; _read_code will stop when bits run out
        self._chunk_reader = _Reader(self._reader.read(read_size))

    def _start_new_block(self):
        self._next_free_code = self._first_sequence_code
        self._set_code_length(_LZC_MIN_CODE_LENGTH)
        self._start_new_chunk()

    def _read_code(self):
        need_new_chunk = (
            self._chunk_reader is None
            or self._chunk_reader.bits_left < self._code_length
            or self._next_free_code > self._max_code
        )
        if need_new_chunk:
            if self._next_free_code > self._max_code:
                self._set_code_length(self._code_length + 1)
            self._start_new_chunk()
        if self._chunk_reader is None or self._chunk_reader.bits_left < self._code_length:
            return None
        return self._chunk_reader.read_bits(self._code_length)

    def decompress(self):
        decomp_length = self._read_header()
        self._next_free_code = self._first_sequence_code

        decomp_left = decomp_length
        codes = {}          # code → {'base': int, 'next': int, 'chain_index': int}
        chain_buf = bytearray(1 << self._code_length_limit)

        prev_code     = None
        prev_code_def = None

        while decomp_left > 0:
            code = self._read_code()
            if self._block_mode == _LZC_MULTI_BLOCK and code == _LZC_CODE_END_BLOCK:
                self._start_new_block()
                prev_code     = None
                prev_code_def = None
                continue
            if self._compat_mode and code is None:
                break
            if code is None:
                raise DecompressError("unexpected end of compressed data")
            if code >= self._code_limit:
                raise DecompressError("unknown code %d encountered" % code)

            chain_length = 0
            if code == prev_code:
                # Same code repeated - chain still in buffer
                chain_length = (prev_code_def['chain_index'] if prev_code_def else 0) + 1
            elif code < self._next_free_code:
                resolve = code
                while resolve > _LZC_LITERAL_CODE_COUNT - 1:
                    if resolve >= self._next_free_code:
                        raise DecompressError("unknown code %d encountered" % resolve)
                    cdef = codes.get(resolve)
                    if cdef is None:
                        raise DecompressError("unknown code %d encountered" % resolve)
                    chain_buf[cdef['chain_index']] = cdef['next']
                    chain_length += 1
                    resolve = cdef['base']
                chain_buf[0] = resolve
                chain_length += 1
            elif code == self._next_free_code and prev_code is not None:
                # NOTE-8: ababa case
                prev_ci = prev_code_def['chain_index'] if prev_code_def else 0
                chain_buf[prev_ci + 1] = chain_buf[0]
                chain_length = prev_ci + 2
            else:
                raise DecompressError("unknown code %d encountered" % code)

            self._writer.write(chain_buf[:chain_length])
            decomp_left -= chain_length

            if prev_code is not None and self._next_free_code < self._code_limit:
                prev_ci = prev_code_def['chain_index'] if prev_code_def else 0
                codes[self._next_free_code] = {
                    'base':        prev_code,
                    'next':        chain_buf[0],
                    'chain_index': prev_ci + 1,
                }
                self._next_free_code += 1

            prev_code     = code
            prev_code_def = codes.get(code)

        return self._writer.data

    @staticmethod
    def decompress_data(data, compat_mode=False):
        return _LZCDecompress(data, compat_mode).decompress()


# ---------------------------------------------------------------------------
# LZH constants
# ---------------------------------------------------------------------------

_LZH_VERSION   = 1
_LZH_HEAD_NOISE_LEN = 2
_LZH_DEFAULT_COMPRESSION_LEVEL = 2
_LZH_TREETYPE_STATIC  = 1
_LZH_TREETYPE_DYNAMIC = 2
_LZH_LITLEN_HUFFTREE_MAX_BITS = 15
_LZH_DIST_HUFFTREE_MAX_BITS   = 15
_LZH_BITLEN_HUFFTREE_MAX_BITS = 7
_LZH_WINDOW_SIZE    = 0x4000
_LZH_MIN_MATCH      = 3
_LZH_MAX_MATCH      = 258
_LZH_HASH_SIZE      = 14
_LZH_HASH_MASK      = (1 << _LZH_HASH_SIZE) - 1
_LZH_HASH_SHIFT     = (_LZH_HASH_SIZE + _LZH_MIN_MATCH - 1) // _LZH_MIN_MATCH
_LZH_MIN_LOOKAHEAD  = _LZH_MAX_MATCH + _LZH_MIN_MATCH + 1
_LZH_MAX_DISTANCE   = _LZH_WINDOW_SIZE - _LZH_MIN_LOOKAHEAD
_LZH_MAX_DISTANCE_3 = 4096
_LZH_MIN_DISTANCE   = 1
_LZH_LITLEN_COUNT   = 286
_LZH_DIST_COUNT     = 30
_LZH_BITLEN_COUNT   = 19
_LZH_END_BLOCK      = 256
_LZH_LIT_LAST       = 255
_LZH_LENGTH_FIRST   = 257   # first length code in litlen alphabet

_LZH_LEN_EXTRA = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, 99, 99
]
_LZH_DIST_EXTRA = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
]
_LZH_BITLEN_EXTRA = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7
]
_LZH_BITLEN_RANKING = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]

_LZH_BITLEN_REPEAT_NZ_3_6    = 16
_LZH_BITLEN_REPEAT_NZ_3_6_ST = 3
_LZH_BITLEN_REPEAT_Z_3_10    = 17
_LZH_BITLEN_REPEAT_Z_3_10_ST = 3
_LZH_BITLEN_REPEAT_Z_11_138  = 18
_LZH_BITLEN_REPEAT_Z_11_138_ST = 11

_LZH_COMPRESSION_LEVELS = [
    {'level': 0, 'good_length': 0,  'max_lazy': 0,   'max_chain': 0},
    {'level': 1, 'good_length': 4,  'max_lazy': 4,   'max_chain': 16},
    {'level': 2, 'good_length': 6,  'max_lazy': 8,   'max_chain': 16},
    {'level': 3, 'good_length': 8,  'max_lazy': 16,  'max_chain': 32},
    {'level': 4, 'good_length': 8,  'max_lazy': 32,  'max_chain': 64},
    {'level': 5, 'good_length': 8,  'max_lazy': 64,  'max_chain': 128},
    {'level': 6, 'good_length': 8,  'max_lazy': 128, 'max_chain': 256},
    {'level': 7, 'good_length': 8,  'max_lazy': 128, 'max_chain': 512},
    {'level': 8, 'good_length': 32, 'max_lazy': 258, 'max_chain': 1024},
    {'level': 9, 'good_length': 32, 'max_lazy': 258, 'max_chain': 4096},
]


# ---------------------------------------------------------------------------
# LZH Huffman tree
# ---------------------------------------------------------------------------

def _reverse_int(value, length):
    """Reverse the low `length` bits of `value`."""
    rev = 0
    for _ in range(length):
        rev = (rev << 1) | (value & 1)
        value >>= 1
    return rev


class _HuffTree:
    """Huffman tree node container.

    Each node is a dict with keys: value, code, code_length.
    For encode nodes additionally: occurrence, depth, synthetic, padding_node.
    """

    def __init__(self, nodes):
        self.nodes       = nodes
        self._lookup     = None
        self._max_bits   = None
        self._bitlen_seq = None

    def get_max_code_length(self):
        if self._max_bits is None:
            self._max_bits = max((n['code_length'] for n in self.nodes), default=0)
        return self._max_bits

    def get_highest_assigned_node(self):
        for n in reversed(self.nodes):
            if n['code_length'] > 0:
                return n
        raise CompressError("empty Huffman tree: no assigned node")

    # ------------------------------------------------------------------
    # Encoding
    # ------------------------------------------------------------------

    def write_node(self, node_idx, writer):
        node = self.nodes[node_idx]
        writer.write_bits(node['code'], node['code_length'])

    def calculate_encoded_size(self, occurrences, extra_bits_lookup, extra_bits_start):
        total = 0
        for idx, occ in enumerate(occurrences):
            node = self.nodes[idx]
            extra = extra_bits_lookup[idx - extra_bits_start] if idx >= extra_bits_start else 0
            total += occ * (node['code_length'] + extra)
        return total

    def get_bitlen_sequence(self):
        if self._bitlen_seq is None:
            self._bitlen_seq = list(self._generate_bitlen_sequence())
        return self._bitlen_seq

    def write_bitlen_occurrences(self, occ):
        for entry in self.get_bitlen_sequence():
            occ[entry['code']] += 1

    def _generate_bitlen_sequence(self):
        nodes      = self.nodes
        last_node  = self.get_highest_assigned_node()
        last_idx   = last_node['value']

        def next_match_bounds(curlen, nextlen):
            if nextlen == 0:
                return 3, 138
            elif curlen == nextlen:
                return 3, 6
            else:
                return 4, 7

        prevlen   = -1
        streak    = 0
        min_match, max_match = next_match_bounds(-1, nodes[0]['code_length'])

        for i in range(last_idx + 1):
            curlen  = nodes[i]['code_length']
            nextlen = nodes[i + 1]['code_length'] if i < last_idx else -1
            streak += 1
            if curlen == nextlen and streak < max_match:
                continue

            if streak < min_match:
                for _ in range(streak):
                    yield {'type': 'single', 'code': curlen, 'encoded_value': -1}
            elif curlen != 0:
                if curlen != prevlen:
                    yield {'type': 'single',       'code': curlen,                        'encoded_value': -1}
                    yield {'type': 'repeat-nz',    'code': _LZH_BITLEN_REPEAT_NZ_3_6,    'encoded_value': (streak - 1) - _LZH_BITLEN_REPEAT_NZ_3_6_ST}
                else:
                    yield {'type': 'repeat-nz',    'code': _LZH_BITLEN_REPEAT_NZ_3_6,    'encoded_value': streak - _LZH_BITLEN_REPEAT_NZ_3_6_ST}
            else:
                if streak <= 10:
                    yield {'type': 'repeat-z3',    'code': _LZH_BITLEN_REPEAT_Z_3_10,    'encoded_value': streak - _LZH_BITLEN_REPEAT_Z_3_10_ST}
                else:
                    yield {'type': 'repeat-z11',   'code': _LZH_BITLEN_REPEAT_Z_11_138,  'encoded_value': streak - _LZH_BITLEN_REPEAT_Z_11_138_ST}

            streak = 0
            prevlen = curlen
            min_match, max_match = next_match_bounds(curlen, nextlen)

    def encode_to(self, writer, bitlen_tree):
        for entry in self.get_bitlen_sequence():
            bitlen_tree.write_node(entry['code'], writer)
            extra_bits = _LZH_BITLEN_EXTRA[entry['code']]
            if extra_bits > 0:
                writer.write_bits(entry['encoded_value'], extra_bits)

    # ------------------------------------------------------------------
    # Decoding
    # ------------------------------------------------------------------

    def _build_lookup(self):
        max_bits = self.get_max_code_length()
        length_lookup = [0] * (1 << max_bits)
        node_lookup   = [None] * (max_bits + 1)

        for n in self.nodes:
            cl = n['code_length']
            if cl <= 0:
                continue
            if node_lookup[cl] is None:
                node_lookup[cl] = {}
            code = n['code']
            node_lookup[cl][code] = n
            # Fill length_lookup for all extensions of this code
            ext_count = 1 << (max_bits - cl)
            for i in range(ext_count):
                length_lookup[code | (i << cl)] = cl
        self._lookup = (length_lookup, node_lookup)

    def lookup_code(self, code, code_length=None):
        if self._lookup is None:
            self._build_lookup()
        length_lookup, node_lookup = self._lookup
        cl = length_lookup[code] if code < len(length_lookup) else 0
        if code_length is not None:
            cl = min(cl, code_length)
        if cl == 0:
            return None
        code = code & ((1 << cl) - 1)
        m = node_lookup[cl]
        return m.get(code) if m else None

    def read_code(self, reader):
        max_bits = self.get_max_code_length()
        raw      = reader.peek_bits(max_bits)
        node     = self.lookup_code(raw)
        if node is None:
            raise DecompressError("bad hufman tree: no node for code 0x%x" % raw)
        reader.skip_bits(node['code_length'])
        return node

    def read_code_two_staged(self, reader, first_stage_len):
        # NOTE-5
        max_bits = self.get_max_code_length()
        if first_stage_len >= max_bits:
            return self.read_code(reader)
        first = reader.peek_bits(first_stage_len)
        node  = self.lookup_code(first, first_stage_len)
        if node is None:
            second = reader.peek_bits(max_bits)
            node   = self.lookup_code(second)
        if node is None:
            raise DecompressError("bad hufman tree: no node for code")
        reader.skip_bits(node['code_length'])
        return node

    # ------------------------------------------------------------------
    # Static constructors
    # ------------------------------------------------------------------

    @staticmethod
    def from_distribution(dist):
        """Build a decode tree from a list of code-length values (index=value)."""
        nodes = [{'value': i, 'code': -1, 'code_length': cl} for i, cl in enumerate(dist)]
        _HuffTree._generate_node_codes(nodes)
        return _HuffTree(nodes)

    @staticmethod
    def _generate_node_codes(leaf_nodes, dist=None):
        if dist is None:
            dist = _HuffTree._make_distribution(leaf_nodes)
        _HuffTree._validate_distribution(dist)
        next_codes = [0] * (len(dist) + 1)
        code = 0
        for cl in range(1, len(dist) + 1):
            code = (code + (dist[cl - 1] if cl - 1 < len(dist) else 0)) << 1
            next_codes[cl] = code
        for n in leaf_nodes:
            cl = n['code_length']
            if cl <= 0:
                continue
            n['code'] = _reverse_int(next_codes[cl], cl)
            next_codes[cl] += 1

    @staticmethod
    def _make_distribution(nodes):
        dist = []
        for n in nodes:
            cl = n['code_length']
            if cl <= 0:
                continue
            while len(dist) <= cl:
                dist.append(0)
            dist[cl] += 1
        return dist

    @staticmethod
    def _validate_distribution(dist):
        available = 1
        for count in dist:
            available -= count
            if available < 0:
                raise DecompressError("bad hufman tree: invalid code-length distribution")
            available *= 2
        if available > 0:
            raise DecompressError("bad hufman tree: code-length distribution has unassigned codes")


class _HuffHeapTree:
    """Min-heap of Huffman nodes ordered by (occurrence, depth)."""

    def __init__(self, nodes):
        # 1-based; index 0 is unused placeholder
        self.heap = [None] + nodes

    @property
    def length(self):
        return len(self.heap) - 1

    def _cmp(self, a, b):
        """Return negative if a < b, 0 if equal, positive if a > b."""
        if a['occurrence'] != b['occurrence']:
            return a['occurrence'] - b['occurrence']
        return a['depth'] - b['depth']

    def _update(self, idx):
        base = self.heap[idx]
        while True:
            c1 = idx << 1
            if c1 >= len(self.heap):
                break
            c2 = c1 + 1
            # When tied, prefer c2 (NOTE in TS: "When in a tie, child2 is used")
            smaller = c2 if (c2 < len(self.heap) and self._cmp(self.heap[c1], self.heap[c2]) >= 0) else c1
            if self._cmp(base, self.heap[smaller]) <= 0:
                break
            self.heap[idx] = self.heap[smaller]
            idx = smaller
        self.heap[idx] = base

    def init(self):
        for i in range(self.length // 2, 0, -1):
            self._update(i)

    def pop(self):
        if self.length == 0:
            raise CompressError("cannot pop from empty heap")
        if self.length == 1:
            return self.heap.pop()
        top = self.heap[1]
        self.heap[1] = self.heap.pop()
        self._update(1)
        return top

    def create_huff_node(self):
        if self.length < 2:
            raise CompressError("heap has fewer than 2 elements")
        top  = self.pop()
        top2 = self.heap[1]
        syn  = {
            'synthetic':    True,
            'occurrence':   top['occurrence'] + top2['occurrence'],
            'depth':        max(top['depth'], top2['depth']) + 1,
            'code_length':  -1,
            'parent':       None,
            'children':     (top, top2),
        }
        top['parent']  = syn
        top2['parent'] = syn
        self.heap[1]   = syn
        self._update(1)
        return syn


class _HuffTreeEncoder:

    @staticmethod
    def build_tree(occurrences, max_code_length):
        enc = _HuffTreeEncoder()
        return enc._build(occurrences, max_code_length)

    def _build(self, occurrences, max_code_length):
        base_nodes = self._make_bare_nodes(occurrences)
        populated  = [n for n in base_nodes if n['occurrence'] > 0]
        self._pad_nodes(populated, base_nodes)
        tree_nodes = self._create_huffman_nodes(populated)
        dist       = self._arrange_nodes(tree_nodes, max_code_length)
        _HuffTree._generate_node_codes(populated, dist)
        return _HuffTree(base_nodes)

    def _make_bare_nodes(self, occurrences):
        return [
            {
                'value':       i,
                'occurrence':  occ,
                'synthetic':   False,
                'padding_node': False,
                'depth':       0,
                'parent':      None,
                'code':        -1,
                'code_length': 0,
            }
            for i, occ in enumerate(occurrences)
        ]

    def _pad_nodes(self, nodes, base_nodes):
        # NOTE-12
        while len(nodes) < 2:
            if len(nodes) == 0:
                next_pad = 0
            else:
                next_pad = nodes[0]['value'] + 1 if nodes[0]['value'] < 2 else 0
            pad = base_nodes[next_pad]
            pad['occurrence']   = 1
            pad['padding_node'] = True
            nodes.append(pad)
        nodes.sort(key=lambda n: n['value'])

    def _create_huffman_nodes(self, base_nodes):
        heap = _HuffHeapTree(list(base_nodes))
        heap.init()
        tree_nodes = []
        while heap.length >= 2:
            syn = heap.create_huff_node()
            tree_nodes.extend(syn['children'])
        tree_nodes.append(heap.heap[1])
        return tree_nodes

    def _arrange_nodes(self, tree_nodes, max_code_length):
        # Root is the last element, with depth 0
        tree_nodes[-1]['code_length'] = 0
        overflow = 0
        dist     = [0] * (max_code_length + 1)

        for i in range(len(tree_nodes) - 2, -1, -1):
            node = tree_nodes[i]
            cl   = node['parent']['code_length'] + 1
            if cl > max_code_length:
                cl = max_code_length
                overflow += 1
            node['code_length'] = cl
            if not node['synthetic']:
                dist[cl] += 1

        if overflow:
            # NOTE-4: rearrange overflowed nodes
            while overflow > 0:
                next_free = -1
                for i in range(max_code_length - 1, -1, -1):
                    if dist[i] > 0:
                        next_free = i
                        break
                if next_free < 0:
                    raise CompressError("no space to fit overflow nodes into Huffman tree")
                dist[next_free]     -= 1
                dist[next_free + 1] += 1
                dist[max_code_length] -= 1
                dist[next_free + 1] += 1
                overflow -= 2

            # Re-assign code lengths to natural nodes
            natural = [n for n in tree_nodes if not n['synthetic']]
            nat_iter = iter(natural)
            for layer in range(max_code_length, 0, -1):
                for _ in range(dist[layer]):
                    try:
                        next(nat_iter)['code_length'] = layer
                    except StopIteration:
                        raise CompressError("ran out of leaf nodes during Huffman rearrangement")

        return dist


# ---------------------------------------------------------------------------
# LZH static trees (cached at class level)
# ---------------------------------------------------------------------------

class _LZHBase:
    _len_code_map  = None   # (codeLookup: bytes, valueStartLookup: list)
    _dist_code_map = None
    _static_litlen = None
    _static_dist   = None

    @classmethod
    def get_length_code_mapping(cls):
        if cls._len_code_map is None:
            cls._len_code_map = cls._gen_length_code_mapping()
        return cls._len_code_map

    @staticmethod
    def _gen_length_code_mapping():
        lookup = bytearray(259)      # index 0-258
        starts = [0] * 29

        length = _LZH_MIN_MATCH
        for code in range(28):
            starts[code] = length
            count = 1 << _LZH_LEN_EXTRA[code]
            for _ in range(count):
                lookup[length] = code
                length += 1
        # NOTE-3: length 258 gets its own code
        lookup[_LZH_MAX_MATCH] = 28
        starts[28]             = _LZH_MAX_MATCH
        return lookup, starts

    @classmethod
    def get_distance_code_mapping(cls):
        if cls._dist_code_map is None:
            cls._dist_code_map = cls._gen_distance_code_mapping()
        return cls._dist_code_map

    @staticmethod
    def _gen_distance_code_mapping():
        lookup = bytearray(32769)
        starts = [0] * 30
        dist = 1
        for code in range(30):
            starts[code] = dist
            count = 1 << _LZH_DIST_EXTRA[code]
            for _ in range(count):
                lookup[dist] = code
                dist += 1
        return lookup, starts

    @classmethod
    def get_static_litlen_tree(cls):
        if cls._static_litlen is None:
            cls._static_litlen = cls._gen_static_litlen_tree()
        return cls._static_litlen

    @staticmethod
    def _gen_static_litlen_tree():
        # 288 nodes needed for canonical tree generation (codes 286-287 are dummies)
        nodes = []
        for c in range(144):
            nodes.append({'value': c, 'code': -1, 'code_length': 8})
        for c in range(144, 256):
            nodes.append({'value': c, 'code': -1, 'code_length': 9})
        for c in range(256, 280):
            nodes.append({'value': c, 'code': -1, 'code_length': 7})
        for c in range(280, 288):
            nodes.append({'value': c, 'code': -1, 'code_length': 8})
        _HuffTree._generate_node_codes(nodes)
        return _HuffTree(nodes)

    @classmethod
    def get_static_dist_tree(cls):
        if cls._static_dist is None:
            cls._static_dist = cls._gen_static_dist_tree()
        return cls._static_dist

    @staticmethod
    def _gen_static_dist_tree():
        nodes = [
            {'value': c, 'code_length': 5, 'code': _reverse_int(c, 5)}
            for c in range(30)
        ]
        return _HuffTree(nodes)


# ---------------------------------------------------------------------------
# LZH LZSS matcher
# ---------------------------------------------------------------------------

class _LZSSMatcher:
    """Sliding-window LZSS byte-stream matcher."""

    def __init__(self, reader, config):
        self._reader  = reader
        self._config  = config
        self._window  = bytearray(_LZH_WINDOW_SIZE * 2)
        self._win_off = 0
        self._win_cur = 0
        self._win_end = 0
        self._win_sealed = False
        self._hash_index   = {}           # hash → local_cursor
        self._hash_history = array('H', bytes(2 * _LZH_WINDOW_SIZE))  # 16-bit entries
        self._cur_hash     = 0
        self._nearest      = None   # global position of nearest match

    def _hash(self, base, next_byte):
        return ((base << _LZH_HASH_SHIFT) ^ next_byte) & _LZH_HASH_MASK

    def _populate_window(self):
        if self._win_sealed:
            raise RuntimeError("window is sealed")
        win_used = self._win_end - self._win_off
        win_free = len(self._window) - win_used
        if win_free == 0:
            self._shift_window()
            win_free = _LZH_WINDOW_SIZE

        if self._reader.end_reached:
            self._win_sealed = True
            return

        count = min(win_free, self._reader.bytes_left)
        local_end = self._win_end - self._win_off
        self._window[local_end:local_end + count] = self._reader.read(count)
        self._win_end += count

    def _shift_window(self):
        ws = _LZH_WINDOW_SIZE
        self._window[:ws] = self._window[ws:ws * 2]
        self._win_off += ws
        # Adjust hash_index
        self._hash_index = {
            k: v - ws
            for k, v in self._hash_index.items()
            if v >= ws
        }
        # Adjust hash_history
        hist = self._hash_history
        for n in range(ws):
            m = hist[n]
            hist[n] = (m - ws) if m >= ws else 0

    def _move_cursor_to(self, pos):
        win_off = self._win_off
        h       = self._cur_hash
        while self._win_cur < pos:
            self._win_cur += 1
            if h < 0:
                continue
            local = self._win_cur - win_off
            h = self._hash(h, self._window[local + _LZH_MIN_MATCH - 1])
            prev = self._hash_index.get(h)
            self._nearest = (prev + win_off) if prev is not None else None
            self._hash_index[h] = local
            self._hash_history[local % _LZH_WINDOW_SIZE] = prev if prev is not None else 0
        self._cur_hash = h
        while (self._win_end - self._win_cur < _LZH_MIN_LOOKAHEAD
               and not self._win_sealed):
            self._populate_window()

    def _next_match(self, min_length=None):
        if min_length is None:
            min_length = _LZH_MIN_MATCH
        if self._win_cur >= self._win_end:
            return None
        near = self._nearest
        if (near is None
                or self._win_cur - near > _LZH_MAX_DISTANCE
                or self._win_end - self._win_cur < min_length):
            return {'cursor': self._win_cur, 'distance': 0, 'length': 1}

        win_off = self._win_off
        bound   = max(self._win_cur - _LZH_MAX_DISTANCE, 0)
        max_hops = (self._config['max_chain'] // 4
                    if min_length > self._config['good_length']
                    else self._config['max_chain'])

        local_cur = self._win_cur - win_off
        win       = self._window
        hist      = self._hash_history

        occ_start       = near
        local_occ_start = occ_start - win_off
        hops      = 0
        best      = None

        while True:
            # Quick reject (NOTE-10: use 0 for out-of-bounds reads)
            wc0 = win[local_cur]            if local_cur < len(win) else 0
            wo0 = win[local_occ_start]      if local_occ_start < len(win) else 0
            wc1 = win[local_cur + min_length - 1]      if (local_cur + min_length - 1) < len(win) else 0
            wo1 = win[local_occ_start + min_length - 1] if (local_occ_start + min_length - 1) < len(win) else 0
            wc2 = win[local_cur + min_length - 2]       if (local_cur + min_length - 2) < len(win) else 0
            wo2 = win[local_occ_start + min_length - 2] if (local_occ_start + min_length - 2) < len(win) else 0

            if wc0 == wo0 and wc1 == wo1 and wc2 == wo2:
                match_len = 1
                while (match_len < _LZH_MAX_MATCH
                       and (win[local_cur + match_len] if (local_cur + match_len) < len(win) else 0)
                           == (win[local_occ_start + match_len] if (local_occ_start + match_len) < len(win) else 0)):
                    match_len += 1

                if match_len >= min_length:
                    best = {'cursor': self._win_cur, 'distance': self._win_cur - occ_start, 'length': match_len}
                    if match_len >= _LZH_MAX_MATCH:
                        break
                    min_length = match_len + 1

            local_occ_start = hist[local_occ_start % _LZH_WINDOW_SIZE]
            occ_start       = local_occ_start + win_off
            hops += 1
            if hops >= max_hops or occ_start <= bound:
                break

        if best is None:
            return {'cursor': self._win_cur, 'distance': 0, 'length': 1}

        # Cap to actual remaining bytes (NOTE-10)
        best['length'] = min(best['length'], self._win_end - self._win_cur)
        # Discard short distant matches
        if best['length'] == _LZH_MIN_MATCH and best['distance'] > _LZH_MAX_DISTANCE_3:
            return {'cursor': self._win_cur, 'distance': 0, 'length': 1}
        return best

    def _resolve(self, m):
        local = m['cursor'] - self._win_off
        return {
            'distance':   m['distance'],
            'length':     m['length'],
            'first_byte': self._window[local],
        }

    def match(self):
        self._populate_window()
        # Prime the hash with MIN_MATCH - 1 bytes ahead
        for i in range(_LZH_MIN_MATCH):
            self._cur_hash = self._hash(self._cur_hash, self._window[i])
        self._hash_index[self._cur_hash] = 0

        while self._win_cur < self._win_end:
            cur = self._next_match()
            while cur and (cur['length'] == 1 or cur['length'] >= self._config['max_lazy']):
                yield self._resolve(cur)
                self._move_cursor_to(cur['cursor'] + cur['length'])
                cur = self._next_match()

            while cur:
                self._move_cursor_to(self._win_cur + 1)
                pending = cur
                cur     = self._next_match(pending['length'] + 1)
                if not cur or pending['length'] >= cur['length']:
                    yield self._resolve(pending)
                    self._move_cursor_to(pending['cursor'] + pending['length'])
                    cur = None
                else:
                    yield self._resolve({'cursor': pending['cursor'], 'distance': 0, 'length': 1})
                    if cur['length'] >= self._config['max_lazy']:
                        yield self._resolve(cur)
                        self._move_cursor_to(cur['cursor'] + cur['length'])
                        cur = None


class _LZSSBlockMatcher:
    """Groups LZSS matches into encoder blocks."""

    def __init__(self, reader, config):
        self._reader = reader
        self._config = config

    def _should_end_block(self, blk):
        mc  = blk['match_count']
        dmc = blk['dist_match_count']
        if mc == 0x3fff or dmc == 0x4000:
            return True
        if (self._config['level'] > 2
                and (mc & 0xfff) == 0
                and dmc < (mc >> 1)
                and (blk['compressed_tracker'] >> 3) < (blk['uncompressed_size'] >> 1)):
            return True
        return False

    def match(self):
        _, dist_starts = _LZHBase.get_distance_code_mapping()
        dist_lookup, _ = _LZHBase.get_distance_code_mapping()

        def new_block():
            return {'matches': [], 'match_count': 0, 'dist_match_count': 0,
                    'uncompressed_size': 1,   # off-by-one replication from original
                    'compressed_tracker': 0}

        blk = new_block()
        for m in _LZSSMatcher(self._reader, self._config).match():
            blk['matches'].append(m)
            blk['match_count'] += 1
            if m['distance'] == 0:
                blk['compressed_tracker'] += 8
            else:
                blk['dist_match_count'] += 1
                dc = dist_lookup[m['distance']]
                blk['compressed_tracker'] += 8 + 5 + _LZH_DIST_EXTRA[dc]

            if self._should_end_block(blk):
                yield {'matches': blk['matches'], 'block_finished': True}
                blk = new_block()
                continue

            blk['uncompressed_size'] += m['length']

        if blk['matches']:
            yield {'matches': blk['matches'], 'block_finished': False}


# ---------------------------------------------------------------------------
# LZH compress
# ---------------------------------------------------------------------------

class _LZHCompress(_LZHBase):

    def __init__(self, data, level):
        self._reader = _Reader(data)
        self._writer = _Writer()
        self._config = _LZH_COMPRESSION_LEVELS[level]

    def compress(self):
        self._write_head()
        len_lookup, len_starts = self.get_length_code_mapping()
        dist_lookup, dist_starts = self.get_distance_code_mapping()

        open_block = None
        for block in _LZSSBlockMatcher(self._reader, self._config).match():
            if block['block_finished']:
                self._write_match_block(block['matches'], final=False,
                                        len_lookup=len_lookup, len_starts=len_starts,
                                        dist_lookup=dist_lookup, dist_starts=dist_starts)
            else:
                open_block = block

        self._write_match_block(
            open_block['matches'] if open_block else [],
            final=True,
            len_lookup=len_lookup, len_starts=len_starts,
            dist_lookup=dist_lookup, dist_starts=dist_starts,
        )
        self._writer.flush_pending_bits()
        # NOTE-5: courtesy zero byte
        self._writer.write_byte(0)
        return self._writer.data

    def _write_head(self):
        hdr = _build_header(self._reader.total_length, _HDR_ALG_LZH, _LZH_VERSION,
                            self._config['level'])
        self._writer.write(hdr)
        # NOTE-16: fixed noise bits (3 bits of noise, value 7)
        self._writer.write_bits(3, _LZH_HEAD_NOISE_LEN)
        self._writer.write_bits(7, 3)

    def _write_match_block(self, matches, final, len_lookup, len_starts,
                           dist_lookup, dist_starts):
        # Count occurrences
        litlen_occ = [0] * _LZH_LITLEN_COUNT
        dist_occ   = [0] * _LZH_DIST_COUNT
        litlen_occ[_LZH_END_BLOCK] = 1
        for m in matches:
            if m['distance'] == 0:
                litlen_occ[m['first_byte']] += 1
            else:
                lc = len_lookup[m['length']]
                litlen_occ[lc + 257] += 1
                dc = dist_lookup[m['distance']]
                dist_occ[dc] += 1

        litlen_tree = _HuffTreeEncoder.build_tree(litlen_occ, _LZH_LITLEN_HUFFTREE_MAX_BITS)
        dist_tree   = _HuffTreeEncoder.build_tree(dist_occ,   _LZH_DIST_HUFFTREE_MAX_BITS)

        bitlen_occ = [0] * _LZH_BITLEN_COUNT
        litlen_tree.write_bitlen_occurrences(bitlen_occ)
        dist_tree.write_bitlen_occurrences(bitlen_occ)
        bitlen_tree = _HuffTreeEncoder.build_tree(bitlen_occ, _LZH_BITLEN_HUFFTREE_MAX_BITS)

        ranked = self._rank_bitlen_nodes(bitlen_tree)
        hi_ranked = max((i for i, n in enumerate(ranked) if n['code_length'] > 0), default=-1)
        if hi_ranked < 3:
            raise CompressError("max_bitlen_index cannot be below 3")

        static_ll = self.get_static_litlen_tree()
        static_d  = self.get_static_dist_tree()
        # NOTE in TS: static tree size calculation uses LEN extra bits for both
        # litlen and dist (a bug kept for compatibility)
        static_bits = (
            static_ll.calculate_encoded_size(litlen_occ, _LZH_LEN_EXTRA, 257)
            + static_d.calculate_encoded_size(dist_occ, _LZH_LEN_EXTRA, 0)
        )
        static_bytes = (static_bits + 3 + 7) >> 3

        dyn_bits = (
            litlen_tree.calculate_encoded_size(litlen_occ, _LZH_LEN_EXTRA, 257)
            + dist_tree.calculate_encoded_size(dist_occ, _LZH_LEN_EXTRA, 0)
            + bitlen_tree.calculate_encoded_size(bitlen_occ, _LZH_BITLEN_EXTRA, 0)
            + 3 * (hi_ranked + 1) + 5 + 5 + 4
        )
        dyn_bytes = (dyn_bits + 3 + 7) >> 3

        w = self._writer
        w.write_bits(1 if final else 0, 1)
        if static_bytes <= dyn_bytes:
            w.write_bits(_LZH_TREETYPE_STATIC, 2)
            self._write_matches(matches, static_ll, static_d,
                                len_lookup, len_starts, dist_lookup, dist_starts)
            static_ll.write_node(_LZH_END_BLOCK, w)
        else:
            w.write_bits(_LZH_TREETYPE_DYNAMIC, 2)
            self._write_dynamic_trees(litlen_tree, dist_tree, bitlen_tree)
            self._write_matches(matches, litlen_tree, dist_tree,
                                len_lookup, len_starts, dist_lookup, dist_starts)
            litlen_tree.write_node(_LZH_END_BLOCK, w)

    def _rank_bitlen_nodes(self, bitlen_tree):
        return [bitlen_tree.nodes[_LZH_BITLEN_RANKING[i]] for i in range(_LZH_BITLEN_COUNT)]

    def _write_dynamic_trees(self, litlen_tree, dist_tree, bitlen_tree):
        w = self._writer
        hi_lit  = litlen_tree.get_highest_assigned_node()['value']
        hi_dist = dist_tree.get_highest_assigned_node()['value']
        w.write_bits(hi_lit - 256, 5)
        w.write_bits(hi_dist, 5)

        ranked    = self._rank_bitlen_nodes(bitlen_tree)
        hi_ranked = max((i for i, n in enumerate(ranked) if n['code_length'] > 0), default=-1)
        w.write_bits(hi_ranked - 3, 4)
        for i in range(hi_ranked + 1):
            w.write_bits(ranked[i]['code_length'], 3)

        litlen_tree.encode_to(w, bitlen_tree)
        dist_tree.encode_to(w, bitlen_tree)

    def _write_matches(self, matches, litlen_tree, dist_tree,
                       len_lookup, len_starts, dist_lookup, dist_starts):
        w = self._writer
        for m in matches:
            if m['distance'] == 0:
                litlen_tree.write_node(m['first_byte'], w)
            else:
                lc = len_lookup[m['length']]
                litlen_tree.write_node(lc + 257, w)
                len_extra = _LZH_LEN_EXTRA[lc]
                if len_extra:
                    w.write_bits(m['length'] - len_starts[lc], len_extra)
                dc = dist_lookup[m['distance']]
                dist_tree.write_node(dc, w)
                dist_extra = _LZH_DIST_EXTRA[dc]
                if dist_extra:
                    w.write_bits(m['distance'] - dist_starts[dc], dist_extra)

    @staticmethod
    def compress_data(data, level=_LZH_DEFAULT_COMPRESSION_LEVEL):
        return _LZHCompress(data, level).compress()


# ---------------------------------------------------------------------------
# LZH decompress
# ---------------------------------------------------------------------------

class _LZHDecompress(_LZHBase):

    def __init__(self, data):
        self._reader     = _Reader(data)
        self._writer     = _Writer()
        self._dec_buf    = bytearray(_LZH_WINDOW_SIZE)
        self._dec_cursor = 0

    def decompress(self):
        self._read_head()
        while True:
            last_block = self._reader.read_bits(1)
            block_type = self._reader.read_bits(2)
            if block_type == _LZH_TREETYPE_STATIC:
                self._read_static_block()
            elif block_type == _LZH_TREETYPE_DYNAMIC:
                self._read_dynamic_block()
            else:
                raise DecompressError("unknown block type 0x%x" % block_type)
            if last_block:
                break
        return self._writer.data

    def _read_head(self):
        hdr_bytes = self._reader.read(_HDR_SIZE)
        length, alg_id, _, _ = _parse_header(hdr_bytes)
        if alg_id != _HDR_ALG_LZH:
            raise DecompressError("unknown algorithm: expected LZH algorithm identifier")
        noise_count = self._reader.read_bits(_LZH_HEAD_NOISE_LEN)
        if noise_count:
            self._reader.skip_bits(noise_count)

    def _read_static_block(self):
        self._read_block_content(
            self.get_static_litlen_tree(),
            self.get_static_dist_tree(),
        )

    def _read_dynamic_block(self):
        r = self._reader
        litlen_count = 257 + r.read_bits(5)
        dist_count   = 1   + r.read_bits(5)
        bitlen_count = 4   + r.read_bits(4)

        if litlen_count > _LZH_LITLEN_COUNT:
            raise DecompressError("invalid litlen code count %d" % litlen_count)
        if dist_count > _LZH_DIST_COUNT:
            raise DecompressError("invalid dist code count %d" % dist_count)

        bitlen_dist = [0] * _LZH_BITLEN_COUNT
        for i in range(bitlen_count):
            bitlen_dist[_LZH_BITLEN_RANKING[i]] = r.read_bits(3)
        bitlen_tree = _HuffTree.from_distribution(bitlen_dist)

        litlen_cl = self._read_encoded_lengths(r, bitlen_tree, litlen_count)
        litlen_tree = _HuffTree.from_distribution(litlen_cl)

        dist_cl   = self._read_encoded_lengths(r, bitlen_tree, dist_count)
        dist_tree = _HuffTree.from_distribution(dist_cl)

        self._read_block_content(litlen_tree, dist_tree)

    @staticmethod
    def _read_encoded_lengths(reader, bitlen_tree, count):
        codes = []
        lastlen = -1
        while len(codes) < count:
            node    = bitlen_tree.read_code(reader)
            bl_code = node['value']
            if bl_code < 16:
                codes.append(bl_code)
                lastlen = bl_code
            elif bl_code == _LZH_BITLEN_REPEAT_NZ_3_6:
                rep = _LZH_BITLEN_REPEAT_NZ_3_6_ST + reader.read_bits(_LZH_BITLEN_EXTRA[bl_code])
                if rep > count - len(codes):
                    raise DecompressError("repeat code overflows expected code count")
                codes.extend([lastlen] * rep)
            elif bl_code == _LZH_BITLEN_REPEAT_Z_3_10:
                rep = _LZH_BITLEN_REPEAT_Z_3_10_ST + reader.read_bits(_LZH_BITLEN_EXTRA[bl_code])
                if rep > count - len(codes):
                    raise DecompressError("repeat code overflows expected code count")
                codes.extend([0] * rep)
                lastlen = 0
            elif bl_code == _LZH_BITLEN_REPEAT_Z_11_138:
                rep = _LZH_BITLEN_REPEAT_Z_11_138_ST + reader.read_bits(_LZH_BITLEN_EXTRA[bl_code])
                if rep > count - len(codes):
                    raise DecompressError("repeat code overflows expected code count")
                codes.extend([0] * rep)
                lastlen = 0
            else:
                raise DecompressError("unknown bitlen code %d" % bl_code)
        return codes

    def _read_block_content(self, litlen_tree, dist_tree):
        r   = self._reader
        w   = self._writer
        buf = self._dec_buf
        eob = litlen_tree.nodes[_LZH_END_BLOCK]
        if not eob or eob['code_length'] == 0:
            raise DecompressError("litlen tree has no end-of-block code")

        len_lookup, len_starts  = self.get_length_code_mapping()
        dist_lookup, dist_starts = self.get_distance_code_mapping()

        while True:
            node = litlen_tree.read_code_two_staged(r, eob['code_length'])
            val  = node['value']
            if val <= _LZH_LIT_LAST:
                buf[self._dec_cursor] = val
                w.write_byte(val)
                self._dec_cursor = (self._dec_cursor + 1) % _LZH_WINDOW_SIZE
                continue
            if val == _LZH_END_BLOCK:
                break

            # Length-distance back reference
            lc           = val - _LZH_LENGTH_FIRST
            len_extra    = _LZH_LEN_EXTRA[lc]
            length       = len_starts[lc] + r.read_bits(len_extra)
            if length > _LZH_MAX_MATCH:
                raise DecompressError("invalid match length %d" % length)

            dist_node    = dist_tree.read_code(r)
            dc           = dist_node['value']
            dist_extra   = _LZH_DIST_EXTRA[dc]
            distance     = dist_starts[dc] + r.read_bits(dist_extra)
            if distance > _LZH_MAX_DISTANCE:
                raise DecompressError("invalid match distance %d" % distance)

            copy_left  = length
            copy_start = (self._dec_cursor - distance + _LZH_WINDOW_SIZE) % _LZH_WINDOW_SIZE
            while copy_left > 0:
                slide_left   = _LZH_WINDOW_SIZE - max(copy_start, self._dec_cursor)
                copy_length  = min(slide_left, copy_left)
                curs         = self._dec_cursor
                if curs > copy_start and curs > copy_start + copy_length or curs < copy_start:
                    buf[curs:curs + copy_length] = buf[copy_start:copy_start + copy_length]
                else:
                    for i in range(copy_length):
                        buf[curs + i] = buf[copy_start + i]
                w.write(buf[curs:curs + copy_length])
                self._dec_cursor = (curs + copy_length) % _LZH_WINDOW_SIZE
                copy_left  -= copy_length
                copy_start  = (copy_start + copy_length) % _LZH_WINDOW_SIZE

    @staticmethod
    def decompress_data(data):
        return _LZHDecompress(data).decompress()


# ---------------------------------------------------------------------------
# Public API  (compatible with the old C pysapcompress extension)
# ---------------------------------------------------------------------------

def compress(data, algorithm=ALG_LZC):
    """Compress *data* using the given SAP algorithm.

    :param bytes data: data to compress
    :param int algorithm: ALG_LZC (0) or ALG_LZH (2)
    :returns: tuple (status, compressed_length, compressed_bytes)
    :rtype: tuple[int, int, bytes]
    :raises CompressError: on error
    """
    if not data:
        raise CompressError("Compression error (CS_E_IN_BUFFER_LEN: invalid input length)")

    try:
        if algorithm == ALG_LZC:
            out = _LZCCompress.compress_data(bytes(data))
        elif algorithm == ALG_LZH:
            out = _LZHCompress.compress_data(bytes(data))
        else:
            raise CompressError("Compression error (CS_E_UNKNOWN_ALG: unknown algorithm)")
    except CompressError:
        raise
    except Exception as exc:
        raise CompressError("Compression error (%s)" % exc) from exc

    return _CS_END_OF_STREAM, len(out), out


def decompress(data, out_length):
    """Decompress *data*, expecting *out_length* uncompressed bytes.

    :param bytes data: compressed data (including 8-byte SAP header)
    :param int out_length: expected uncompressed length
    :returns: tuple (status, decompressed_length, decompressed_bytes)
    :rtype: tuple[int, int, bytes]
    :raises DecompressError: on error
    """
    if not data:
        raise DecompressError("Decompression error (CS_E_IN_BUFFER_LEN: invalid input length)")

    data = bytes(data)
    if len(data) < _HDR_SIZE:
        raise DecompressError("Decompression error (CS_E_IN_BUFFER_LEN: invalid input length)")

    # Peek at the algorithm identifier without consuming
    try:
        hdr_length, alg_id, _, _ = _parse_header(data)
    except DecompressError as exc:
        raise DecompressError("Decompression error (%s)" % exc) from exc

    try:
        if alg_id == _HDR_ALG_LZC:
            if hdr_length != out_length:
                raise DecompressError(
                    "Decompression error (CS_E_OUT_BUFFER_LEN: invalid output length): "
                    "header says %d but caller expects %d" % (hdr_length, out_length)
                )
            out = _LZCDecompress.decompress_data(data, compat_mode=True)
        elif alg_id == _HDR_ALG_LZH:
            if hdr_length != out_length:
                raise DecompressError(
                    "Decompression error (CS_E_OUT_BUFFER_LEN: invalid output length): "
                    "header says %d but caller expects %d" % (hdr_length, out_length)
                )
            out = _LZHDecompress.decompress_data(data)
        else:
            raise DecompressError(
                "Decompression error (CS_E_UNKNOWN_ALG: unknown algorithm): "
                "algorithm id 0x%x" % alg_id
            )
    except DecompressError:
        raise
    except Exception as exc:
        raise DecompressError("Decompression error (%s)" % exc) from exc

    return _CS_END_OF_STREAM, len(out), out
