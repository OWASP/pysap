# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# Copyright (C) 2012-2017 by Martin Gallo, Core Security
#
# The library was designed and developed by Martin Gallo from the Security
# Consulting Services team of Core Security.
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
# ==============


# Standard imports
import struct
from datetime import datetime
# External imports
from scapy.config import conf
from scapy.packet import Packet
from scapy.volatile import (RandNum, RandTermString, RandBin)
from scapy.fields import (MultiEnumField, StrLenField, Field, StrFixedLenField,
                          StrField, PacketListField)


def saptimestamp_to_datetime(timestamp):
    """Converts a timestamp in "SAP format" to a datetime object. Time zone
    looks to be fixed at GMT+1."""
    return datetime.utcfromtimestamp((int(timestamp) & 0xFFFFFFFF) + 1000000000)


class PacketNoPadded(Packet):
    """Regular scapy packet with no padding.
    """
    def extract_padding(self, s):
        return '', s


class RandByteReduced(RandNum):
    """RandByte that only returns random values between 0 and x2a. Used while
    performing some fuzz to reduce the test cases space.

    """
    def __init__(self):
        RandNum.__init__(self, 0, 0x2a)


class ByteMultiEnumKeysField(MultiEnumField):
    """MultiEnumField that picks a reduced number of values. Used for fuzzing
    Byte fields with reduced number of values.

    """
    def randval(self):
        return RandByteReduced()


class MutablePacketField(StrLenField):
    """Packet field that mutates the class according to a list of evaluators.
    The evaluators are run against the packet and given to a class getter.

    If the class can't be found, the field is treated as a StrLenField.
    """
    __slots__ = ["length_from", "evaluators", "_get_class"]

    def __init__(self, name, default, length_from, get_class, evaluators=None):
        """
        :param length_from: function to obtain the field length
        :type length_from: C{callable}

        :param get_class: function to obtain the class
        :type get_class: C{callable}

        :param evaluators: evaluators
        :type evaluators: ``list`` of C{callable}
        """
        StrLenField.__init__(self, name, default, length_from=length_from)
        self.evaluators = evaluators or []
        self._get_class = get_class

    def get_class(self, pkt):
        # Run the evaluators on the actual packet
        values = [evaluator(pkt) for evaluator in self.evaluators]
        # Return the class using the function provided
        return self._get_class(pkt, *values)

    def i2m(self, pkt, i):
        cls = self.get_class(pkt)
        if cls is not None:
            return str(i)
        else:
            return StrLenField.i2m(self, pkt, i)

    def m2i(self, pkt, m):
        cls = self.get_class(pkt)
        if cls is not None:
            return cls(m)
        else:
            return StrLenField.m2i(self, pkt, m)


class StrNullFixedLenField(StrFixedLenField):
    """Packet field that has a fixed length and is null-terminated.
    """
    __slots__ = ["length_from", "max_length"]

    def __init__(self, name, default, length=None, length_from=None, max_length=None):
        self.max_length = max_length or 200
        StrFixedLenField.__init__(self, name, default, length=length, length_from=length_from)

    def i2repr(self, pkt, v):
        if type(v) is str:
            v = v.rstrip("\0")
        return repr(v)

    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        return s[l + 1:], self.m2i(pkt, s[:l])

    def addfield(self, pkt, s, val):
        l = self.length_from(pkt)
        return s + struct.pack("%is" % l, self.i2m(pkt, val)) + "\x00"

    def randval(self):
        try:
            l = self.length_from(None)
        except:
            l = RandTermString(RandNum(0, self.max_length), "\x00")
        return RandBin(l)


class StrFixedLenPaddedField(StrFixedLenField):
    """Packet field that has a fixed length and is padded with a
    given character.
    """
    __slots__ = ["length_from", "padd"]

    def __init__(self, name, default, length=None, length_from=None, padd=" "):
        StrFixedLenField.__init__(self, name, default, length, length_from)
        self.padd = padd

    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        return s[l:], self.m2i(pkt, s[:l])

    def addfield(self, pkt, s, val):
        l = self.length_from(pkt)
        val += self.padd * l
        return StrFixedLenField.addfield(self, pkt, s, val)


class StrNullFixedLenPaddedField(StrFixedLenField):
    """Packet field that has a fixed length and is padded with a
    given character and null terminated.
    """
    __slots__ = ["length_from", "padd"]

    def __init__(self, name, default, length=None, length_from=None, padd=" "):
        StrFixedLenField.__init__(self, name, default, length, length_from)
        self.padd = padd

    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        lz = s.find("\x00")
        if lz < l:
            return s[l + 1:], self.m2i(pkt, s[:lz])
        return s[l + 1:], self.m2i(pkt, s[:l])

    def addfield(self, pkt, s, val):
        l = self.length_from(pkt)
        val += self.padd * l
        return StrFixedLenField.addfield(self, pkt, s, val)


class IntToStrField(Field):
    """Custom field from int to str values, with a variable length
    """
    __slots__ = ["length", "format"]

    def __init__(self, name, default, length=11):
        """Initialize the field with a variable length. The 'machine'
        representation is a string field and the 'internal' repr.
        is a numeric value.
        """
        Field.__init__(self, name, default, "%ds" % length)
        # Stores the length of the field
        self.length = length
        # Stores the conversion format between representations
        self.format = "%" + "%d" % length + "d"

    def m2i(self, pkt, x):
        return str(x)

    def i2m(self, pkt, x):
        return self.format % int(x)

    def i2count(self, pkt, x):
        return x


class StrEncodedPaddedField(StrField):
    __slots__ = ["remain", "encoding", "padd"]

    def __init__(self, name, default, encoding="utf-16", padd="\x0c",
                 fmt="H", remain=0):
        StrField.__init__(self, name, default, fmt, remain)
        self.encoding = encoding
        self.padd = padd

    def h2i(self, pkt, x):
        if x:
            x = x.encode(self.encoding)
        return x

    def i2h(self, pkt, x):
        if x:
            x = x.decode(self.encoding)
        return x

    def addfield(self, pkt, s, val):
        return s + self.i2m(pkt, val) + self.padd

    def getfield(self, pkt, s):
        l = s.find(self.padd)
        if l < 0:
            return "", s
        return s[l + 1:], self.m2i(pkt, s[:l])


class PacketListStopField(PacketListField):
    """Custom field that contains a list of packets until a 'stop' condition is met.
    """
    __slots__ = ["count_from", "length_from", "stop"]

    def __init__(self, name, default, cls, count_from=None, length_from=None, stop=None):
        PacketListField.__init__(self, name, default, cls, count_from=count_from, length_from=length_from)
        self.stop = stop

    def getfield(self, pkt, s):
        c = l = None
        if self.length_from is not None:
            l = self.length_from(pkt)
        elif self.count_from is not None:
            c = self.count_from(pkt)

        lst = []
        ret = ""
        remain = s
        if l is not None:
            remain, ret = s[:l], s[l:]
        while remain:
            if c is not None:
                if c <= 0:
                    break
                c -= 1
            try:
                p = self.m2i(pkt, remain)
            except Exception:
                if conf.debug_dissector:
                    raise
                p = conf.raw_layer(load=remain)
                remain = ""
            else:
                if conf.padding_layer in p:
                    pad = p[conf.padding_layer]
                    remain = pad.load
                    del (pad.underlayer.payload)
                else:
                    remain = ""
            lst.append(p)
            # Evaluate the stop condition
            if self.stop and self.stop(p):
                break
        return remain + ret, lst
