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

# Standard imports
from binascii import unhexlify
from os import environ
from os.path import join as join, dirname


REPO_ROOT = dirname(dirname(__file__))


def data_filename(filename):
    return join(dirname(__file__), 'data', filename)


def script_env():
    """Build an environment for subprocess tests that import the local checkout."""
    env = environ.copy()
    pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = REPO_ROOT if not pythonpath else REPO_ROOT + ":" + pythonpath
    return env


def read_data_file(filename, unhex=True):
    filename = data_filename(filename)
    if unhex:
        with open(filename, 'r') as f:
            data = f.read()
        data = data.replace('\n', ' ').replace(' ', '')
        data = unhexlify(data)
    else:
        with open(filename, 'rb') as f:
            data = f.read()

    return data


def roundtrip_packet(packet):
    """Build and dissect a packet instance back into the same class."""
    return packet.__class__(bytes(packet))


class DummyConnection(object):
    """Simple stand-in for socket-like test doubles."""

    def __init__(self, recv_values=None):
        self.sent = []
        self.recv_values = list(recv_values or [])
        self.closed = False

    def send(self, packet):
        self.sent.append(packet)

    def recv(self):
        return self.recv_values.pop(0)

    def close(self):
        self.closed = True
