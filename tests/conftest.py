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

from scapy.config import conf
from scapy.interfaces import NetworkInterfaceDict
import socket

import pytest

conf.route_autoload = False
conf.route6_autoload = False


def _skip_interface_reload(self):
    return None


NetworkInterfaceDict.reload = _skip_interface_reload


def _can_create_listening_socket():
    try:
        sock = socket.socket()
        try:
            sock.bind(("127.0.0.1", 0))
            sock.listen(1)
        finally:
            sock.close()
    except OSError:
        return False
    return True


def pytest_collection_modifyitems(config, items):
    if _can_create_listening_socket():
        return

    skip_integration = pytest.mark.skip(reason="listening sockets are unavailable in this environment")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)
