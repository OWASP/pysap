# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# SECUREAUTH LABS. Copyright (C) 2019 SecureAuth Corporation. All rights reserved.
#
# The library was designed and developed by Martin Gallo from
# the SecureAuth Labs team.
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

# External imports
from scapy.layers.inet import TCP
from scapy.packet import Packet, bind_layers


class SAPHDB(Packet):
    """SAP HANA SQL Command Network Protocol packet

    This packet is used for the HANA SQL Command Network Protocol
    """
    name = "SAP HANA SQL Command Network Protocol"
    fields_desc = [
    ]


# Bind SAP NI with the HDB ports
bind_layers(TCP, SAPHDB, dport=30013)
bind_layers(TCP, SAPHDB, dport=30015)
