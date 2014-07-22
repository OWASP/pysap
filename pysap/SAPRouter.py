# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# Copyright (C) 2014 Core Security Technologies
#
# The library was designed and developed by Martin Gallo from the Security
# Consulting Services team of Core Security Technologies.
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
from scapy.fields import ByteField, ShortField,\
    ConditionalField, StrField, IntField, StrNullField, PacketListField,\
    FieldLenField, FieldListField, SignedIntEnumField, StrFixedLenField,\
    PacketField
# Custom imports
from pysap.SAPNI import SAPNI
from pysap.SAPSNC import SAPSNCFrame
from pysap.utils import PacketNoPadded, ByteEnumKeysField, StrNullFixedLenField


# Router Opcode values
router_control_opcodes = {
    0: "Error information",
    1: "Version request",
    2: "Version response",
    5: "Send Handle (5)",            # TODO: Check this opcodes
    6: "Send Handle (6)",            # TODO: Check this opcodes
    8: "Send Handle (8)",            # TODO: Check this opcodes
    70: "SNC request",
    71: "SNC handshake complete",
    }
""" Router Opcode values """


# Router Return Code values (as per SAP Note 63342 http://service.sap.com/sap/support/notes/63342)
router_return_codes = {
    -1: "NI-internal error (NIEINTERN)",
    -2: "Host name unknown (NIEHOST_UNKNOWN)",
    -3: "Service unknown (NIESERV_UNKNOWN)",
    -4: "Service already used (NIESERV_USED)",
    -5: "Time limit reached (NIETIMEOUT)",
    -6: "Connection to partner broken (NIECONN_BROKEN)",
    -7: "Data range too small (NIETOO_SMALL)",
    -8: "Invalid parameters (NIEINVAL)",
    -9: "Wake-Up (without data) (NIEWAKEUP)",
    -10: "Connection setup failed (NIECONN_REFUSED)",
    -11: "PING/PONG signal received (NIEPING)",
    -12: "Connection to partner via NiRouter not yet set up (NIECONN_PENDING)",
    -13: "Invalid version (NIEVERSION)",
    -14: "Local hostname cannot be found (NIEMYHOSTNAME)",
    -15: "No free port in range (NIENOFREEPORT)",
    -16: "Local hostname invalid (NIEMYHOST_VERIFY)",
    -17: "Error in the SNC shift in the saprouter ==> (NIESNC_FAILURE)",
    -18: "Opcode received (NIEOPCODE)",
    -19: "queue limit reached, next package not accepted (NIEQUE_FULL)",
    -20: "Requested package too large (NIETOO_BIG)",
    -90: "Host name unknown (NIEROUT_HOST_UNKNOWN)",
    -91: "Service unknown (NIEROUT_SERV_UNKNOWN)",
    -92: "Connection setup failed (NIEROUT_CONN_REFUSED)",
    -93: "NI-internal errors (NIEROUT_INTERN)",
    -94: "Connect from source to destination not allowed (NIEROUT_PERM_DENIED)",
    -95: "Connection terminated (NIEROUT_CONN_BROKEN)",
    -96: "Invalid client version (NIEROUT_VERSION)",
    -97: "Connection cancelled by administrator (NIEROUT_CANCELED)",
    -98: "saprouter shutdown (NIEROUT_SHUTDOWN)",
    -99: "Information request refused (NIEROUT_INFO_DENIED)",
    -100: "Max. number of clients reached (NIEROUT_OVERFLOW)",
    -101: "Talkmode not allowed (NIEROUT_MODE_DENIED)",
    -102: "Client not available (NIEROUT_NOCLIENT)",
    -103: "Error in external library (NIEROUT_EXTERN)",
    -104: "Error in the SNC shift (NIEROUT_SNC_FAILURE)",
}
""" Router Return Code values """


# Router Administration Command values
router_adm_commands = {
    2: "Information Request",
    3: "New Route Table Request",
    4: "Toggle Trace Request",
    5: "Stop Request",
    6: "Cancel Route Request",
    7: "Dump Buffers Request",
    8: "Flush Buffers Request",
    9: "Soft Shutdown Request",
    10: "Set Trace Peer",
    11: "Clear Trace Peer",
    12: "Trace Connection",
    13: "Trace Connection",
    14: "Hide Error Information Request",
    }
""" Router Administration Command values """


# Router NI Talk mode values
router_ni_talk_mode_values = {
    0: "NI_MSG_IO",
    1: "NI_RAW_IO",
    2: "NI_ROUT_IO",
    }
""" Router NI Talk mode values """


class SAPRouterRouteHop(PacketNoPadded):
    """
    SAP Router Protocol Route Hop

    This packet is used to describe a hop in a route using the SAP Router.
    """
    name = "SAP Router Route Hop"
    fields_desc = [
        StrNullField("hostname", ""),
        StrNullField("port", ""),
        StrNullField("password", ""),
        ]


def router_is_route(pkt):
    """
    Returns if the packet is a Route packet.

    @param pkt: packet to look at
    @type pkt: L{SAPRouter}

    @return: if the type of the packet is Route
    @rtype: C{bool}
    """
    return pkt.type == SAPRouter.SAPROUTER_ROUTE


def router_is_admin(pkt):
    """
    Returns if the packet is a Admin packet.

    @param pkt: packet to look at
    @type pkt: L{SAPRouter}

    @return: if the type of the packet is Admin
    @rtype: C{bool}
    """
    return pkt.type == SAPRouter.SAPROUTER_ADMIN


def router_is_error(pkt):
    """
    Returns if the packet is a Error Information packet.

    @param pkt: packet to look at
    @type pkt: L{SAPRouter}

    @return: if the type of the packet is Error
    @rtype: C{bool}
    """
    return pkt.type == SAPRouter.SAPROUTER_ERROR


def router_is_control(pkt):
    """
    Returns if the packet is a Control packet.

    @param pkt: packet to look at
    @type pkt: L{SAPRouter}

    @return: if the type of the packet is Control
    @rtype: C{bool}
    """
    return pkt.type == SAPRouter.SAPROUTER_CONTROL


def router_is_pong(pkt):
    """
    Returns if the packet is a Pong (route accepted) packet.

    @param pkt: packet to look at
    @type pkt: L{SAPRouter}

    @return: if the type of the packet is Pong
    @rtype: C{bool}
    """
    return pkt.type == SAPRouter.SAPROUTER_PONG


def router_is_known_type(pkt):
    """
    Returns if the packet is of a known type (Admin, Route, Error or Pong).

    @param pkt: packet to look at
    @type pkt: L{SAPRouter}

    @return: if the type of the packet is known
    @rtype: C{bool}

    """
    return pkt.type in SAPRouter.router_type_values


class SAPRouter(Packet):
    """
    SAP Router packet

    This packet is used for general SAP Router packets. There are (at least) five
    types of SAP Router packets:

        1. Route packets. For requesting the routing of a connection to a remote
        hosts. The packet contains some general information and a connection string
        with a list of routing hops (L{SAPRouterRouteHop}).

        2. Administration packets. This packet is used for the SAP Router to send
        administrative commands. It's suppose to be used only from the hosts
        running the SAP Router or when an specific route is included in the
        routing table. Generally administration packets are not accepted from the
        external binding.

        3. Error Information packets. Packets sent when an error occurred.

        4. Control Message packets. Used to perform some control activities, like
        retrieving the current SAPRouter version or to perform the SNC handshake.
        They have the same structure that error information packets.

        5. Route accepted packet. Used to acknowledge a route request ("NI_PONG").


    Routed packets and some responses doesn't fill in these five packet
    types. For identifying those cases, you should check the type using the
    function L{router_is_known_type}.

    NI Versions found (unconfirmed):
        - 36: Release <6.20
        - 38: Release 7.00/7.10
        - 40: Release 7.20/7.21
    """

    # Constants for router types
    SAPROUTER_ROUTE = "NI_ROUTE"
    """ @cvar: Constant for route packets
        @type: C{string} """

    SAPROUTER_ADMIN = "ROUTER_ADM"
    """ @cvar: Constant for administration packets
        @type: C{string} """

    SAPROUTER_ERROR = "NI_RTERR"
    """ @cvar: Constant for error information packets
        @type: C{string} """

    SAPROUTER_CONTROL = "NI_RTERR"
    """ @cvar: Constant for control messages packets
        @type: C{string} """

    SAPROUTER_PONG = "NI_PONG"
    """ @cvar: Constant for route accepted packets
        @type: C{string} """

    router_type_values = [
        SAPROUTER_ADMIN,
        SAPROUTER_ERROR,
        SAPROUTER_CONTROL,
        SAPROUTER_ROUTE,
        SAPROUTER_PONG,
        ]
    """ @cvar: List of known packet types
        @type: C{list} of C{string} """

    name = "SAP Router"
    fields_desc = [
        # General fields present in all SAP Router packets
        StrNullField("type", SAPROUTER_ROUTE),

        ConditionalField(ByteField("version", 0x02), lambda pkt:router_is_known_type(pkt) and not router_is_pong(pkt)),

        # Route packets
        ConditionalField(ByteField("route_ni_version", 0x28), router_is_route),
        ConditionalField(ByteField("route_entries", 0), router_is_route),
        ConditionalField(ByteEnumKeysField("route_talk_mode", 0, router_ni_talk_mode_values), router_is_route),
        ConditionalField(ShortField("route_padd", 0), router_is_route),
        ConditionalField(ByteField("route_rest_nodes", 0), router_is_route),
        ConditionalField(FieldLenField("route_length", 0, length_of="route_string", fmt="I"), router_is_route),
        ConditionalField(IntField("route_offset", 0), router_is_route),
        ConditionalField(PacketListField("route_string", None, SAPRouterRouteHop,
                                         length_from=lambda pkt:pkt.route_length), router_is_route),

        # Admin packets
        ConditionalField(ByteEnumKeysField("adm_command", 0x02, router_adm_commands), router_is_admin),
        ConditionalField(ShortField("adm_unused", 0x00), lambda pkt:router_is_admin(pkt) and pkt.adm_command not in [10, 11, 12, 13]),

        # Info Request fields
        ConditionalField(StrNullFixedLenField("adm_password", "", 19), lambda pkt:router_is_admin(pkt) and pkt.adm_command in [2]),

        # Cancel Route fields
        ConditionalField(FieldLenField("adm_client_count", None, count_of="adm_client_ids", fmt="H"), lambda pkt:router_is_admin(pkt) and pkt.adm_command in [6]),
        ConditionalField(FieldListField("adm_client_ids", [0x00], IntField("", 0), count_from=lambda pkt:pkt.adm_client_count), lambda pkt:router_is_admin(pkt) and pkt.adm_command in [6]),

        # Trace Connection fields
        ConditionalField(FieldLenField("adm_client_count", None, count_of="adm_client_ids", fmt="I"), lambda pkt:router_is_admin(pkt) and pkt.adm_command in [12, 13]),
        ConditionalField(FieldListField("adm_client_ids", [0x00], IntField("", 0), count_from=lambda pkt:pkt.adm_client_count), lambda pkt:router_is_admin(pkt) and pkt.adm_command in [12, 13]),

        # Set/Clear Peer Trace fields  # TODO: Check whether this field should be a IPv6 address or another proper field
        ConditionalField(StrFixedLenField("adm_address_mask", "", 32), lambda pkt:router_is_admin(pkt) and pkt.adm_command in [10, 11]),

        # Error Information/Control Messages fields
        ConditionalField(ByteEnumKeysField("opcode", 0, router_control_opcodes), lambda pkt: router_is_error(pkt) or router_is_control(pkt)),
        ConditionalField(ByteField("opcode_padd", 0), lambda pkt: router_is_error(pkt) or router_is_control(pkt)),
        ConditionalField(SignedIntEnumField("return_code", 0, router_return_codes), lambda pkt: router_is_error(pkt) or router_is_control(pkt)),

        # Error Information fields
        ConditionalField(FieldLenField("err_text_length", None, length_of="err_text_value", fmt="!I"), lambda pkt: router_is_error(pkt) and pkt.opcode == 0),
        ConditionalField(FieldListField("err_text_value", [""], StrNullField("", "")), lambda pkt: router_is_error(pkt) and pkt.opcode == 0),

        # Control Message fields
        ConditionalField(IntField("control_text_length", 0), lambda pkt: router_is_control(pkt) and pkt.opcode != 0),
        ConditionalField(StrField("control_text_value", "*ERR"), lambda pkt: router_is_control(pkt) and pkt.opcode != 0),

        # SNC Frame fields
        ConditionalField(PacketField("snc_frame", None, SAPSNCFrame), lambda pkt: router_is_control(pkt) and pkt.opcode in [70, 71])
        ]


# Retrieve the version of the remote SAP Router
def get_router_version(connection):
    """ Helper function to retrieve the version of a remote SAP Router.

    @param connection: connection with the SAP Router
    @type connection: L{SAPNIStreamSocket}

    @return: version or None
    """
    r = connection.sr(SAPRouter(type=SAPRouter.SAPROUTER_CONTROL, version=40, opcode=1))
    if router_is_control(r) and r.opcode == 2:
        return r.version
    else:
        return None


# Bind SAP NI with the SAP Router port
bind_layers(TCP, SAPNI, dport=3999)

# Bind SAP NI with SAP Router
bind_layers(SAPNI, SAPRouter, )
