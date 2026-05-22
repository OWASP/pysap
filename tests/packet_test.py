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

import importlib
import inspect
import pkgutil

import pytest


def library_packet_class_examples():
    """Default instances for every concrete packet class defined by pysap."""
    import pysap
    from scapy.packet import Packet

    for module_info in pkgutil.walk_packages(pysap.__path__, pysap.__name__ + "."):
        if module_info.ispkg:
            continue
        module = importlib.import_module(module_info.name)
        for name, cls in inspect.getmembers(module, inspect.isclass):
            if not issubclass(cls, Packet):
                continue
            if cls.__module__ != module.__name__:
                continue
            if name in ["PacketNoPadded"]:
                continue
            yield "%s.%s" % (module.__name__, name), cls()


def documented_packet_examples():
    """Packets exercised by the protocol notebooks' visual examples."""
    from pysap.SAPDiag import SAPDiag, SAPDiagDP, SAPDiagError, SAPDiagItem
    from pysap.SAPEnqueue import (SAPEnqueue, SAPEnqueueParam,
                                  SAPEnqueueTracePattern,
                                  enqueue_conn_admin_opcode_values,
                                  enqueue_dest_values,
                                  enqueue_param_values,
                                  enqueue_server_admin_opcode_values)
    from pysap.SAPHDB import (SAPHDB, SAPHDBInitializationReply,
                              SAPHDBInitializationRequest,
                              SAPHDBMultiLineOptionPartRow, SAPHDBOptionPartRow,
                              SAPHDBPart, SAPHDBPartAuthentication,
                              SAPHDBPartAuthenticationField,
                              SAPHDBPartClientId, SAPHDBPartCommand,
                              SAPHDBPartError, SAPHDBSegment,
                              hdb_partkind_values, hdb_segmentkind_values)
    from pysap.SAPIGS import SAPIGS, SAPIGSTable
    from pysap.SAPMS import (SAPDPInfo1, SAPDPInfo2, SAPDPInfo3, SAPMS,
                             SAPMSAdmRecord, SAPMSClient1, SAPMSClient2,
                             SAPMSClient3, SAPMSClient4, SAPMSCounter,
                             SAPMSJ2EECluster, SAPMSJ2EEHeader,
                             SAPMSJ2EEService, SAPMSLogon, SAPMSProperty,
                             SAPMSStat3, ms_adm_opcode_values, ms_iflag_values,
                             ms_opcode_values)
    from pysap.SAPNI import SAPNI
    from pysap.SAPRFC import (SAPCPIC, SAPCPIC2, SAPCPICPARAM, SAPCPICPARAM2,
                              SAPCPICSUFFIX, SAPCPIC_CUT, SAPRFC, SAPRFCDTStruct,
                              SAPRFCEXTEND, SAPRFCPING, SAPRFCTHStruct,
                              SAPRFXPG, SAPRFXPG_END, rfc_monitor_cmd_values,
                              rfc_req_type_values)
    from pysap.SAPRouter import (SAPRouter, SAPRouterError, SAPRouterInfoClient,
                                 SAPRouterInfoClients, SAPRouterInfoServer,
                                 SAPRouterRouteHop, router_adm_commands,
                                 router_control_opcodes)
    from pysap.SAPSNC import SAPSNCFrame

    yield "SAPDiagDP", SAPDiagDP()
    yield "SAPDiag", SAPDiag()
    for item_type in [0x01, 0x10, 0x11, 0x12]:
        yield "SAPDiagItem %d" % item_type, SAPDiagItem(item_type=item_type, item_value=b"")
    yield "SAPDiagError", SAPDiagError()

    for dest in enqueue_dest_values:
        yield "SAPEnqueue dest %d" % dest, SAPEnqueue(dest=dest)
    for opcode in enqueue_server_admin_opcode_values:
        yield "SAPEnqueue server admin %d" % opcode, SAPEnqueue(dest=3, opcode=opcode)
    for opcode in enqueue_conn_admin_opcode_values:
        yield "SAPEnqueue conn admin %d" % opcode, SAPEnqueue(dest=6, opcode=opcode)
    for param in enqueue_param_values:
        yield "SAPEnqueueParam %d" % param, SAPEnqueueParam(param=param)
    yield "SAPEnqueueTracePattern", SAPEnqueueTracePattern(len=5, pattern=b"TRACE")

    yield "SAPHDBInitializationRequest", SAPHDBInitializationRequest()
    yield "SAPHDBInitializationReply", SAPHDBInitializationReply()
    yield "SAPHDB", SAPHDB()
    for segment_kind in hdb_segmentkind_values:
        yield "SAPHDBSegment %d" % segment_kind, SAPHDBSegment(segmentkind=segment_kind)
    for part_kind in hdb_partkind_values:
        yield "SAPHDBPart %d" % part_kind, SAPHDBPart(partkind=part_kind)
    auth_fields = [
        SAPHDBPartAuthenticationField(value=b"username"),
        SAPHDBPartAuthenticationField(value=b"SCRAMSHA256"),
        SAPHDBPartAuthenticationField(value=b"XXXXX"),
    ]
    yield "SAPHDBPartAuthentication", SAPHDBPartAuthentication(auth_fields=auth_fields)
    yield "SAPHDBPartClientId", SAPHDBPartClientId(clientid=b"pid@hostname")
    yield "SAPHDBPartCommand", SAPHDBPartCommand(command=b"command")
    yield "SAPHDBPartError", SAPHDBPartError()
    yield "SAPHDBOptionPartRow", SAPHDBOptionPartRow()
    yield "SAPHDBMultiLineOptionPartRow", SAPHDBMultiLineOptionPartRow()

    yield "SAPIGS", SAPIGS()
    yield "SAPIGSTable", SAPIGSTable()

    for iflag in ms_iflag_values:
        yield "SAPMS iflag %d" % iflag, SAPMS(iflag=iflag)
    for opcode in ms_opcode_values:
        if opcode in [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x0a, 0x11, 0x1c, 0x22, 0x23, 0x24,
                      0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
                      0x2d, 0x2e, 0x2f, 0x30, 0x43, 0x44, 0x45, 0x46,
                      0x47, 0x4a]:
            yield "SAPMS opcode %d" % opcode, SAPMS(iflag=1, opcode=opcode)
    for client_cls in [SAPMSClient1, SAPMSClient2, SAPMSClient3, SAPMSClient4]:
        yield client_cls.__name__, client_cls()
    yield "SAPMSStat3", SAPMSStat3()
    yield "SAPMSLogon", SAPMSLogon()
    yield "SAPMSCounter", SAPMSCounter()
    for adm_opcode in [0x01, 0x15, 0x2e]:
        yield "SAPMSAdmRecord %s" % ms_adm_opcode_values[adm_opcode], SAPMSAdmRecord(opcode=adm_opcode)
    for dp_info_cls in [SAPDPInfo1, SAPDPInfo2, SAPDPInfo3]:
        yield dp_info_cls.__name__, dp_info_cls()
    yield "SAPMSProperty", SAPMSProperty(client=b"CLIENT", id=0x07,
                                         release=b"720", patchno=1,
                                         supplvl=2, platform=3)
    for j2ee_cls in [SAPMSJ2EEHeader, SAPMSJ2EECluster, SAPMSJ2EEService]:
        yield j2ee_cls.__name__, j2ee_cls()

    yield "SAPNI", SAPNI() / b"Some content"

    for version in [2, 3]:
        for req_type in rfc_req_type_values:
            yield "SAPRFC version %d req %d" % (version, req_type), SAPRFC(version=version, req_type=req_type)
    for command in rfc_monitor_cmd_values:
        yield "SAPRFC monitor %d" % command, SAPRFC(req_type=9, cmd=command)
    yield "SAPRFCEXTEND", SAPRFCEXTEND()
    yield "SAPRFCDTStruct", SAPRFCDTStruct()
    yield "SAPCPICSUFFIX", SAPCPICSUFFIX()
    yield "SAPCPICPARAM", SAPCPICPARAM(ip="0.0.0.0", mask="0.0.0.0")
    yield "SAPCPICPARAM2", SAPCPICPARAM2(ip="0.0.0.0", mask="0.0.0.0")
    yield "SAPRFCTHStruct", SAPRFCTHStruct()
    yield "SAPRFXPG", SAPRFXPG()
    yield "SAPRFCPING", SAPRFCPING()
    yield "SAPCPIC", SAPCPIC()
    yield "SAPCPIC2", SAPCPIC2()
    yield "SAPRFXPG_END", SAPRFXPG_END()
    yield "SAPCPIC_CUT", SAPCPIC_CUT()

    for command in router_adm_commands:
        yield "SAPRouter admin %d" % command, SAPRouter(type=SAPRouter.SAPROUTER_ADMIN,
                                                        adm_command=command)
    for opcode in router_control_opcodes:
        packet = SAPRouter(type=SAPRouter.SAPROUTER_CONTROL, opcode=opcode)
        if opcode in [70, 71]:
            packet.snc_frame = b""
        yield "SAPRouter control %d" % opcode, packet
    hop = SAPRouterRouteHop(hostname="8.8.8.8", port="3299")
    yield "SAPRouterRouteHop", hop
    yield "SAPRouter pong", SAPRouter(type=SAPRouter.SAPROUTER_PONG)
    yield "SAPRouterError", SAPRouterError(error=b"connection refused", return_code="-94")
    yield "SAPRouterInfoServer", SAPRouterInfoServer(pid=1234, ppid=1,
                                                     port=3299, pport=3200)
    yield "SAPRouterInfoClient", SAPRouterInfoClient(id=1, address="127.0.0.1",
                                                     partner="10.0.0.1",
                                                     service="3200")
    yield "SAPRouterInfoClients", SAPRouterInfoClients(
        clients=[SAPRouterInfoClient(id=1, address="127.0.0.1",
                                     partner="10.0.0.1", service="3200")])

    yield "SAPSNCFrame", SAPSNCFrame() / b"Some content"


def packet_examples():
    for name, packet in library_packet_class_examples():
        yield name, packet
    for name, packet in documented_packet_examples():
        yield "variant %s" % name, packet


def renderable_packet_examples():
    """Packets that can be rendered with Scapy's field-based canvas_dump."""
    from scapy.asn1packet import ASN1_Packet

    for name, packet in packet_examples():
        if isinstance(packet, ASN1_Packet):
            continue
        yield name, packet


def scapy_canvas_dump_available():
    """Return whether Scapy's PyX-backed packet rendering is available."""
    from scapy.packet import PYX

    return bool(PYX)


@pytest.mark.unit
@pytest.mark.parametrize("name,packet", list(packet_examples()))
def test_packet_examples_build_and_dissect(name, packet):
    raw_packet = bytes(packet)
    packet.__class__(raw_packet)


@pytest.mark.slow
@pytest.mark.packet_visual
@pytest.mark.skipif(not scapy_canvas_dump_available(),
                    reason="Scapy canvas_dump requires PyX and pdflatex")
@pytest.mark.parametrize("name,packet", list(renderable_packet_examples()))
def test_packet_examples_render_canvas(name, packet):
    assert packet.canvas_dump() is not None, name
