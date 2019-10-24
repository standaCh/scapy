#! /usr/bin/env python

# Copyright (C) 2019 Travelping GmbH <info@travelping.com>

# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# scapy.contrib.description = 3GPP Packet Forwarding Control Protocol (3GPP TS 29.244)
# scapy.contrib.status = loads

import struct


from scapy.compat import chb, orb
from scapy.error import warning
from scapy.fields import BitEnumField, BitField, ByteEnumField, ByteField, \
    ConditionalField, FieldLenField, FieldListField, FlagsField, IntField, \
    IPField, PacketListField, ShortField, StrFixedLenField, StrLenField, \
    XBitField, XByteField, XIntField
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6, IP6Field
from scapy.layers.ppp import PPP
from scapy.modules.six.moves import range
from scapy.packet import bind_layers, bind_bottom_up, bind_top_down, \
    Packet, Raw
from scapy.volatile import RandInt, RandIP, RandNum, RandString



PFCPmessageType = {
    1: "heartbeat_request",
    2: "heartbeat_response",
    3: "pfd_management_request",
    4: "pfd_management_response",
    5: "association_setup_request",
    6: "association_setup_response",
    7: "association_update_request",
    8: "association_update_response",
    9: "association_release_request",
    10: "association_release_response",
    11: "version_not_supported_response",
    12: "node_report_request",
    13: "node_report_response",
    14: "session_set_deletion_request",
    15: "session_set_deletion_response",
    50: "session_establishment_request",
    51: "session_establishment_response",
    52: "session_modification_request",
    53: "session_modification_response",
    54: "session_deletion_request",
    55: "session_deletion_response",
    56: "session_report_request",
    57: "session_report_response",
}

IEType = {
    0: "Reserved",
    1: "Create PDR",
    2: "PDI",
    3: "Create FAR",
    4: "Forwarding Parameters",
    5: "Duplicating Parameters",
    6: "Create URR",
    7: "Create QER",
    8: "Created PDR",
    9: "Update PDR",
    10: "Update FAR",
    11: "Update Forwarding Parameters",
    12: "Update BAR (PFCP Session Report Response)",
    13: "Update URR",
    14: "Update QER",
    15: "Remove PDR",
    16: "Remove FAR",
    17: "Remove URR",
    18: "Remove QER",
    19: "Cause",
    20: "Source Interface",
    21: "F-TEID",
    22: "Network Instance",
    23: "SDF Filter",
    24: "Application ID",
    25: "Gate Status",
    26: "MBR",
    27: "GBR",
    28: "QER Correlation ID",
    29: "Precedence",
    30: "Transport Level Marking",
    31: "Volume Threshold",
    32: "Time Threshold",
    33: "Monitoring Time",
    34: "Subsequent Volume Threshold",
    35: "Subsequent Time Threshold",
    36: "Inactivity Detection Time",
    37: "Reporting Triggers",
    38: "Redirect Information",
    39: "Report Type",
    40: "Offending IE",
    41: "Forwarding Policy",
    42: "Destination Interface",
    43: "UP Function Features",
    44: "Apply Action",
    45: "Downlink Data Service Information",
    46: "Downlink Data Notification Delay",
    47: "DL Buffering Duration",
    48: "DL Buffering Suggested Packet Count",
    49: "PFCPSMReq-Flags",
    50: "PFCPSRRsp-Flags",
    51: "Load Control Information",
    52: "Sequence Number",
    53: "Metric",
    54: "Overload Control Information",
    55: "Timer",
    56: "PDR ID",
    57: "F-SEID",
    58: "Application ID's PFDs",
    59: "PFD context",
    60: "Node ID",
    61: "PFD contents",
    62: "Measurement Method",
    63: "Usage Report Trigger",
    64: "Measurement Period",
    65: "FQ-CSID",
    66: "Volume Measurement",
    67: "Duration Measurement",
    68: "Application Detection Information",
    69: "Time of First Packet",
    70: "Time of Last Packet",
    71: "Quota Holding Time",
    72: "Dropped DL Traffic Threshold",
    73: "Volume Quota",
    74: "Time Quota",
    75: "Start Time",
    76: "End Time",
    77: "Query URR",
    78: "Usage Report (Session Modification Response)",
    79: "Usage Report (Session Deletion Response)",
    80: "Usage Report (Session Report Request)",
    81: "URR ID",
    82: "Linked URR ID",
    83: "Downlink Data Report",
    84: "Outer Header Creation",
    85: "Create BAR",
    86: "Update BAR (Session Modification Request)",
    87: "Remove BAR",
    88: "BAR ID",
    89: "CP Function Features",
    90: "Usage Information",
    91: "Application Instance ID",
    92: "Flow Information",
    93: "UE IP Address",
    94: "Packet Rate",
    95: "Outer Header Removal",
    96: "Recovery Time Stamp",
    97: "DL Flow Level Marking",
    98: "Header Enrichment",
    99: "Error Indication Report",
    100: "Measurement Information",
    101: "Node Report Type",
    102: "User Plane Path Failure Report",
    103: "Remote GTP-U Peer",
    104: "UR-SEQN",
    105: "Update Duplicating Parameters",
    106: "Activate Predefined Rules",
    107: "Deactivate Predefined Rules",
    108: "FAR ID",
    109: "QER ID",
    110: "OCI Flags",
    111: "PFCP Association Release Request",
    112: "Graceful Release Period",
    113: "PDN Type",
    114: "Failed Rule ID",
    115: "Time Quota Mechanism",
    116: "User Plane IP Resource Information",
    117: "User Plane Inactivity Timer",
    118: "Aggregated URRs",
    119: "Multiplier",
    120: "Aggregated URR ID",
    121: "Subsequent Volume Quota",
    122: "Subsequent Time Quota",
    123: "RQI",
    124: "QFI",
    125: "Query URR Reference",
    126: "Additional Usage Reports Information",
    127: "Create Traffic Endpoint",
    128: "Created Traffic Endpoint",
    129: "Update Traffic Endpoint",
    130: "Remove Traffic Endpoint",
    131: "Traffic Endpoint ID",
    132: "Ethernet Packet Filter",
    133: "MAC address",
    134: "C-TAG",
    135: "S-TAG",
    136: "Ethertype",
    137: "Proxying",
    138: "Ethernet Filter ID",
    139: "Ethernet Filter Properties",
    140: "Suggested Buffering Packets Count",
    141: "User ID",
    142: "Ethernet PDU Session Information",
    143: "Ethernet Traffic Information",
    144: "MAC Addresses Detected",
    145: "MAC Addresses Removed",
    146: "Ethernet Inactivity Timer",
    147: "Additional Monitoring Time",
    148: "Event Quota",
    149: "Event Threshold",
    150: "Subsequent Event Quota",
    151: "Subsequent Event Threshold",
    152: "Trace Information",
    153: "Framed-Route",
    154: "Framed-Routing",
    155: "Framed-IPv6-Route",
    156: "Event Time Stamp",
    157: "Averaging Window",
    158: "Paging Policy Indicator",
    159: "APN/DNN",
    160: "3GPP Interface Type",
}

CauseValues = {
    0: "Reserved",
    1: "Request accepted",
    64: "Request rejected",
    65: "Session context not found",
    66: "Mandatory IE missing",
    67: "Conditional IE missing",
    68: "Invalid length",
    69: "Mandatory IE incorrect",
    70: "Invalid Forwarding Policy",
    71: "Invalid F-TEID allocation option",
    72: "No established Sx Association",
    73: "Rule creation/modification Failure",
    74: "PFCP entity in congestion",
    75: "No resources available",
    76: "Service not supported",
    77: "System failure",
}

SourceInterface = {
    0: "Access",
    1: "Core",
    2: "SGi-LAN/N6-LAN",
    3: "CP-function",
}

DestinationInterface = {
    0: "Access",
    1: "Core",
    2: "SGi-LAN/N6-LAN",
    3: "CP-function",
    4: "LI function",
}

class PFCPHeader(Packet):
    # 3GPP TS 29.244 V15.6.0 (2019-07)
    # without the version
    name = "PFCP (v1) Header"
    fields_desc = [BitField("version", 1, 3),
                   BitField("SPARE", 0, 1),
                   BitField("SPARE", 0, 1),
                   BitField("SPARE", 0, 1),
                   BitField("MP", 0, 1),
                   BitField("S", 1, 1),
                   ByteEnumField("message_type", None, PFCPmessageType),
                   ShortField("length", None),
                   ConditionalField(XLongField("seid", 0),
                                    lambda pkt:pkt.S == 1),
                   ThreeBytesField("seq", RandShort()),
                   ConditionalField(BitField("priority", 0, 4),
                                    lambda pkt:pkt.MP == 1),
                   ConditionalField(BitField("SPARE", 0, 4),
                                    lambda pkt:pkt.MP == 1),
                   ConditionalField(ByteField("SPARE", 0),
                                    lambda pkt:pkt.MP == 0),
                   ]

    def post_build(self, p, pay):
        p += pay
        if self.length is None:
            tmp_len = len(p) - 8
            p = p[:2] + struct.pack("!H", tmp_len) + p[4:]
        return p

    def hashret(self):
        return struct.pack("B", self.version) + self.payload.hashret()

    def answers(self, other):
        return (isinstance(other, PFCPHeader) and
                self.version == other.version and
                self.payload.answers(other.payload))


class APNStrLenField(StrLenField):
    # Inspired by DNSStrField
    def m2i(self, pkt, s):
        ret_s = b""
        tmp_s = s
        while tmp_s:
            tmp_len = orb(tmp_s[0]) + 1
            if tmp_len > len(tmp_s):
                warning("APN prematured end of character-string (size=%i, remaining bytes=%i)" % (tmp_len, len(tmp_s)))  # noqa: E501
            ret_s += tmp_s[1:tmp_len]
            tmp_s = tmp_s[tmp_len:]
            if len(tmp_s):
                ret_s += b"."
        s = ret_s
        return s

    def i2m(self, pkt, s):
        s = b"".join(chb(len(x)) + x for x in s.split("."))
        return s

def IE_Dispatcher(s):
    """Choose the correct Information Element class."""

    # Get the IE type
    ietype = (orb(s[0]) * 256) + orb(s[1])
    cls = ietypecls.get(ietype, Raw)

    if cls is Raw:
        cls = IE_NotImplemented

    return cls(s)

class IE_Base(Packet):

    def extract_padding(self, pkt):
        return "", pkt

    def post_build(self, p, pay):
        p += pay
        if self.length is None:
            tmp_len = len(p) - 4
            p = p[:2] + struct.pack("!H", tmp_len) + p[4:]
        return p

class IE_CreatePDR(IE_Base):
    name = "IE Create PDR"
    fields_desc = [ShortEnumField("ietype", 1, IEType),
                   ShortField("length", None),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]

class IE_PDI(IE_Base):
    name = "IE PDI"
    fields_desc = [ShortEnumField("ietype", 2, IEType),
                   ShortField("length", None),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]

class IE_CreateFAR(IE_Base):
    name = "IE Create FAR"
    fields_desc = [ShortEnumField("ietype", 3, IEType),
                   ShortField("length", None),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]

class IE_ForwardingParameters(IE_Base):
    name = "IE Forwarding Parameters"
    fields_desc = [ShortEnumField("ietype", 4, IEType),
                   ShortField("length", None),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]

class IE_DuplicatingParameters(IE_Base):
    name = "IE Duplicating Parameters"
    fields_desc = [ShortEnumField("ietype", 5, IEType),
                   ShortField("length", None),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]

class IE_CreateURR(IE_Base):
    name = "IE Create URR"
    fields_desc = [ShortEnumField("ietype", 6, IEType),
                   ShortField("length", None),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]

class IE_CreateQER(IE_Base):
    name = "IE Create QER"
    fields_desc = [ShortEnumField("ietype", 7, IEType),
                   ShortField("length", None),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]

class IE_CreatedPDR(IE_Base):
    name = "IE Created PDR"
    fields_desc = [ShortEnumField("ietype", 8, IEType),
                   ShortField("length", None),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]

class IE_UpdatePDR(IE_Base):
    name = "IE Update PDR"
    fields_desc = [ShortEnumField("ietype", 9, IEType),
                   ShortField("length", None),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]

class IE_UpdateFAR(IE_Base):
    name = "IE Update FAR"
    fields_desc = [ShortEnumField("ietype", 10, IEType),
                   ShortField("length", None),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]

class IE_UpdateForwardingParameters(IE_Base):
    name = "IE Update Forwarding Parameters"
    fields_desc = [ShortEnumField("ietype", 11, IEType),
                   ShortField("length", None),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]

class IE_UpdateBAR_SRR(IE_Base):
    name = "IE Update BAR (PFCP Session Report Response)"
    fields_desc = [ShortEnumField("ietype", 12, IEType),
                   ShortField("length", None),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]

class IE_UpdateURR(IE_Base):
    name = "IE Update URR"
    fields_desc = [ShortEnumField("ietype", 13, IEType),
                   ShortField("length", None),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]

class IE_UpdateQER(IE_Base):
    name = "IE Update QER"
    fields_desc = [ShortEnumField("ietype", 14, IEType),
                   ShortField("length", None),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]

class IE_RemovePDR(IE_Base):
    name = "IE Remove PDR"
    fields_desc = [ShortEnumField("ietype", 15, IEType),
                   ShortField("length", None),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]

class IE_RemoveFAR(IE_Base):
    name = "IE Remove FAR"
    fields_desc = [ShortEnumField("ietype", 16, IEType),
                   ShortField("length", None),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]

class IE_RemoveURR(IE_Base):
    name = "IE Remove URR"
    fields_desc = [ShortEnumField("ietype", 17, IEType),
                   ShortField("length", None),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]

class IE_RemoveQER(IE_Base):
    name = "IE Remove QER"
    fields_desc = [ShortEnumField("ietype", 18, IEType),
                   ShortField("length", None),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]

class IE_Cause(IE_Base):
    name = "IE Cause"
    fields_desc = [ShortEnumField("ietype", 19, IEType),
                   ShortField("length", None),
                   ByteEnumField("Cause", None, CauseValues)]

class IE_SourceInterface(IE_Base):
    name = "IE Source Interface"
    fields_desc = [ShortEnumField("ietype", 20, IEType),
                   ShortField("length", None),
                   XBitField("SPARE", 0, 4),
                   BitEnumField("Interface", "Access", 4, SourceInterface)]

class IE_FqTEID(IE_Base):
    name = "IE F-TEID"
    fields_desc = [ShortEnumField("ietype", 21, IEType),
                   ShortField("length", None),
                   XBitField("SPARE", 0, 4),
                   BitField("CHID", 0, 1),
                   BitField("CH", 0, 1),
                   BitField("V6", 0, 1),
                   BitField("V4", 0, 1),
                   ConditionalField(XIntField("TEID", 0), lambda x: x.CH == 0),
                   ConditionalField(IPField("ipv4", RandIP()),
                                    lambda x: x.V4 == 1 and x.CH == 0),
                   ConditionalField(IP6Field("ipv6", RandIP6()),
                                    lambda x: x.V6 == 1 and x.CH == 0),
                   ConditionalField(ByteField("CHOOSE ID", 0),
                                    lambda x: x.CHID == 1)]

class IE_NetworkInstance(IE_Base):
    name = "IE Network Instance"
    fields_desc = [ShortEnumField("ietype", 22, IEType),
                   ShortField("length", None),
                   APNStrLenField("Network Instance", "", length_from=lambda x: x.length)]

class IE_SDF_Filter(IE_Base):
    name = "IE SDF Filter"
    fields_desc = [ShortEnumField("ietype", 23, IEType),
                   ShortField("length", None),
                   ]

class IE_ApplicationId(IE_Base):
    name = "IE Application ID"
    fields_desc = [ShortEnumField("ietype", 24, IEType),
                   ShortField("length", None),
                   ]

class IE_GateStatus(IE_Base):
    name = "IE Gate Status"
    fields_desc = [ShortEnumField("ietype", 25, IEType),
                   ShortField("length", None),
                   ]

class IE_MBR(IE_Base):
    name = "IE MBR"
    fields_desc = [ShortEnumField("ietype", 26, IEType),
                   ShortField("length", None),
                   ]

class IE_GBR(IE_Base):
    name = "IE GBR"
    fields_desc = [ShortEnumField("ietype", 27, IEType),
                   ShortField("length", None),
                   ]

class IE_QERCorrelationId(IE_Base):
    name = "IE QER Correlation ID"
    fields_desc = [ShortEnumField("ietype", 28, IEType),
                   ShortField("length", None),
                   ]

class IE_Precedence(IE_Base):
    name = "IE Precedence"
    fields_desc = [ShortEnumField("ietype", 29, IEType),
                   ShortField("length", None),
                   IntField("Precedence", RandInt()),
                   ConditionalField(StrLenField("data", "", length_from=lambda x: x.length - 4),
                                    lambda x: x.length > 4)]

class IE_TransportLevelMarking(IE_Base):
    name = "IE Transport Level Marking"
    fields_desc = [ShortEnumField("ietype", 30, IEType),
                   ShortField("length", None),
                   ]

class IE_VolumeThreshold(IE_Base):
    name = "IE Volume Threshold"
    fields_desc = [ShortEnumField("ietype", 31, IEType),
                   ShortField("length", None),
                   ]

class IE_TimeThreshold(IE_Base):
    name = "IE Time Threshold"
    fields_desc = [ShortEnumField("ietype", 32, IEType),
                   ShortField("length", None),
                   ]

class IE_MonitoringTime(IE_Base):
    name = "IE Monitoring Time"
    fields_desc = [ShortEnumField("ietype", 33, IEType),
                   ShortField("length", None),
                   ]

class IE_SubsequentVolumeThreshold(IE_Base):
    name = "IE Subsequent Volume Threshold"
    fields_desc = [ShortEnumField("ietype", 34, IEType),
                   ShortField("length", None),
                   ]

class IE_SubsequentTimeThreshold(IE_Base):
    name = "IE Subsequent Time Threshold"
    fields_desc = [ShortEnumField("ietype", 35, IEType),
                   ShortField("length", None),
                   ]

class IE_InactivityDetectionTime(IE_Base):
    name = "IE Inactivity Detection Time"
    fields_desc = [ShortEnumField("ietype", 36, IEType),
                   ShortField("length", None),
                   ]

class IE_ReportingTriggers(IE_Base):
    name = "IE Reporting Triggers"
    fields_desc = [ShortEnumField("ietype", 37, IEType),
                   ShortField("length", None),
                   ]

class IE_RedirectInformation(IE_Base):
    name = "IE Redirect Information"
    fields_desc = [ShortEnumField("ietype", 38, IEType),
                   ShortField("length", None),
                   ]

class IE_ReportType(IE_Base):
    name = "IE Report Type"
    fields_desc = [ShortEnumField("ietype", 39, IEType),
                   ShortField("length", None),
                   ]

class IE_OffendingIE(IE_Base):
    name = "IE Offending IE"
    fields_desc = [ShortEnumField("ietype", 40, IEType),
                   ShortField("length", None),
                   ]

class IE_ForwardingPolicy(IE_Base):
    name = "IE Forwarding Policy"
    fields_desc = [ShortEnumField("ietype", 41, IEType),
                   ShortField("length", None),
                   ]

class IE_DestinationInterface(IE_Base):
    name = "IE Destination Interface"
    fields_desc = [ShortEnumField("ietype", 42, IEType),
                   ShortField("length", None),
                   XBitField("SPARE", 0, 4),
                   BitEnumField("Interface", "Access", 4, DestinationInterface)]


class IE_UPFunctionFeatures(IE_Base):
    name = "IE UP Function Features"
    fields_desc = [ShortEnumField("ietype", 43, IEType),
                   ShortField("length", 2),
                   ConditionalField(BitField("TREU", None, 1), lambda x: x.length > 0),
                   ConditionalField(BitField("HEEU", None, 1), lambda x: x.length > 0),
                   ConditionalField(BitField("PFDM", None, 1), lambda x: x.length > 0),
                   ConditionalField(BitField("FTUP", None, 1), lambda x: x.length > 0),
                   ConditionalField(BitField("TRST", None, 1), lambda x: x.length > 0),
                   ConditionalField(BitField("DLBD", None, 1), lambda x: x.length > 0),
                   ConditionalField(BitField("DDND", None, 1), lambda x: x.length > 0),
                   ConditionalField(BitField("BUCP", None, 1), lambda x: x.length > 0),
                   ConditionalField(BitField("SPARE", None, 1), lambda x: x.length > 1),
                   ConditionalField(BitField("PFDE", None, 1), lambda x: x.length > 1),
                   ConditionalField(BitField("FRRT", None, 1), lambda x: x.length > 1),
                   ConditionalField(BitField("TRACE", None, 1), lambda x: x.length > 1),
                   ConditionalField(BitField("QUOAC", None, 1), lambda x: x.length > 1),
                   ConditionalField(BitField("UDBC", None, 1), lambda x: x.length > 1),
                   ConditionalField(BitField("PDIU", None, 1), lambda x: x.length > 1),
                   ConditionalField(BitField("EMPU", None, 1), lambda x: x.length > 1)]

class IE_ApplyAction(IE_Base):
    name = "IE Apply Action"
    fields_desc = [ShortEnumField("ietype", 44, IEType),
                   ShortField("length", None),
                   XBitField("SPARE", None, 3),
                   BitField("DUPL", None, 1),
                   BitField("NOCP", None, 1),
                   BitField("BUFF", None, 1),
                   BitField("FORW", None, 1),
                   BitField("DROP", None, 1),
                   ConditionalField(StrLenField("data", "", length_from=lambda x: x.length - 1),
                                    lambda x: x.length > 1)]

class IE_DownlinkDataServiceInformation(IE_Base):
    name = "IE Downlink Data Service Information"
    fields_desc = [ShortEnumField("ietype", 45, IEType),
                   ShortField("length", None),
                   ]

class IE_DownlinkDataNotificationDelay(IE_Base):
    name = "IE Downlink Data Notification Delay"
    fields_desc = [ShortEnumField("ietype", 46, IEType),
                   ShortField("length", None),
                   ]

class IE_DLBufferingDuration(IE_Base):
    name = "IE DL Buffering Duration"
    fields_desc = [ShortEnumField("ietype", 47, IEType),
                   ShortField("length", None),
                   ]

class IE_DLBufferingSuggestedPacketCount(IE_Base):
    name = "IE DL Buffering Suggested Packet Count"
    fields_desc = [ShortEnumField("ietype", 48, IEType),
                   ShortField("length", None),
                   ]

class IE_PFCPSMReqFlags(IE_Base):
    name = "IE PFCPSMReq-Flags"
    fields_desc = [ShortEnumField("ietype", 49, IEType),
                   ShortField("length", None),
                   ]

class IE_PFCPSRRspFlags(IE_Base):
    name = "IE PFCPSRRsp-Flags"
    fields_desc = [ShortEnumField("ietype", 50, IEType),
                   ShortField("length", None),
                   ]

class IE_LoadControlInformation(IE_Base):
    name = "IE Load Control Information"
    fields_desc = [ShortEnumField("ietype", 51, IEType),
                   ShortField("length", None),
                   ]

class IE_SequenceNumber(IE_Base):
    name = "IE Sequence Number"
    fields_desc = [ShortEnumField("ietype", 52, IEType),
                   ShortField("length", None),
                   ]

class IE_Metric(IE_Base):
    name = "IE Metric"
    fields_desc = [ShortEnumField("ietype", 53, IEType),
                   ShortField("length", None),
                   ]

class IE_OverloadControlInformation(IE_Base):
    name = "IE Overload Control Information"
    fields_desc = [ShortEnumField("ietype", 54, IEType),
                   ShortField("length", None),
                   ]

class IE_Timer(IE_Base):
    name = "IE Timer"
    fields_desc = [ShortEnumField("ietype", 55, IEType),
                   ShortField("length", None),
                   ]

class IE_PDR_Id(IE_Base):
    name = "IE PDR ID"
    fields_desc = [ShortEnumField("ietype", 56, IEType),
                   ShortField("length", None),
                   ConditionalField(ShortField("PDRid", RandShort()), lambda x: x.length > 1),
                   ConditionalField(StrLenField("data", "", length_from=lambda x: x.length - 4),
                                    lambda x: x.length > 4)]

class IE_FqSEID(IE_Base):
    name = "IE F-SEID"
    fields_desc = [ShortEnumField("ietype", 57, IEType),
                   ShortField("length", None),
                   XBitField("SPARE", 0, 6),
                   BitField("V4", 0, 1),
                   BitField("V6", 0, 1),
                   XLongField("seid", 0),
                   ConditionalField(IPField("ipv4", RandIP()),
                                    lambda x: x.V4 == 1),
                   ConditionalField(IP6Field("ipv6", RandIP6()),
                                    lambda x: x.V6 == 1)]

class IE_ApplicationID_PFDs(IE_Base):
    name = "IE Application ID's PFDs"
    fields_desc = [ShortEnumField("ietype", 58, IEType),
                   ShortField("length", None),
                   ]

class IE_PFDContext(IE_Base):
    name = "IE PFD context"
    fields_desc = [ShortEnumField("ietype", 59, IEType),
                   ShortField("length", None),
                   ]

NodeIdType = {
    0: "IPv4",
    1: "IPv6",
    2: "FQDN",
}

class IE_NodeId(IE_Base):
    name = "IE Node ID"
    fields_desc = [ShortEnumField("ietype", 60, IEType),
                   ShortField("length", None),
                   BitField("SPARE", 0, 4),
                   BitEnumField("NodeIdType", "IPv4", 4, NodeIdType),
                   ConditionalField(IPField("IPv4", RandIP()),
                                    lambda x: x.NodeIdType == 0),
                   ConditionalField(IP6Field("IPv6", RandIP6()),
                                    lambda x: x.NodeIdType == 1),
                   ConditionalField(
                       APNStrLenField("node_id", "", length_from=lambda x: x.length - 1),
                       lambda x: x.NodeIdType == 2)]

class IE_PFDContents(IE_Base):
    name = "IE PFD contents"
    fields_desc = [ShortEnumField("ietype", 61, IEType),
                   ShortField("length", None),
                   ]

class IE_MeasurementMethod(IE_Base):
    name = "IE Measurement Method"
    fields_desc = [ShortEnumField("ietype", 62, IEType),
                   ShortField("length", None),
                   ]

class IE_UsageReportTrigger(IE_Base):
    name = "IE Usage Report Trigger"
    fields_desc = [ShortEnumField("ietype", 63, IEType),
                   ShortField("length", None),
                   ]

class IE_MeasurementPeriod(IE_Base):
    name = "IE Measurement Period"
    fields_desc = [ShortEnumField("ietype", 64, IEType),
                   ShortField("length", None),
                   ]

class IE_FqCSID(IE_Base):
    name = "IE FQ-CSID"
    fields_desc = [ShortEnumField("ietype", 65, IEType),
                   ShortField("length", None),
                   ]

class IE_VolumeMeasurement(IE_Base):
    name = "IE Volume Measurement"
    fields_desc = [ShortEnumField("ietype", 66, IEType),
                   ShortField("length", None),
                   ]

class IE_DurationMeasurement(IE_Base):
    name = "IE Duration Measurement"
    fields_desc = [ShortEnumField("ietype", 67, IEType),
                   ShortField("length", None),
                   ]

class IE_ApplicationDetectionInformation(IE_Base):
    name = "IE Application Detection Information"
    fields_desc = [ShortEnumField("ietype", 68, IEType),
                   ShortField("length", None),
                   ]

class IE_TimeOfFirstPacket(IE_Base):
    name = "IE Time of First Packet"
    fields_desc = [ShortEnumField("ietype", 69, IEType),
                   ShortField("length", None),
                   ]

class IE_TimeOfLastPacket(IE_Base):
    name = "IE Time of Last Packet"
    fields_desc = [ShortEnumField("ietype", 70, IEType),
                   ShortField("length", None),
                   ]

class IE_QuotaHoldingTime(IE_Base):
    name = "IE Quota Holding Time"
    fields_desc = [ShortEnumField("ietype", 71, IEType),
                   ShortField("length", None),
                   ]

class IE_DroppedDLTrafficThreshold(IE_Base):
    name = "IE Dropped DL Traffic Threshold"
    fields_desc = [ShortEnumField("ietype", 72, IEType),
                   ShortField("length", None),
                   ]

class IE_VolumeQuota(IE_Base):
    name = "IE Volume Quota"
    fields_desc = [ShortEnumField("ietype", 73, IEType),
                   ShortField("length", None),
                   ]

class IE_TimeQuota(IE_Base):
    name = "IE Time Quota"
    fields_desc = [ShortEnumField("ietype", 74, IEType),
                   ShortField("length", None),
                   ]

class IE_StartTime(IE_Base):
    name = "IE Start Time"
    fields_desc = [ShortEnumField("ietype", 75, IEType),
                   ShortField("length", None),
                   ]

class IE_EndTime(IE_Base):
    name = "IE End Time"
    fields_desc = [ShortEnumField("ietype", 76, IEType),
                   ShortField("length", None),
                   ]

class IE_QueryURR(IE_Base):
    name = "IE Query URR"
    fields_desc = [ShortEnumField("ietype", 77, IEType),
                   ShortField("length", None),
                   ]

class IE_UsageReport_SMR(IE_Base):
    name = "IE Usage Report (Session Modification Response)"
    fields_desc = [ShortEnumField("ietype", 78, IEType),
                   ShortField("length", None),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]

class IE_UsageReport_SDR(IE_Base):
    name = "IE Usage Report (Session Deletion Response)"
    fields_desc = [ShortEnumField("ietype", 79, IEType),
                   ShortField("length", None),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]

class IE_UsageReport_SRR(IE_Base):
    name = "IE Usage Report (Session Report Request)"
    fields_desc = [ShortEnumField("ietype", 80, IEType),
                   ShortField("length", None),
                   PacketListField("IE_list", None, IE_Dispatcher,
                                   length_from=lambda pkt: pkt.length)]

class IE_URR_Id(IE_Base):
    name = "IE URR ID"
    fields_desc = [ShortEnumField("ietype", 81, IEType),
                   ShortField("length", None),
                   ]

class IE_LinkedURR_Id(IE_Base):
    name = "IE Linked URR ID"
    fields_desc = [ShortEnumField("ietype", 82, IEType),
                   ShortField("length", None),
                   ]

class IE_DownlinkDataReport(IE_Base):
    name = "IE Downlink Data Report"
    fields_desc = [ShortEnumField("ietype", 83, IEType),
                   ShortField("length", None),
                   ]

class IE_OuterHeaderCreation(IE_Base):
    name = "IE Outer Header Creation"
    fields_desc = [ShortEnumField("ietype", 84, IEType),
                   ShortField("length", None),
                   ]

class IE_Create_BAR(IE_Base):
    name = "IE Create BAR"
    fields_desc = [ShortEnumField("ietype", 85, IEType),
                   ShortField("length", None),
                   ]

class IE_Update_BAR_SMR(IE_Base):
    name = "IE Update BAR (Session Modification Request)"
    fields_desc = [ShortEnumField("ietype", 86, IEType),
                   ShortField("length", None),
                   ]

class IE_Remove_BAR(IE_Base):
    name = "IE Remove BAR"
    fields_desc = [ShortEnumField("ietype", 87, IEType),
                   ShortField("length", None),
                   ]

class IE_BAR_Id(IE_Base):
    name = "IE BAR ID"
    fields_desc = [ShortEnumField("ietype", 88, IEType),
                   ShortField("length", None),
                   ]

class IE_CPFunctionFeatures(IE_Base):
    name = "IE CP Function Features"
    fields_desc = [ShortEnumField("ietype", 89, IEType),
                   ShortField("length", None),
                   ]

class IE_UsageInformation(IE_Base):
    name = "IE Usage Information"
    fields_desc = [ShortEnumField("ietype", 90, IEType),
                   ShortField("length", None),
                   ]

class IE_ApplicationInstanceId(IE_Base):
    name = "IE Application Instance ID"
    fields_desc = [ShortEnumField("ietype", 91, IEType),
                   ShortField("length", None),
                   ]

class IE_FlowInformation(IE_Base):
    name = "IE Flow Information"
    fields_desc = [ShortEnumField("ietype", 92, IEType),
                   ShortField("length", None),
                   ]

class IE_UE_IP_Address(IE_Base):
    name = "IE UE IP Address"
    fields_desc = [ShortEnumField("ietype", 93, IEType),
                   ShortField("length", None),
                   ]

class IE_PacketRate(IE_Base):
    name = "IE Packet Rate"
    fields_desc = [ShortEnumField("ietype", 94, IEType),
                   ShortField("length", None),
                   ]

OuterHeaderRemovalDescription = {
    0: "GTP-U/UDP/IPv4",
    1: "GTP-U/UDP/IPv6",
    2: "UDP/IPv4",
    3: "UDP/IPv6",
    4: "IPv4",
    5: "IPv6",
    6: "GTP-U/UDP/IP",
    7: "VLAN S-TAG",
    8: "S-TAG and C-TAG",
}

class IE_OuterHeaderRemoval(IE_Base):
    name = "IE Outer Header Removal"
    fields_desc = [ShortEnumField("ietype", 95, IEType),
                   ShortField("length", None),
                   ByteEnumField("OuterHeaderRemoval", None, OuterHeaderRemovalDescription),
                   ConditionalField(XBitField("SPARE", None, 7), lambda x: x.length > 1),
                   ConditionalField(BitField("PDU Session Container", None, 1), lambda x: x.length > 1)]

class IE_RecoveryTimeStamp(IE_Base):
    name = "IE Recovery Time Stamp"
    fields_desc = [ShortEnumField("ietype", 96, IEType),
                   ShortField("length", 4),
                   IntField("Recovery Time Stamp", RandInt())
                   ]

class IE_DLFlowLevelMarking(IE_Base):
    name = "IE DL Flow Level Marking"
    fields_desc = [ShortEnumField("ietype", 97, IEType),
                   ShortField("length", None),
                   ]

class IE_HeaderEnrichment(IE_Base):
    name = "IE Header Enrichment"
    fields_desc = [ShortEnumField("ietype", 98, IEType),
                   ShortField("length", None),
                   ]

class IE_ErrorIndicationReport(IE_Base):
    name = "IE Error Indication Report"
    fields_desc = [ShortEnumField("ietype", 99, IEType),
                   ShortField("length", None),
                   ]

class IE_MeasurementInformation(IE_Base):
    name = "IE Measurement Information"
    fields_desc = [ShortEnumField("ietype", 100, IEType),
                   ShortField("length", None),
                   ]

class IE_NodeReportType(IE_Base):
    name = "IE Node Report Type"
    fields_desc = [ShortEnumField("ietype", 101, IEType),
                   ShortField("length", None),
                   ]

class IE_UserPlanePathFailureReport(IE_Base):
    name = "IE User Plane Path Failure Report"
    fields_desc = [ShortEnumField("ietype", 102, IEType),
                   ShortField("length", None),
                   ]

class IE_RemoteGTP_U_Peer(IE_Base):
    name = "IE Remote GTP-U Peer"
    fields_desc = [ShortEnumField("ietype", 103, IEType),
                   ShortField("length", None),
                   ]

class IE_UR_SEQN(IE_Base):
    name = "IE UR-SEQN"
    fields_desc = [ShortEnumField("ietype", 104, IEType),
                   ShortField("length", None),
                   ]

class IE_UpdateDuplicatingParameters(IE_Base):
    name = "IE Update Duplicating Parameters"
    fields_desc = [ShortEnumField("ietype", 105, IEType),
                   ShortField("length", None),
                   ]

class IE_ActivatePredefinedRules(IE_Base):
    name = "IE Activate Predefined Rules"
    fields_desc = [ShortEnumField("ietype", 106, IEType),
                   ShortField("length", None),
                   ]

class IE_DeactivatePredefinedRules(IE_Base):
    name = "IE Deactivate Predefined Rules"
    fields_desc = [ShortEnumField("ietype", 107, IEType),
                   ShortField("length", None),
                   ]

class IE_FAR_Id(IE_Base):
    name = "IE FAR ID"
    fields_desc = [ShortEnumField("ietype", 108, IEType),
                   ShortField("length", None),
                   ConditionalField(IntField("FARid", RandInt()), lambda x: x.length > 3),
                   ConditionalField(StrLenField("data", "", length_from=lambda x: x.length - 4),
                                    lambda x: x.length > 4)]

class IE_QER_Id(IE_Base):
    name = "IE QER ID"
    fields_desc = [ShortEnumField("ietype", 109, IEType),
                   ShortField("length", None),
                   ConditionalField(IntField("QERid", RandInt()), lambda x: x.length > 3),
                   ConditionalField(StrLenField("data", "", length_from=lambda x: x.length - 4),
                                    lambda x: x.length > 4)]

class IE_OCIFlags(IE_Base):
    name = "IE OCI Flags"
    fields_desc = [ShortEnumField("ietype", 110, IEType),
                   ShortField("length", None),
                   ]

class IE_PFCPAssociationReleaseRequest(IE_Base):
    name = "IE PFCP Association Release Request"
    fields_desc = [ShortEnumField("ietype", 111, IEType),
                   ShortField("length", None),
                   ]

class IE_GracefulReleasePeriod(IE_Base):
    name = "IE Graceful Release Period"
    fields_desc = [ShortEnumField("ietype", 112, IEType),
                   ShortField("length", None),
                   ]

class IE_PDNType(IE_Base):
    name = "IE PDN Type"
    fields_desc = [ShortEnumField("ietype", 113, IEType),
                   ShortField("length", None),
                   ]

class IE_FailedRuleId(IE_Base):
    name = "IE Failed Rule ID"
    fields_desc = [ShortEnumField("ietype", 114, IEType),
                   ShortField("length", None),
                   ]

class IE_TimeQuotaMechanism(IE_Base):
    name = "IE Time Quota Mechanism"
    fields_desc = [ShortEnumField("ietype", 115, IEType),
                   ShortField("length", None),
                   ]

class IE_UserPlaneIPResourceInformation(IE_Base):
    name = "IE User Plane IP Resource Information"
    fields_desc = [ShortEnumField("ietype", 116, IEType),
                   ShortField("length", None),
                   XBitField("SPARE", 0, 1),
                   BitField("ASSOSI", 0, 1),
                   BitField("ASSONI", 0, 1),
                   BitField("TEIDRI", 0, 3),
                   BitField("V6", 0, 1),
                   BitField("V4", 0, 1),
                   ConditionalField(XByteField("TEIDrange", 0), lambda x: x.TEIDRI != 0),
                   ConditionalField(IPField("ipv4", RandIP()),
                                    lambda x: x.V4 == 1),
                   ConditionalField(IP6Field("ipv6", RandIP6()),
                                    lambda x: x.V6 == 1),
                   ConditionalField(
                       APNStrLenField("Network Instance", "",
                                   length_from=lambda x: x.length - 1 - (1 if x.TEIDRI != 0 else 0) - (x.V4 * 4) - (x.V6 * 16) - x.ASSOSI),
                       lambda x: x.ASSONI == 1),
                   ConditionalField(XBitField("SPARE", None, 4), lambda x: x.ASSOSI == 1),
                   ConditionalField(BitEnumField("Interface", "Access", 4, SourceInterface),
                                    lambda x: x.ASSOSI == 1)]


class IE_UserPlaneInactivityTimer(IE_Base):
    name = "IE User Plane Inactivity Timer"
    fields_desc = [ShortEnumField("ietype", 117, IEType),
                   ShortField("length", None),
                   ]

class IE_AggregatedURRs(IE_Base):
    name = "IE Aggregated URRs"
    fields_desc = [ShortEnumField("ietype", 118, IEType),
                   ShortField("length", None),
                   ]

class IE_Multiplier(IE_Base):
    name = "IE Multiplier"
    fields_desc = [ShortEnumField("ietype", 119, IEType),
                   ShortField("length", None),
                   ]

class IE_AggregatedURR_Id(IE_Base):
    name = "IE Aggregated URR ID"
    fields_desc = [ShortEnumField("ietype", 120, IEType),
                   ShortField("length", None),
                   ConditionalField(IntField("URRid", RandInt()), lambda x: x.length > 3),
                   ConditionalField(StrLenField("data", "", length_from=lambda x: x.length - 4),
                                    lambda x: x.length > 4)]

class IE_SubsequentVolumeQuota(IE_Base):
    name = "IE Subsequent Volume Quota"
    fields_desc = [ShortEnumField("ietype", 121, IEType),
                   ShortField("length", None),
                   ]

class IE_SubsequentTimeQuota(IE_Base):
    name = "IE Subsequent Time Quota"
    fields_desc = [ShortEnumField("ietype", 122, IEType),
                   ShortField("length", None),
                   ]

class IE_RQI(IE_Base):
    name = "IE RQI"
    fields_desc = [ShortEnumField("ietype", 123, IEType),
                   ShortField("length", None),
                   ]

class IE_QFI(IE_Base):
    name = "IE QFI"
    fields_desc = [ShortEnumField("ietype", 124, IEType),
                   ShortField("length", None),
                   ]

class IE_QueryURRReference(IE_Base):
    name = "IE Query URR Reference"
    fields_desc = [ShortEnumField("ietype", 125, IEType),
                   ShortField("length", None),
                   ]

class IE_AdditionalUsageReportsInformation(IE_Base):
    name = "IE Additional Usage Reports Information"
    fields_desc = [ShortEnumField("ietype", 126, IEType),
                   ShortField("length", None),
                   ]

class IE_CreateTrafficEndpoint(IE_Base):
    name = "IE Create Traffic Endpoint"
    fields_desc = [ShortEnumField("ietype", 127, IEType),
                   ShortField("length", None),
                   ]

class IE_CreatedTrafficEndpoint(IE_Base):
    name = "IE Created Traffic Endpoint"
    fields_desc = [ShortEnumField("ietype", 128, IEType),
                   ShortField("length", None),
                   ]

class IE_UpdateTrafficEndpoint(IE_Base):
    name = "IE Update Traffic Endpoint"
    fields_desc = [ShortEnumField("ietype", 129, IEType),
                   ShortField("length", None),
                   ]

class IE_RemoveTrafficEndpoint(IE_Base):
    name = "IE Remove Traffic Endpoint"
    fields_desc = [ShortEnumField("ietype", 130, IEType),
                   ShortField("length", None),
                   ]

class IE_TrafficEndpointId(IE_Base):
    name = "IE Traffic Endpoint ID"
    fields_desc = [ShortEnumField("ietype", 131, IEType),
                   ShortField("length", None),
                   ]

class IE_EthernetPacketFilter(IE_Base):
    name = "IE Ethernet Packet Filter"
    fields_desc = [ShortEnumField("ietype", 132, IEType),
                   ShortField("length", None),
                   ]

class IE_MACaddress(IE_Base):
    name = "IE MAC address"
    fields_desc = [ShortEnumField("ietype", 133, IEType),
                   ShortField("length", None),
                   ]

class IE_C_TAG(IE_Base):
    name = "IE C-TAG"
    fields_desc = [ShortEnumField("ietype", 134, IEType),
                   ShortField("length", None),
                   ]

class IE_S_TAG(IE_Base):
    name = "IE S-TAG"
    fields_desc = [ShortEnumField("ietype", 135, IEType),
                   ShortField("length", None),
                   ]

class IE_Ethertype(IE_Base):
    name = "IE Ethertype"
    fields_desc = [ShortEnumField("ietype", 136, IEType),
                   ShortField("length", None),
                   ]

class IE_Proxying(IE_Base):
    name = "IE Proxying"
    fields_desc = [ShortEnumField("ietype", 137, IEType),
                   ShortField("length", None),
                   ]

class IE_EthernetFilterId(IE_Base):
    name = "IE Ethernet Filter ID"
    fields_desc = [ShortEnumField("ietype", 138, IEType),
                   ShortField("length", None),
                   ]

class IE_EthernetFilterProperties(IE_Base):
    name = "IE Ethernet Filter Properties"
    fields_desc = [ShortEnumField("ietype", 139, IEType),
                   ShortField("length", None),
                   ]

class IE_SuggestedBufferingPacketsCount(IE_Base):
    name = "IE Suggested Buffering Packets Count"
    fields_desc = [ShortEnumField("ietype", 140, IEType),
                   ShortField("length", None),
                   ]

class IE_UserId(IE_Base):
    name = "IE User ID"
    fields_desc = [ShortEnumField("ietype", 141, IEType),
                   ShortField("length", None),
                   ]

class IE_EthernetPDUSessionInformation(IE_Base):
    name = "IE Ethernet PDU Session Information"
    fields_desc = [ShortEnumField("ietype", 142, IEType),
                   ShortField("length", None),
                   ]

class IE_EthernetTrafficInformation(IE_Base):
    name = "IE Ethernet Traffic Information"
    fields_desc = [ShortEnumField("ietype", 143, IEType),
                   ShortField("length", None),
                   ]

class IE_MACAddressesDetected(IE_Base):
    name = "IE MAC Addresses Detected"
    fields_desc = [ShortEnumField("ietype", 144, IEType),
                   ShortField("length", None),
                   ]

class IE_MACAddressesRemoved(IE_Base):
    name = "IE MAC Addresses Removed"
    fields_desc = [ShortEnumField("ietype", 145, IEType),
                   ShortField("length", None),
                   ]

class IE_EthernetInactivityTimer(IE_Base):
    name = "IE Ethernet Inactivity Timer"
    fields_desc = [ShortEnumField("ietype", 146, IEType),
                   ShortField("length", None),
                   ]

class IE_AdditionalMonitoringTime(IE_Base):
    name = "IE Additional Monitoring Time"
    fields_desc = [ShortEnumField("ietype", 147, IEType),
                   ShortField("length", None),
                   ]

class IE_EventQuota(IE_Base):
    name = "IE Event Quota"
    fields_desc = [ShortEnumField("ietype", 148, IEType),
                   ShortField("length", None),
                   ]

class IE_EventThreshold(IE_Base):
    name = "IE Event Threshold"
    fields_desc = [ShortEnumField("ietype", 149, IEType),
                   ShortField("length", None),
                   ]

class IE_SubsequentEventQuota(IE_Base):
    name = "IE Subsequent Event Quota"
    fields_desc = [ShortEnumField("ietype", 150, IEType),
                   ShortField("length", None),
                   ]

class IE_SubsequentEventThreshold(IE_Base):
    name = "IE Subsequent Event Threshold"
    fields_desc = [ShortEnumField("ietype", 151, IEType),
                   ShortField("length", None),
                   ]

class IE_TraceInformation(IE_Base):
    name = "IE Trace Information"
    fields_desc = [ShortEnumField("ietype", 152, IEType),
                   ShortField("length", None),
                   ]

class IE_FramedRoute(IE_Base):
    name = "IE Framed-Route"
    fields_desc = [ShortEnumField("ietype", 153, IEType),
                   ShortField("length", None),
                   ]

class IE_FramedRouting(IE_Base):
    name = "IE Framed-Routing"
    fields_desc = [ShortEnumField("ietype", 154, IEType),
                   ShortField("length", None),
                   ]

class IE_FramedIPv6Route(IE_Base):
    name = "IE Framed-IPv6-Route"
    fields_desc = [ShortEnumField("ietype", 155, IEType),
                   ShortField("length", None),
                   ]

class IE_EventTimeStamp(IE_Base):
    name = "IE Event Time Stamp"
    fields_desc = [ShortEnumField("ietype", 156, IEType),
                   ShortField("length", None),
                   ]

class IE_AveragingWindow(IE_Base):
    name = "IE Averaging Window"
    fields_desc = [ShortEnumField("ietype", 157, IEType),
                   ShortField("length", None),
                   ]

class IE_PagingPolicyIndicator(IE_Base):
    name = "IE Paging Policy Indicator"
    fields_desc = [ShortEnumField("ietype", 158, IEType),
                   ShortField("length", None),
                   ]

class IE_APN_DNN(IE_Base):
    name = "IE APN/DNN"
    fields_desc = [ShortEnumField("ietype", 159, IEType),
                   ShortField("length", None),
                   ]

class IE_3GPP_InterfaceType(IE_Base):
    name = "IE 3GPP Interface Type"
    fields_desc = [ShortEnumField("ietype", 160, IEType),
                   ShortField("length", None),
                   ]

class IE_NotImplemented(IE_Base):
    name = "IE not implemented"
    fields_desc = [ShortEnumField("ietype", 0, IEType),
                   ShortField("length", None),
                   StrLenField("data", "", length_from=lambda x: x.length)]

# class IE_IPv4(gtp.IE_Base):
#     name = "IE IPv4"
#     fields_desc = [ByteEnumField("ietype", 74, IEType),
#                    ShortField("length", 0),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    IPField("address", RandIP())]
#
# class IE_MEI(gtp.IE_Base):
#     name = "IE MEI"
#     fields_desc = [ByteEnumField("ietype", 75, IEType),
#                    ShortField("length", 0),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    LongField("MEI", 0)]
#
# class IE_EPSBearerID(gtp.IE_Base):
#     name = "IE EPS Bearer ID"
#     fields_desc = [ByteEnumField("ietype", 73, IEType),
#                    ShortField("length", 0),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    ByteField("EBI", 0)]
#
#
# class IE_RAT(gtp.IE_Base):
#     name = "IE RAT"
#     fields_desc = [ByteEnumField("ietype", 82, IEType),
#                    ShortField("length", 0),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    ByteEnumField("RAT_type", None, RATType)]
#
#
# class IE_ServingNetwork(gtp.IE_Base):
#     name = "IE Serving Network"
#     fields_desc = [ByteEnumField("ietype", 83, IEType),
#                    ShortField("length", 0),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    gtp.TBCDByteField("MCC", "", 2),
#                    gtp.TBCDByteField("MNC", "", 1)]
#
#
# class ULI_RAI(gtp.IE_Base):
#     name = "IE Tracking Area Identity"
#     fields_desc = [
#         gtp.TBCDByteField("MCC", "", 2),
#         # MNC: if the third digit of MCC is 0xf, then the length of
#         # MNC is 1 byte
#         gtp.TBCDByteField("MNC", "", 1),
#         ShortField("LAC", 0),
#         ShortField("RAC", 0)]
#
#
# class ULI_SAI(gtp.IE_Base):
#     name = "IE Tracking Area Identity"
#     fields_desc = [
#         gtp.TBCDByteField("MCC", "", 2),
#         gtp.TBCDByteField("MNC", "", 1),
#         ShortField("LAC", 0),
#         ShortField("SAC", 0)]
#
#
# class ULI_TAI(gtp.IE_Base):
#     name = "IE Tracking Area Identity"
#     fields_desc = [
#         gtp.TBCDByteField("MCC", "", 2),
#         gtp.TBCDByteField("MNC", "", 1),
#         ShortField("TAC", 0)]
#
#
# class ULI_ECGI(gtp.IE_Base):
#     name = "IE E-UTRAN Cell Identifier"
#     fields_desc = [
#         gtp.TBCDByteField("MCC", "", 2),
#         gtp.TBCDByteField("MNC", "", 1),
#         BitField("SPARE", 0, 4),
#         BitField("ECI", 0, 28)]
#
#
# class IE_ULI(gtp.IE_Base):
#     name = "IE ULI"
#     fields_desc = [ByteEnumField("ietype", 86, IEType),
#                    ShortField("length", 0),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    BitField("SPARE", 0, 2),
#                    BitField("LAI_Present", 0, 1),
#                    BitField("ECGI_Present", 0, 1),
#                    BitField("TAI_Present", 0, 1),
#                    BitField("RAI_Present", 0, 1),
#                    BitField("SAI_Present", 0, 1),
#                    BitField("CGI_Present", 0, 1),
#                    ConditionalField(
#         PacketField("SAI", 0, ULI_SAI), lambda pkt: bool(pkt.SAI_Present)),
#         ConditionalField(
#         PacketField("RAI", 0, ULI_RAI), lambda pkt: bool(pkt.RAI_Present)),
#         ConditionalField(
#         PacketField("TAI", 0, ULI_TAI), lambda pkt: bool(pkt.TAI_Present)),
#         ConditionalField(PacketField("ECGI", 0, ULI_ECGI),
#                          lambda pkt: bool(pkt.ECGI_Present))]
#
#
# class IE_FTEID(gtp.IE_Base):
#     name = "IE F-TEID"
#     fields_desc = [ByteEnumField("ietype", 87, IEType),
#                    ShortField("length", 0),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    BitField("ipv4_present", 0, 1),
#                    BitField("ipv6_present", 0, 1),
#                    BitField("InterfaceType", 0, 6),
#                    XIntField("GRE_Key", 0),
#                    ConditionalField(
#         IPField("ipv4", RandIP()), lambda pkt: pkt.ipv4_present),
#         ConditionalField(XBitField("ipv6", "2001::", 128),
#                          lambda pkt: pkt.ipv6_present)]
#
#
# class IE_BearerContext(gtp.IE_Base):
#     name = "IE Bearer Context"
#     fields_desc = [ByteEnumField("ietype", 93, IEType),
#                    ShortField("length", 0),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    PacketListField("IE_list", None, IE_Dispatcher,
#                                    length_from=lambda pkt: pkt.length)]
#
#
#
#
# class IE_IMSI(gtp.IE_Base):
#     name = "IE IMSI"
#     fields_desc = [ByteEnumField("ietype", 1, IEType),
#                    ShortField("length", None),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    gtp.TBCDByteField("IMSI", "33607080910",
#                                      length_from=lambda x: x.length)]
#
#
# class IE_Cause(gtp.IE_Base):
#     name = "IE Cause"
#     fields_desc = [ByteEnumField("ietype", 2, IEType),
#                    ShortField("length", None),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    ByteEnumField("Cause", 1, CauseValues),
#                    BitField("SPARE", 0, 5),
#                    BitField("PCE", 0, 1),
#                    BitField("BCE", 0, 1),
#                    BitField("CS", 0, 1)]
#
#
# class IE_RecoveryRestart(gtp.IE_Base):
#     name = "IE Recovery Restart"
#     fields_desc = [ByteEnumField("ietype", 3, IEType),
#                    ShortField("length", None),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    ByteField("restart_counter", 0)]
#
#
# class IE_APN(gtp.IE_Base):
#     name = "IE APN"
#     fields_desc = [ByteEnumField("ietype", 71, IEType),
#                    ShortField("length", None),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    gtp.APNStrLenField("APN", "internet",
#                                       length_from=lambda x: x.length)]
#
#
# class IE_AMBR(gtp.IE_Base):
#     name = "IE AMBR"
#     fields_desc = [ByteEnumField("ietype", 72, IEType),
#                    ShortField("length", None),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    IntField("AMBR_Uplink", 0),
#                    IntField("AMBR_Downlink", 0)]
#
#
# class IE_MSISDN(gtp.IE_Base):
#     name = "IE MSISDN"
#     fields_desc = [ByteEnumField("ietype", 76, IEType),
#                    ShortField("length", None),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    gtp.TBCDByteField("digits", "33123456789",
#                                      length_from=lambda x: x.length)]
#
#
# class IE_Indication(gtp.IE_Base):
#     name = "IE Cause"
#     fields_desc = [ByteEnumField("ietype", 77, IEType),
#                    ShortField("length", None),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    BitField("DAF", 0, 1),
#                    BitField("DTF", 0, 1),
#                    BitField("HI", 0, 1),
#                    BitField("DFI", 0, 1),
#                    BitField("OI", 0, 1),
#                    BitField("ISRSI", 0, 1),
#                    BitField("ISRAI", 0, 1),
#                    BitField("SGWCI", 0, 1),
#                    BitField("SQCI", 0, 1),
#                    BitField("UIMSI", 0, 1),
#                    BitField("CFSI", 0, 1),
#                    BitField("CRSI", 0, 1),
#                    BitField("PS", 0, 1),
#                    BitField("PT", 0, 1),
#                    BitField("SI", 0, 1),
#                    BitField("MSV", 0, 1),
#
#                    ConditionalField(
#                        BitField("RetLoc", 0, 1), lambda pkt: pkt.length > 2),
#                    ConditionalField(
#                        BitField("PBIC", 0, 1), lambda pkt: pkt.length > 2),
#                    ConditionalField(
#                        BitField("SRNI", 0, 1), lambda pkt: pkt.length > 2),
#                    ConditionalField(
#                        BitField("S6AF", 0, 1), lambda pkt: pkt.length > 2),
#                    ConditionalField(
#                        BitField("S4AF", 0, 1), lambda pkt: pkt.length > 2),
#                    ConditionalField(
#                        BitField("MBMDT", 0, 1), lambda pkt: pkt.length > 2),
#                    ConditionalField(
#                        BitField("ISRAU", 0, 1), lambda pkt: pkt.length > 2),
#                    ConditionalField(
#                        BitField("CCRSI", 0, 1), lambda pkt: pkt.length > 2),
#
#                    ConditionalField(
#         BitField("CPRAI", 0, 1), lambda pkt: pkt.length > 3),
#         ConditionalField(
#         BitField("ARRL", 0, 1), lambda pkt: pkt.length > 3),
#         ConditionalField(
#         BitField("PPOFF", 0, 1), lambda pkt: pkt.length > 3),
#         ConditionalField(
#         BitField("PPON", 0, 1), lambda pkt: pkt.length > 3),
#         ConditionalField(
#         BitField("PPSI", 0, 1), lambda pkt: pkt.length > 3),
#         ConditionalField(
#         BitField("CSFBI", 0, 1), lambda pkt: pkt.length > 3),
#         ConditionalField(
#         BitField("CLII", 0, 1), lambda pkt: pkt.length > 3),
#         ConditionalField(
#         BitField("CPSR", 0, 1), lambda pkt: pkt.length > 3),
#
#     ]
#
#
# PDN_TYPES = {
#     1: "IPv4",
#     2: "IPv6",
#     3: "IPv4/IPv6",
# }
#
# PCO_OPTION_TYPES = {
#     3: "IPv4",
#     129: "Primary DNS Server IP address",
#     130: "Primary NBNS Server IP address",
#     131: "Secondary DNS Server IP address",
#     132: "Secondary NBNS Server IP address",
# }
#
#
# class PCO_Option(Packet):
#     def extract_padding(self, pkt):
#         return "", pkt
#
#
# class PCO_IPv4(PCO_Option):
#     name = "IPv4"
#     fields_desc = [ByteEnumField("type", None, PCO_OPTION_TYPES),
#                    ByteField("length", 0),
#                    IPField("address", RandIP())]
#
#
# class PCO_Primary_DNS(PCO_Option):
#     name = "Primary DNS Server IP Address"
#     fields_desc = [ByteEnumField("type", None, PCO_OPTION_TYPES),
#                    ByteField("length", 0),
#                    IPField("address", RandIP())]
#
#
# class PCO_Primary_NBNS(PCO_Option):
#     name = "Primary DNS Server IP Address"
#     fields_desc = [ByteEnumField("type", None, PCO_OPTION_TYPES),
#                    ByteField("length", 0),
#                    IPField("address", RandIP())]
#
#
# class PCO_Secondary_DNS(PCO_Option):
#     name = "Secondary DNS Server IP Address"
#     fields_desc = [ByteEnumField("type", None, PCO_OPTION_TYPES),
#                    ByteField("length", 0),
#                    IPField("address", RandIP())]
#
#
# class PCO_Secondary_NBNS(PCO_Option):
#     name = "Secondary NBNS Server IP Address"
#     fields_desc = [ByteEnumField("type", None, PCO_OPTION_TYPES),
#                    ByteField("length", 0),
#                    IPField("address", RandIP())]
#
#
# PCO_PROTOCOL_TYPES = {
#     0x0001: 'P-CSCF IPv6 Address Request',
#     0x0003: 'DNS Server IPv6 Address Request',
#     0x0005: 'MS Support of Network Requested Bearer Control indicator',
#     0x000a: 'IP Allocation via NAS',
#     0x000d: 'DNS Server IPv4 Address Request',
#     0x000c: 'P-CSCF IPv4 Address Request',
#     0x0010: 'IPv4 Link MTU Request',
#     0x8021: 'IPCP',
#     0xc023: 'Password Authentication Protocol',
#     0xc223: 'Challenge Handshake Authentication Protocol',
# }
#
# PCO_OPTION_CLASSES = {
#     3: PCO_IPv4,
#     129: PCO_Primary_DNS,
#     130: PCO_Primary_NBNS,
#     131: PCO_Secondary_DNS,
#     132: PCO_Secondary_NBNS,
# }
#
#
# def PCO_option_dispatcher(s):
#     """Choose the correct PCO element."""
#     option = orb(s[0])
#
#     cls = PCO_OPTION_CLASSES.get(option, Raw)
#     return cls(s)
#
#
# def len_options(pkt):
#     return pkt.length - 4 if pkt.length else 0
#
#
# class PCO_P_CSCF_IPv6_Address_Request(PCO_Option):
#     name = "PCO PCO-P CSCF IPv6 Address Request"
#     fields_desc = [ShortEnumField("type", None, PCO_PROTOCOL_TYPES),
#                    ByteField("length", 0),
#                    ConditionalField(XBitField("address",
#                                               "2001:db8:0:42::", 128),
#                                     lambda pkt: pkt.length)]
#
#
# class PCO_DNS_Server_IPv6(PCO_Option):
#     name = "PCO DNS Server IPv6 Address Request"
#     fields_desc = [ShortEnumField("type", None, PCO_PROTOCOL_TYPES),
#                    ByteField("length", 0),
#                    ConditionalField(XBitField("address",
#                                               "2001:db8:0:42::", 128),
#                                     lambda pkt: pkt.length)]
#
#
# class PCO_SOF(PCO_Option):
#     name = "PCO MS Support of Network Requested Bearer Control indicator"
#     fields_desc = [ShortEnumField("type", None, PCO_PROTOCOL_TYPES),
#                    ByteField("length", 0),
#                    ]
#
#
# class PCO_PPP(PCO_Option):
#     name = "PPP IP Control Protocol"
#     fields_desc = [ByteField("Code", 0),
#                    ByteField("Identifier", 0),
#                    ShortField("length", 0),
#                    PacketListField("Options", None, PCO_option_dispatcher,
#                                    length_from=len_options)]
#
#     def extract_padding(self, pkt):
#         return "", pkt
#
#
# class PCO_IP_Allocation_via_NAS(PCO_Option):
#     name = "PCO IP Address allocation via NAS Signaling"
#     fields_desc = [ShortEnumField("type", None, PCO_PROTOCOL_TYPES),
#                    ByteField("length", 0),
#                    PacketListField("Options", None, PCO_option_dispatcher,
#                                    length_from=len_options)]
#
#
# class PCO_P_CSCF_IPv4_Address_Request(PCO_Option):
#     name = "PCO PCO-P CSCF IPv4 Address Request"
#     fields_desc = [ShortEnumField("type", None, PCO_PROTOCOL_TYPES),
#                    ByteField("length", 0),
#                    ConditionalField(IPField("address", RandIP()),
#                                     lambda pkt: pkt.length)]
#
#
# class PCO_DNS_Server_IPv4(PCO_Option):
#     name = "PCO DNS Server IPv4 Address Request"
#     fields_desc = [ShortEnumField("type", None, PCO_PROTOCOL_TYPES),
#                    ByteField("length", 0),
#                    ConditionalField(IPField("address", RandIP()),
#                                     lambda pkt: pkt.length)]
#
#
# class PCO_IPv4_Link_MTU_Request(PCO_Option):
#     name = "PCO IPv4 Link MTU Request"
#     fields_desc = [ShortEnumField("type", None, PCO_PROTOCOL_TYPES),
#                    ByteField("length", 0),
#                    ConditionalField(ShortField("MTU_size", 1500),
#                                     lambda pkt: pkt.length)]
#
#
# class PCO_IPCP(PCO_Option):
#     name = "PCO Internet Protocol Control Protocol"
#     fields_desc = [ShortEnumField("type", None, PCO_PROTOCOL_TYPES),
#                    ByteField("length", 0),
#                    PacketField("PPP", None, PCO_PPP)]
#
#
# class PCO_PPP_Auth(PCO_Option):
#     name = "PPP Password Authentication Protocol"
#     fields_desc = [ByteField("Code", 0),
#                    ByteField("Identifier", 0),
#                    ShortField("length", 0),
#                    ByteField("PeerID_length", 0),
#                    ConditionalField(StrFixedLenField(
#                        "PeerID",
#                        "",
#                        length_from=lambda pkt: pkt.PeerID_length),
#                        lambda pkt: pkt.PeerID_length),
#                    ByteField("Password_length", 0),
#                    ConditionalField(
#                        StrFixedLenField(
#                            "Password",
#                            "",
#                            length_from=lambda pkt: pkt.Password_length),
#                        lambda pkt: pkt.Password_length)]
#
#
# class PCO_PasswordAuthentificationProtocol(PCO_Option):
#     name = "PCO Password Authentication Protocol"
#     fields_desc = [ShortEnumField("type", None, PCO_PROTOCOL_TYPES),
#                    ByteField("length", 0),
#                    PacketField("PPP", None, PCO_PPP_Auth)]
#
#
# class PCO_PPP_Challenge(PCO_Option):
#     name = "PPP Password Authentication Protocol"
#     fields_desc = [ByteField("Code", 0),
#                    ByteField("Identifier", 0),
#                    ShortField("length", 0),
#                    ByteField("value_size", 0),
#                    ConditionalField(StrFixedLenField(
#                        "value", "",
#                        length_from=lambda pkt: pkt.value_size),
#                        lambda pkt: pkt.value_size),
#                    ConditionalField(StrFixedLenField(
#                        "name", "",
#                        length_from=lambda pkt: pkt.length - pkt.value_size - 5),  # noqa: E501
#                        lambda pkt: pkt.length)]
#
#
# class PCO_ChallengeHandshakeAuthenticationProtocol(PCO_Option):
#     name = "PCO Password Authentication Protocol"
#     fields_desc = [ShortEnumField("type", None, PCO_PROTOCOL_TYPES),
#                    ByteField("length", 0),
#                    PacketField("PPP", None, PCO_PPP_Challenge)]
#
#
# PCO_PROTOCOL_CLASSES = {
#     0x0001: PCO_P_CSCF_IPv6_Address_Request,
#     0x0003: PCO_DNS_Server_IPv6,
#     0x0005: PCO_SOF,
#     0x000a: PCO_IP_Allocation_via_NAS,
#     0x000c: PCO_P_CSCF_IPv4_Address_Request,
#     0x000d: PCO_DNS_Server_IPv4,
#     0x0010: PCO_IPv4_Link_MTU_Request,
#     0x8021: PCO_IPCP,
#     0xc023: PCO_PasswordAuthentificationProtocol,
#     0xc223: PCO_ChallengeHandshakeAuthenticationProtocol,
# }
#
#
# def PCO_protocol_dispatcher(s):
#     """Choose the correct PCO element."""
#     proto_num = orb(s[0]) * 256 + orb(s[1])
#     cls = PCO_PROTOCOL_CLASSES.get(proto_num, Raw)
#     return cls(s)
#
#
# class IE_PCO(gtp.IE_Base):
#     name = "IE Protocol Configuration Options"
#     fields_desc = [ByteEnumField("ietype", 78, IEType),
#                    ShortField("length", None),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    BitField("Extension", 0, 1),
#                    BitField("SPARE", 0, 4),
#                    BitField("PPP", 0, 3),
#                    PacketListField("Protocols", None, PCO_protocol_dispatcher,
#                                    length_from=lambda pkt: pkt.length - 1)]
#
#
# class IE_PAA(gtp.IE_Base):
#     name = "IE PAA"
#     fields_desc = [ByteEnumField("ietype", 79, IEType),
#                    ShortField("length", None),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    BitField("SPARE", 0, 5),
#                    BitEnumField("PDN_type", None, 3, PDN_TYPES),
#                    ConditionalField(
#                        ByteField("ipv6_prefix_length", 8),
#                        lambda pkt: pkt.PDN_type in (2, 3)),
#                    ConditionalField(
#                        XBitField("ipv6", "2001:db8:0:42::", 128),
#                        lambda pkt: pkt.PDN_type in (2, 3)),
#                    ConditionalField(
#                        IPField("ipv4", 0), lambda pkt: pkt.PDN_type in (1, 3)),
#                    ]
#
#
# class IE_Bearer_QoS(gtp.IE_Base):
#     name = "IE Bearer Quality of Service"
#     fields_desc = [ByteEnumField("ietype", 80, IEType),
#                    ShortField("length", None),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    BitField("SPARE", 0, 1),
#                    BitField("PCI", 0, 1),
#                    BitField("PriorityLevel", 0, 4),
#                    BitField("SPARE", 0, 1),
#                    BitField("PVI", 0, 1),
#                    ByteField("QCI", 0),
#                    BitField("MaxBitRateForUplink", 0, 40),
#                    BitField("MaxBitRateForDownlink", 0, 40),
#                    BitField("GuaranteedBitRateForUplink", 0, 40),
#                    BitField("GuaranteedBitRateForDownlink", 0, 40)]
#
#
# class IE_ChargingID(gtp.IE_Base):
#     name = "IE Charging ID"
#     fields_desc = [ByteEnumField("ietype", 94, IEType),
#                    ShortField("length", None),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    IntField("ChargingID", 0)]
#
#
# class IE_ChargingCharacteristics(gtp.IE_Base):
#     name = "IE Charging ID"
#     fields_desc = [ByteEnumField("ietype", 95, IEType),
#                    ShortField("length", None),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    XShortField("ChargingCharacteristric", 0)]
#
#
# class IE_PDN_type(gtp.IE_Base):
#     name = "IE PDN Type"
#     fields_desc = [ByteEnumField("ietype", 99, IEType),
#                    ShortField("length", None),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    BitField("SPARE", 0, 5),
#                    BitEnumField("PDN_type", None, 3, PDN_TYPES)]
#
#
# class IE_UE_Timezone(gtp.IE_Base):
#     name = "IE UE Time zone"
#     fields_desc = [ByteEnumField("ietype", 114, IEType),
#                    ShortField("length", None),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    ByteField("Timezone", 0),
#                    ByteField("DST", 0)]
#
#
# class IE_Port_Number(gtp.IE_Base):
#     name = "IE Port Number"
#     fields_desc = [ByteEnumField("ietype", 126, IEType),
#                    ShortField("length", 2),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    ShortField("PortNumber", RandShort())]
#
#
# class IE_APN_Restriction(gtp.IE_Base):
#     name = "IE APN Restriction"
#     fields_desc = [ByteEnumField("ietype", 127, IEType),
#                    ShortField("length", None),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    ByteField("APN_Restriction", 0)]
#
#
# class IE_SelectionMode(gtp.IE_Base):
#     name = "IE Selection Mode"
#     fields_desc = [ByteEnumField("ietype", 128, IEType),
#                    ShortField("length", None),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    BitField("SPARE", 0, 6),
#                    BitField("SelectionMode", 0, 2)]
#
#
# class IE_MMBR(gtp.IE_Base):
#     name = "IE Max MBR/APN-AMBR (MMBR)"
#     fields_desc = [ByteEnumField("ietype", 72, IEType),
#                    ShortField("length", None),
#                    BitField("CR_flag", 0, 4),
#                    BitField("instance", 0, 4),
#                    IntField("uplink_rate", 0),
#                    IntField("downlink_rate", 0)]
#

ietypecls = {
    1: IE_CreatePDR,
    2: IE_PDI,
    3: IE_CreateFAR,
    4: IE_ForwardingParameters,
    5: IE_DuplicatingParameters,
    6: IE_CreateURR,
    7: IE_CreateQER,
    8: IE_CreatedPDR,
    9: IE_UpdatePDR,
    10: IE_UpdateFAR,
    11: IE_UpdateForwardingParameters,
    12: IE_UpdateBAR_SRR,
    13: IE_UpdateURR,
    14: IE_UpdateQER,
    15: IE_RemovePDR,
    16: IE_RemoveFAR,
    17: IE_RemoveURR,
    18: IE_RemoveQER,
    19: IE_Cause,
    20: IE_SourceInterface,
    21: IE_FqTEID,
    22: IE_NetworkInstance,
    23: IE_SDF_Filter,
    24: IE_ApplicationId,
    25: IE_GateStatus,
    26: IE_MBR,
    27: IE_GBR,
    28: IE_QERCorrelationId,
    29: IE_Precedence,
    30: IE_TransportLevelMarking,
    31: IE_VolumeThreshold,
    32: IE_TimeThreshold,
    33: IE_MonitoringTime,
    34: IE_SubsequentVolumeThreshold,
    35: IE_SubsequentTimeThreshold,
    36: IE_InactivityDetectionTime,
    37: IE_ReportingTriggers,
    38: IE_RedirectInformation,
    39: IE_ReportType,
    40: IE_OffendingIE,
    41: IE_ForwardingPolicy,
    42: IE_DestinationInterface,
    43: IE_UPFunctionFeatures,
    44: IE_ApplyAction,
    45: IE_DownlinkDataServiceInformation,
    46: IE_DownlinkDataNotificationDelay,
    47: IE_DLBufferingDuration,
    48: IE_DLBufferingSuggestedPacketCount,
    49: IE_PFCPSMReqFlags,
    50: IE_PFCPSRRspFlags,
    51: IE_LoadControlInformation,
    52: IE_SequenceNumber,
    53: IE_Metric,
    54: IE_OverloadControlInformation,
    55: IE_Timer,
    56: IE_PDR_Id,
    57: IE_FqSEID,
    58: IE_ApplicationID_PFDs,
    59: IE_PFDContext,
    60: IE_NodeId,
    61: IE_PFDContents,
    62: IE_MeasurementMethod,
    63: IE_UsageReportTrigger,
    64: IE_MeasurementPeriod,
    65: IE_FqCSID,
    66: IE_VolumeMeasurement,
    67: IE_DurationMeasurement,
    68: IE_ApplicationDetectionInformation,
    69: IE_TimeOfFirstPacket,
    70: IE_TimeOfLastPacket,
    71: IE_QuotaHoldingTime,
    72: IE_DroppedDLTrafficThreshold,
    73: IE_VolumeQuota,
    74: IE_TimeQuota,
    75: IE_StartTime,
    76: IE_EndTime,
    77: IE_QueryURR,
    78: IE_UsageReport_SMR,
    79: IE_UsageReport_SDR,
    80: IE_UsageReport_SRR,
    81: IE_URR_Id,
    82: IE_LinkedURR_Id,
    83: IE_DownlinkDataReport,
    84: IE_OuterHeaderCreation,
    85: IE_Create_BAR,
    86: IE_Update_BAR_SMR,
    87: IE_Remove_BAR,
    88: IE_BAR_Id,
    89: IE_CPFunctionFeatures,
    90: IE_UsageInformation,
    91: IE_ApplicationInstanceId,
    92: IE_FlowInformation,
    93: IE_UE_IP_Address,
    94: IE_PacketRate,
    95: IE_OuterHeaderRemoval,
    96: IE_RecoveryTimeStamp,
    97: IE_DLFlowLevelMarking,
    98: IE_HeaderEnrichment,
    99: IE_ErrorIndicationReport,
    100: IE_MeasurementInformation,
    101: IE_NodeReportType,
    102: IE_UserPlanePathFailureReport,
    103: IE_RemoteGTP_U_Peer,
    104: IE_UR_SEQN,
    105: IE_UpdateDuplicatingParameters,
    106: IE_ActivatePredefinedRules,
    107: IE_DeactivatePredefinedRules,
    108: IE_FAR_Id,
    109: IE_QER_Id,
    110: IE_OCIFlags,
    111: IE_PFCPAssociationReleaseRequest,
    112: IE_GracefulReleasePeriod,
    113: IE_PDNType,
    114: IE_FailedRuleId,
    115: IE_TimeQuotaMechanism,
    116: IE_UserPlaneIPResourceInformation,
    117: IE_UserPlaneInactivityTimer,
    118: IE_AggregatedURRs,
    119: IE_Multiplier,
    120: IE_AggregatedURR_Id,
    121: IE_SubsequentVolumeQuota,
    122: IE_SubsequentTimeQuota,
    123: IE_RQI,
    124: IE_QFI,
    125: IE_QueryURRReference,
    126: IE_AdditionalUsageReportsInformation,
    127: IE_CreateTrafficEndpoint,
    128: IE_CreatedTrafficEndpoint,
    129: IE_UpdateTrafficEndpoint,
    130: IE_RemoveTrafficEndpoint,
    131: IE_TrafficEndpointId,
    132: IE_EthernetPacketFilter,
    133: IE_MACaddress,
    134: IE_C_TAG,
    135: IE_S_TAG,
    136: IE_Ethertype,
    137: IE_Proxying,
    138: IE_EthernetFilterId,
    139: IE_EthernetFilterProperties,
    140: IE_SuggestedBufferingPacketsCount,
    141: IE_UserId,
    142: IE_EthernetPDUSessionInformation,
    143: IE_EthernetTrafficInformation,
    144: IE_MACAddressesDetected,
    145: IE_MACAddressesRemoved,
    146: IE_EthernetInactivityTimer,
    147: IE_AdditionalMonitoringTime,
    148: IE_EventQuota,
    149: IE_EventThreshold,
    150: IE_SubsequentEventQuota,
    151: IE_SubsequentEventThreshold,
    152: IE_TraceInformation,
    153: IE_FramedRoute,
    154: IE_FramedRouting,
    155: IE_FramedIPv6Route,
    156: IE_EventTimeStamp,
    157: IE_AveragingWindow,
    158: IE_PagingPolicyIndicator,
    159: IE_APN_DNN,
    160: IE_3GPP_InterfaceType
}


#
# PFCP Messages
# 3GPP TS 29.244 V15.6.0 (2019-07)
#


class PFCPMessage(Packet):
    fields_desc = [PacketListField("IE_list", None, IE_Dispatcher)]

    def hashret(self):
        return struct.pack("H", self.seq)

class PFCPHeartbeatRequest(PFCPMessage):
    name = "PFCP Heartbeat Request"
    fields_desc = [PacketListField("IE_list", [IE_RecoveryTimeStamp()
                                              ], IE_Dispatcher)]

class PFCPHeartbeatResponse(PFCPMessage):
    name = "PFCP Heartbeat Response"
    fields_desc = [PacketListField("IE_list", [IE_RecoveryTimeStamp()
                                              ], IE_Dispatcher)]


class PFCPPFDManagementRequest(PFCPMessage):
    name = "PFCP PFD Management Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPPFDManagementResponse(PFCPMessage):
    name = "PFCP PFD Management Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPAssociationSetupRequest(PFCPMessage):
    name = "PFCP Association Setup Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPAssociationSetupResponse(PFCPMessage):
    name = "PFCP Association Setup Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPAssociationUpdateRequest(PFCPMessage):
    name = "PFCP Association Update Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPAssociationUpdateResponse(PFCPMessage):
    name = "PFCP Association Update Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPAssociationReleaseRequest(PFCPMessage):
    name = "PFCP Association Release Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPAssociationReleaseResponse(PFCPMessage):
    name = "PFCP Association Release Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPVersionNotSupportedResponse(PFCPMessage):
    name = "PFCP Version Not Supported Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPNodeReportRequest(PFCPMessage):
    name = "PFCP Node Report Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPNodeReportResponse(PFCPMessage):
    name = "PFCP Node Report Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPSessionSetDeletionRequest(PFCPMessage):
    name = "PFCP Session Set Deletion Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPSessionSetDeletionResponse(PFCPMessage):
    name = "PFCP Session Set Deletion Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPSessionEstablishmentRequest(PFCPMessage):
    name = "PFCP Session Establishment Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPSessionEstablishmentResponse(PFCPMessage):
    name = "PFCP Session Establishment Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPSessionModificationRequest(PFCPMessage):
    name = "PFCP Session Modification Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPSessionModificationResponse(PFCPMessage):
    name = "PFCP Session Modification Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPSessionDeletionRequest(PFCPMessage):
    name = "PFCP Session Deletion Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPSessionDeletionResponse(PFCPMessage):
    name = "PFCP Session Deletion Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPSessionReportRequest(PFCPMessage):
    name = "PFCP Session Report Request"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]


class PFCPSessionReportResponse(PFCPMessage):
    name = "PFCP Session Report Response"
    fields_desc = [PacketListField("IE_list", [], IE_Dispatcher)]



bind_bottom_up(UDP, PFCPHeader, dport=8805)
bind_bottom_up(UDP, PFCPHeader, sport=8805)
bind_layers(UDP, PFCPHeader, dport=8805, sport=8805)
bind_layers(PFCPHeader, PFCPHeartbeatRequest, message_type=1)
bind_layers(PFCPHeader, PFCPHeartbeatResponse, message_type=2)
bind_layers(PFCPHeader, PFCPPFDManagementRequest, message_type=3)
bind_layers(PFCPHeader, PFCPPFDManagementResponse, message_type=4)
bind_layers(PFCPHeader, PFCPAssociationSetupRequest, message_type=5)
bind_layers(PFCPHeader, PFCPAssociationSetupResponse, message_type=6)
bind_layers(PFCPHeader, PFCPAssociationUpdateRequest, message_type=7)
bind_layers(PFCPHeader, PFCPAssociationUpdateResponse, message_type=8)
bind_layers(PFCPHeader, PFCPAssociationReleaseRequest, message_type=9)
bind_layers(PFCPHeader, PFCPAssociationReleaseResponse, message_type=10)
bind_layers(PFCPHeader, PFCPVersionNotSupportedResponse, message_type=11)
bind_layers(PFCPHeader, PFCPNodeReportRequest, message_type=12)
bind_layers(PFCPHeader, PFCPNodeReportResponse, message_type=13)
bind_layers(PFCPHeader, PFCPSessionSetDeletionRequest, message_type=14)
bind_layers(PFCPHeader, PFCPSessionSetDeletionResponse, message_type=15)
bind_layers(PFCPHeader, PFCPSessionEstablishmentRequest, message_type=50, S=1)
bind_layers(PFCPHeader, PFCPSessionEstablishmentResponse, message_type=51, S=1)
bind_layers(PFCPHeader, PFCPSessionModificationRequest, message_type=52, S=1)
bind_layers(PFCPHeader, PFCPSessionModificationResponse, message_type=53, S=1)
bind_layers(PFCPHeader, PFCPSessionDeletionRequest, message_type=54, S=1)
bind_layers(PFCPHeader, PFCPSessionDeletionResponse, message_type=55, S=1)
bind_layers(PFCPHeader, PFCPSessionReportRequest, message_type=5, S=1)
bind_layers(PFCPHeader, PFCPSessionReportResponse, message_type=57, S=1)
