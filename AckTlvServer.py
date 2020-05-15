#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import struct
from datetime import datetime
from enum import Enum, unique
import asyncio
import asyncio.transports as transports

PROTO = "TCP"
SERVER_ADDR = "192.168.175.1"
SERVER_PORT = 8628

@unique
class AckTlvTypeList(Enum):

    # Structural
    DataPackage = 0xFFC08000
    Info = 0xFFC08001
    ScanResult = 0xFFC08002
    GPS = 0xFFC08003
    WirelessInfo = 0xFFC08006
    WirelessAssocListEntry = 0xFFC08007

    # Primitives
    ValueCounter = 0xDFC08000
    ValueGauge = 0xDFC08001
    ValueDerive = 0xDFC08002
    ValueAbsolute = 0xDFC08003

    Instance = 0xDFC08004
    Time = 0xDFC08005
    ProductId = 0xDFC08006
    ProtocolVersion = 0xDFC08007

    HT_CAPAB = 0xDFC08008
    HT_PARAM = 0xDFC08009
    VHT_CAPAB = 0xDFC0800A
    VHT_CHWIDTH = 0xDFC0800B
    FREQ = 0xDFC0800C
    BEACON_INT = 0xDFC0800D
    CAPS = 0xDFC0800E
    QUAL = 0xDFC0800F
    NOISE = 0xDFC08010
    LEVEL = 0xDFC08011
    EST_THROUGHPUT = 0xDFC08012
    SNR = 0xDFC08013
    ROAMING_STATUS = 0xDFC08014
    SSID = 0xDFC08015
    IF_NAME = 0xDFC08016

    Longitude = 0xDFC08017
    Latitude = 0xDFC08018
    ACKTLV_PRI_GPS_HDOP = 0xDFC08024
    ACKTLV_PRI_GPS_VDOP = 0xDFC08025
    ACKTLV_PRI_GPS_SAT_U = 0xDFC08026
    ACKTLV_PRI_GPS_SAT_V = 0xDFC08027

    BSSID = 0xDFC08019
    WirelessMode = 0xDFC0801A
    WirelessChannel = 0xDFC0801B
    WirelessSecuMode = 0xDFC0801C
    WirelessNbClient = 0xDFC0801D
    RssiPercent = 0xDFC0801E
    WirelessConnState = 0xDFC0801F
    WirelessSignal = 0xDFC08020

    PhyLabel = 0xDFC08021
    PhyName = 0xDFC08022
    MacAddr = 0xDFC08023


# Acksys structural TLV description
AckTlvStruct = {
    AckTlvTypeList.DataPackage.value: "DataPackage",
    AckTlvTypeList.Info.value: "TLV info",
    AckTlvTypeList.ScanResult.value: "Wifi scan result",
    AckTlvTypeList.GPS.value: "GPS",
    AckTlvTypeList.WirelessInfo.value: "Wireless info",
    AckTlvTypeList.WirelessAssocListEntry.value: "Wireless association list entry",
}

AckTlvLeaves = {
    AckTlvTypeList.ValueCounter.value: "Value",
    AckTlvTypeList.ValueGauge.value: "Value",
    AckTlvTypeList.ValueDerive.value: "Value",
    AckTlvTypeList.ValueAbsolute.value: "Value",

    AckTlvTypeList.Instance.value: "Instance",
    AckTlvTypeList.Time.value: "Time",
    AckTlvTypeList.ProductId.value: "Product ID",
    AckTlvTypeList.ProtocolVersion.value: "Protocol version",

    AckTlvTypeList.HT_CAPAB.value: "HT capabilities",
    AckTlvTypeList.HT_PARAM.value: "5 octets of HT Operation Information",
    AckTlvTypeList.VHT_CAPAB.value: "VHT capabilities",
    AckTlvTypeList.VHT_CHWIDTH.value: "Channel width in VHT Operation Information",
    AckTlvTypeList.FREQ.value: "Frequency of the channel in MHz",
    AckTlvTypeList.BEACON_INT.value: "Beacon interval in TUs",
    AckTlvTypeList.CAPS.value: "Capability information field",
    AckTlvTypeList.QUAL.value: "Signal quality",
    AckTlvTypeList.NOISE.value: "Noise level",
    AckTlvTypeList.LEVEL.value: "Signal level",
    AckTlvTypeList.EST_THROUGHPUT.value: "Estimated throughput in kbps",
    AckTlvTypeList.SNR.value: "Signal-to-noise ratio in dB",
    AckTlvTypeList.ROAMING_STATUS.value: "Roaming status",
    AckTlvTypeList.SSID.value: "SSID",
    AckTlvTypeList.IF_NAME.value: "Interface name",

    AckTlvTypeList.Longitude.value: "Longitude",
    AckTlvTypeList.Latitude.value: "Latitude",
    AckTlvTypeList.ACKTLV_PRI_GPS_HDOP.value: "Horizonal DOP",
    AckTlvTypeList.ACKTLV_PRI_GPS_VDOP.value: "Vertical DOP",
    AckTlvTypeList.ACKTLV_PRI_GPS_SAT_U.value: "Used satellites",
    AckTlvTypeList.ACKTLV_PRI_GPS_SAT_V.value: "Visible satellites",

    AckTlvTypeList.BSSID.value: "BSSID",
    AckTlvTypeList.WirelessMode.value: "Mode",
    AckTlvTypeList.WirelessChannel.value: "Channel",
    AckTlvTypeList.WirelessSecuMode.value: "Security",
    AckTlvTypeList.WirelessNbClient.value: "Number of client",
    AckTlvTypeList.RssiPercent.value: "RSSI in percentage",
    AckTlvTypeList.WirelessConnState.value: "Connection state",
    AckTlvTypeList.WirelessSignal.value: "Signal",
    AckTlvTypeList.PhyLabel.value: "Phy label",
    AckTlvTypeList.PhyName.value: "Phy name",
    AckTlvTypeList.MacAddr.value: "MAC addr",
}


def handle_roaming_status(array: bytearray):
    value = int.from_bytes(array, byteorder='big', signed=True)
    rs_stat_dict = {
        1: 'Best',
        2: 'Current active',
        3: 'Not qualified',
        4: 'Candidate',
        5: 'Signal below minimum',
        6: 'Signal beyond maximum',
        7: 'Recently connected',
        8: 'Current passive',
    }
    return rs_stat_dict.get(value, "Unknown stat: %d" % value)


def handle_wireless_mode(array: bytearray):
    value = int.from_bytes(array, byteorder='big', signed=True)
    d = {
        1: 'infra-client',
        2: 'access-point',
        3: 'ad-hoc',
        6: 'ieee80211s',
        7: 'repeater',
        8: 'isolating-access-point',
    }
    return d.get(value, "Unknown stat: %d" % value)


def handle_wireless_secu_mode(array: bytearray):
    value = int.from_bytes(array, byteorder='big', signed=True)
    d = {
        1: 'none',
        2: 'wep',
        3: 'wpa-wpa2-psk',
        4: 'wpa-wpa2',
        5: 'sae',
    }
    return d.get(value, "Unknown stat: %d" % value)


def handle_wireless_conn_state(array: bytearray):
    value = int.from_bytes(array, byteorder='big', signed=True)
    d = {
        0: 'not connected',
        9: 'connected',
    }
    return d.get(value, "Unknown stat: %d" % value)


AckTlvDecodeCallbackList = {
    AckTlvTypeList.ValueCounter.value: lambda array: int.from_bytes(array, byteorder='big', signed=False),
    AckTlvTypeList.ValueGauge.value: lambda array: struct.unpack('!d', array)[0],
    AckTlvTypeList.ValueDerive.value: lambda array: int.from_bytes(array, byteorder='big', signed=False),
    AckTlvTypeList.ValueAbsolute.value: lambda array: int.from_bytes(array, byteorder='big', signed=False),

    AckTlvTypeList.Instance.value: lambda array: array.decode('ASCII'),
    AckTlvTypeList.Time.value: lambda array: datetime.utcfromtimestamp(int.from_bytes(array, byteorder='big', signed=True)),
    AckTlvTypeList.ProductId.value: lambda array: array.decode('ASCII'),
    AckTlvTypeList.ProtocolVersion.value: lambda array: array.decode('ASCII'),

    AckTlvTypeList.HT_CAPAB.value: lambda array: int.from_bytes(array, byteorder='big', signed=False),
    AckTlvTypeList.HT_PARAM.value: lambda array: int.from_bytes(array, byteorder='big', signed=False),
    AckTlvTypeList.VHT_CAPAB.value: lambda array: int.from_bytes(array, byteorder='big', signed=False),
    AckTlvTypeList.VHT_CHWIDTH.value: lambda array: int.from_bytes(array, byteorder='big', signed=False),
    AckTlvTypeList.FREQ.value: lambda array: int.from_bytes(array, byteorder='big', signed=False),
    AckTlvTypeList.BEACON_INT.value: lambda array: int.from_bytes(array, byteorder='big', signed=False),
    AckTlvTypeList.CAPS.value: lambda array: int.from_bytes(array, byteorder='big', signed=False),
    AckTlvTypeList.QUAL.value: lambda array: int.from_bytes(array, byteorder='big', signed=False),
    AckTlvTypeList.NOISE.value: lambda array: int.from_bytes(array, byteorder='big', signed=True),
    AckTlvTypeList.LEVEL.value: lambda array: int.from_bytes(array, byteorder='big', signed=True),
    AckTlvTypeList.EST_THROUGHPUT.value: lambda array: int.from_bytes(array, byteorder='big', signed=False),
    AckTlvTypeList.SNR.value: lambda array: int.from_bytes(array, byteorder='big', signed=False),
    AckTlvTypeList.ROAMING_STATUS.value: handle_roaming_status,
    AckTlvTypeList.SSID.value: lambda array: array.decode('ASCII'),
    AckTlvTypeList.IF_NAME.value: lambda array: array.decode('ASCII'),

    AckTlvTypeList.Longitude.value: lambda array: struct.unpack('!d', array)[0],
    AckTlvTypeList.Latitude.value: lambda array: struct.unpack('!d', array)[0],
    AckTlvTypeList.ACKTLV_PRI_GPS_HDOP.value: lambda array: struct.unpack('!d', array)[0],
    AckTlvTypeList.ACKTLV_PRI_GPS_VDOP.value: lambda array: struct.unpack('!d', array)[0],
    AckTlvTypeList.ACKTLV_PRI_GPS_SAT_U.value: lambda array: int.from_bytes(array, byteorder='big', signed=False),
    AckTlvTypeList.ACKTLV_PRI_GPS_SAT_V.value: lambda array: int.from_bytes(array, byteorder='big', signed=False),

    AckTlvTypeList.BSSID.value: lambda array: array.decode('ASCII'),
    AckTlvTypeList.WirelessMode.value: handle_wireless_mode,
    AckTlvTypeList.WirelessChannel.value: lambda array: int.from_bytes(array, byteorder='big', signed=True),
    AckTlvTypeList.WirelessSecuMode.value: handle_wireless_secu_mode,
    AckTlvTypeList.WirelessNbClient.value: lambda array: int.from_bytes(array, byteorder='big', signed=False),
    AckTlvTypeList.RssiPercent.value: lambda array: int.from_bytes(array, byteorder='big', signed=False),
    AckTlvTypeList.WirelessConnState.value: handle_wireless_conn_state,
    AckTlvTypeList.WirelessSignal.value: lambda array: int.from_bytes(array, byteorder='big', signed=True),
    AckTlvTypeList.PhyLabel.value: lambda array: array.decode('ASCII'),
    AckTlvTypeList.PhyName.value: lambda array: array.decode('ASCII'),
    AckTlvTypeList.MacAddr.value: lambda array: array.decode('ASCII'),
}


class Tlv:

    def __init__(self, iter_counter, last_in_list=False):
        self.type = 0
        self.length = 0
        self.value = None
        # Just for print effect
        self.iter_counter = iter_counter
        self.last = last_in_list

    def decode(self, array):
        if len(array) == 0:
            return None
        # Common part
        self.type = struct.unpack('!I', array[0:4])[0]
        self.length = struct.unpack('!H', array[5:7])[0]
        if self.type in AckTlvLeaves.keys():
            if self.length > 0:
                try:
                    self.value = AckTlvDecodeCallbackList[self.type](array[7:self.length + 7])
                except Exception as e:
                    self.value = None
                    print(e)
            else:
                self.value = None
            return self
        elif self.type in AckTlvStruct.keys():
            self.value = list()
            array = array[7:self.length + 7]
            while len(array) > 0:
                sub_len = struct.unpack('!H', array[5:7])[0] + 7
                self.value.append(Tlv(self.iter_counter + 1,
                                      last_in_list=(len(array[sub_len:]) == 0)).decode(array[:sub_len]))
                array = array[sub_len:]
            return self
        else:
            raise Exception("Type not defined: 0x%02X" % self.type)

    def dbg_print(self):
        padding = '\t┃' * self.iter_counter
        if self.type in AckTlvLeaves.keys():
            if self.last:
                print(padding + "\t┗━━━\033[92m%-10s\033[0m\t\033[95m%s\033[0m" %
                      (AckTlvLeaves.get(self.type), str(self.value)))
            else:
                print(padding + "\t┣━━━\033[92m%-10s\033[0m\t\033[95m%s\033[0m" %
                      (AckTlvLeaves.get(self.type), str(self.value)))
        elif self.type in AckTlvStruct.keys():
            print(padding + "\t┣━━━\033[93m%s\033[0m" % AckTlvStruct.get(self.type))
            for i in self.value:
                i.dbg_print()
            print("\t┃" * (self.iter_counter + 1))

    def __len__(self):
        if self.type in AckTlvLeaves.keys():
            # directly got value
            return self.length + 7
        elif self.type in AckTlvStruct.keys():
            s = 0
            for i in self.value:
                s = s + len(i)
            return s + 7


class AckTlvServerProtocol(asyncio.Protocol):
    def connection_made(self, transport: transports.BaseTransport) -> None:
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))

    def data_received(self, data: bytes) -> None:
        # print('====Raw data====')
        # print(''.join(["%02X" % int(x) for x in data]))
        tlv = Tlv(0).decode(data)
        print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        tlv.dbg_print()
        print('====Data end====')
        print('Array length: %d, decode length: %d' % (len(data), len(tlv)))
        print('================\n\n')
        if len(data) != len(tlv):
            print('====Array not fully decoded, there\'s an error somewhere====')


class AckTlvServerUDP(asyncio.BaseProtocol):
    def connection_made(self, _transport):
        self.transport = _transport

    def datagram_received(self, data, addr):
        tlv = Tlv(0).decode(data)
        print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        tlv.dbg_print()
        print('====Data end====')
        print('Array length: %d, decode length: %d' % (len(data), len(tlv)))
        print('================\n\n')
        if len(data) != len(tlv):
            print('====Array not fully decoded, there\'s an error somewhere====')


def run_server():
    loop = asyncio.get_event_loop()
    coro = None
    if PROTO == 'TCP':
        coro = loop.create_server(AckTlvServerProtocol, SERVER_ADDR, SERVER_PORT)
    if PROTO == 'UDP':
        coro = loop.create_datagram_endpoint(AckTlvServerUDP, local_addr=(SERVER_ADDR, SERVER_PORT))
    if coro:
        server = loop.run_until_complete(coro)
    else:
        print("Protocol error!\n")

    print('Server started\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()


if __name__ == '__main__':
    run_server()
