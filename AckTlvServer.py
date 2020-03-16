#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import struct
from datetime import datetime
from enum import Enum, unique
import asyncio
import asyncio.transports as transports

magic_word = 0xFEEDF00D
magic_word_len = 4

@unique
class AckTlvTypeList(Enum):

    # Structural
    DataPackage = 0x01
    Info = 0x02
    ScanResult = 0x03
    GPS = 0x04
    Satellites = 0x05
    DilutionOfPrecision = 0x06
    # Leaves
    ValueCounter = 0x80
    ValueGauge = 0x81
    ValueDerive = 0x82
    ValueAbsolute = 0x83

    Instance = 0x84
    Time = 0x85
    ProductId = 0x86
    ProtocolVersion = 0x87

    HT_CAPAB = 0x90
    HT_PARAM = 0x91
    VHT_CAPAB = 0x92
    VHT_CHWIDTH = 0x93
    FREQ = 0x94
    BEACON_INT = 0x95
    CAPS = 0x96
    QUAL = 0x97
    NOISE = 0x98
    LEVEL = 0x99
    EST_THROUGHPUT = 0x9A
    SNR = 0x9B
    ROAMING_STATUS = 0x9C

    Longitude = 0xA0
    Latitude = 0xA1


# Acksys structural TLV description
AckTlvStruct = {
    AckTlvTypeList.DataPackage.value: "DataPackage",
    AckTlvTypeList.Info.value: "TLV info",
    AckTlvTypeList.ScanResult.value: "Wifi scan result",
    AckTlvTypeList.GPS.value: "GPS",
    AckTlvTypeList.Satellites.value: "Satellites",
    AckTlvTypeList.DilutionOfPrecision.value: "Dilution of precision",
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
    AckTlvTypeList.Longitude.value: "Longitude",
    AckTlvTypeList.Latitude.value: "Latitude",
}


def handle_roaming_status(array: bytearray):
    value = struct.unpack('!q', array)[0]
    rs_stat_dict = {
        1: 'Best',
        2: 'Current',
        3: 'Roaming stat: select 0',
        4: 'Roaming stat: select 1',
        5: 'Roaming stat: select 2',
        6: 'Roaming stat: select 3',
        7: 'Roaming stat: select 4',
        8: 'Roaming stat: select 5',
    }
    return rs_stat_dict.get(value, "Unknown stat: %d" % value)


AckTlvDecodeCallbackList = {
    AckTlvTypeList.ValueCounter.value: lambda array: struct.unpack('!Q', array)[0],
    AckTlvTypeList.ValueGauge.value: lambda array: struct.unpack('!d', array)[0],
    AckTlvTypeList.ValueDerive.value: lambda array: struct.unpack('!q', array)[0],
    AckTlvTypeList.ValueAbsolute.value: lambda array: struct.unpack('!Q', array)[0],
    AckTlvTypeList.Instance.value: lambda array: array.decode('ASCII'),
    AckTlvTypeList.Time.value: lambda array: datetime.utcfromtimestamp(struct.unpack('!q', array)[0]),
    AckTlvTypeList.ProductId.value: lambda array: array.decode('ASCII'),
    AckTlvTypeList.ProtocolVersion.value: lambda array: array.decode('ASCII'),
    AckTlvTypeList.HT_CAPAB.value: lambda array: struct.unpack('!q', array)[0],
    AckTlvTypeList.HT_PARAM.value: lambda array: struct.unpack('!q', array)[0],
    AckTlvTypeList.VHT_CAPAB.value: lambda array: struct.unpack('!q', array)[0],
    AckTlvTypeList.VHT_CHWIDTH.value: lambda array: struct.unpack('!q', array)[0],
    AckTlvTypeList.FREQ.value: lambda array: struct.unpack('!q', array)[0],
    AckTlvTypeList.BEACON_INT.value: lambda array: struct.unpack('!q', array)[0],
    AckTlvTypeList.CAPS.value: lambda array: struct.unpack('!q', array)[0],
    AckTlvTypeList.QUAL.value: lambda array: struct.unpack('!q', array)[0],
    AckTlvTypeList.NOISE.value: lambda array: struct.unpack('!q', array)[0],
    AckTlvTypeList.LEVEL.value: lambda array: struct.unpack('!q', array)[0],
    AckTlvTypeList.EST_THROUGHPUT.value: lambda array: struct.unpack('!q', array)[0],
    AckTlvTypeList.SNR.value: lambda array: struct.unpack('!q', array)[0],
    AckTlvTypeList.ROAMING_STATUS.value: handle_roaming_status,
    AckTlvTypeList.Longitude.value: lambda array: struct.unpack('!d', array)[0],
    AckTlvTypeList.Latitude.value: lambda array: struct.unpack('!d', array)[0],
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
        self.type = int(array[0])
        self.length = struct.unpack('!H', array[1:3])[0]
        if self.type in AckTlvLeaves.keys():
            if self.length > 3:
                try:
                    self.value = AckTlvDecodeCallbackList[self.type](array[3:self.length])
                except Exception as e:
                    self.value = None
                    print(e)
            else:
                self.value = None
            return self
        elif self.type in AckTlvStruct.keys():
            self.value = list()
            array = array[3:]
            while len(array) > 0:
                sub_len = struct.unpack('!H', array[1:3])[0]
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
            return self.length
        elif self.type in AckTlvStruct.keys():
            s = 0
            for i in self.value:
                s = s + len(i)
            return s + 3


class AckTlvServerProtocol(asyncio.Protocol):
    def connection_made(self, transport: transports.BaseTransport) -> None:
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))

    def data_received(self, data: bytes) -> None:
        # print('====Raw data====')
        # print(''.join(["0x%02X " % int(x) for x in data]))
        if int.from_bytes(data[0:4], byteorder="big") != magic_word:
            print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            print('====Data check error, abandon!====')
        else:
            tlv = Tlv(0).decode(data[magic_word_len:])
            print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            tlv.dbg_print()
            print('====Data end====')
            print('Array length: %d, decode length: %d' % (len(data), len(tlv) + magic_word_len))
            print('================\n\n')
            if len(data) != len(tlv) + magic_word_len:
                print('====Array not fully decoded, there\'s an error somewhere====')


def run_server():
    loop = asyncio.get_event_loop()
    coro = loop.create_server(AckTlvServerProtocol, '10.0.0.1', 8628)
    server = loop.run_until_complete(coro)

    print('Serving on {}'.format(server.sockets[0].getsockname()))
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
