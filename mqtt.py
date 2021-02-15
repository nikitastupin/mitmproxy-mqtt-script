from mitmproxy.utils import strutils
from typing import List

import struct


class MQTTControlPacket:
    # Packet types
    (
        CONNECT,
        CONNACK,
        PUBLISH,
        PUBACK,
        PUBREC,
        PUBREL,
        PUBCOMP,
        SUBSCRIBE,
        SUBACK,
        UNSUBSCRIBE,
        UNSUBACK,
        PINGREQ,
        PINGRESP,
        DISCONNECT,
    ) = range(1, 15)

    # http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Table_2.1_-
    NAMES = [
        "reserved",
        "CONNECT",
        "CONNACK",
        "PUBLISH",
        "PUBACK",
        "PUBREC",
        "PUBREL",
        "PUBCOMP",
        "SUBSCRIBE",
        "SUBACK",
        "UNSUBSCRIBE",
        "UNSUBACK",
        "PINGREQ",
        "PINGRESP",
        "DISCONNECT",
        "reserved",
    ]

    # http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Table_3.1_-
    CONNECT_RETURN_CODES = [
        "Connection Accepted",
        "Connection Refused, unacceptable protocol version",
        "Connection Refused, identifier rejected",
        "Connection Refused, Server unavailable",
        "Connection Refused, bad user name or password",
        "Connection Refused, not authorized",
    ]

    SUBACK_RETURN_CODES = {
        0x00: "Success - Maximum QoS 0",
        0x01: "Success - Maximum QoS 1",
        0x02: "Success - Maximum QoS 2",
        0x80: "Failure",
    }

    PACKETS_WITH_IDENTIFIER = [
        PUBACK,
        PUBREC,
        PUBREL,
        PUBCOMP,
        SUBSCRIBE,
        SUBACK,
        UNSUBSCRIBE,
        UNSUBACK,
    ]

    def __init__(self, buf: bytes, packet_type: int, packet_flags: int, length: int, length_size=1):
        self.buf = buf
        self.packet_type = packet_type
        self.packet_type_human = self.NAMES[self.packet_type]
        self.packet_flags = packet_flags
        self.remaining_length = length
        self.remaining_length_size = length_size
        self.packet_identifier = None
        self.payload = {}

        self.dup, self.qos, self.retain = self._parse_flags()

    def parse(self):
        # Variable header & Payload
        # http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718024
        # http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718026
        if self.packet_type == self.CONNECT:
            self._parse_connect_variable_headers()
            self._parse_connect_payload()

        elif self.packet_type == self.CONNACK:
            self._parse_connack_variable_headers()

        elif self.packet_type == self.PUBLISH:
            self._parse_publish_variable_headers()
            self._parse_publish_payload()

        elif self.packet_type in (self.SUBSCRIBE, self.UNSUBSCRIBE):
            flags = self.packet_flags
            if flags != 0x2:
                raise Exception(f'Packet is malformed: flags = {flags} != 0x2')

            self._parse_packet_identifier()
            self._parse_subscribe_payload(with_qos=(self.packet_type == self.SUBSCRIBE))

        elif self.packet_type == self.SUBACK:
            self._parse_packet_identifier()
            self._parse_suback_payload()

        elif self.packet_type == self.UNSUBACK:
            self._parse_packet_identifier()

        elif self.packet_type == self.PUBACK:
            self._parse_packet_identifier()

        elif self.packet_type == self.UNSUBSCRIBE:
            pass

        # else:
        #     self.payload = None

    def pprint(self):
        pid = f' {self.packet_identifier:04x}' if self.packet_identifier is not None else ''
        s = f'[{self.NAMES[self.packet_type]}{pid}]'

        if self.packet_type == self.CONNECT:
            s += f"""
Protocol Level: {self.variable_headers['ProtocolLevel'][0]}
Client Id: {self.payload['ClientId']}
Will Topic: {self.payload.get('WillTopic')}
Will Message: {strutils.bytes_to_escaped_str(self.payload.get('WillMessage', b'None'))}
User Name: {self.payload.get('UserName')}
Password: {strutils.bytes_to_escaped_str(self.payload.get('Password', b'None'))}
"""

        elif self.packet_type == self.CONNACK:
            rc = self.connack_headers["ReturnCode"]
            rc_desc = self.CONNECT_RETURN_CODES[rc] if rc < len(self.CONNECT_RETURN_CODES) else f'{rc:02x}'
            s += f" SessionPresent: {self.connack_headers['SessionPresent']}. {rc_desc}"

        elif self.packet_type in (self.SUBSCRIBE, self.UNSUBSCRIBE):
            s += " sent topic filters: "
            s += ", ".join([f"'{tf}'" for tf in self.topic_filters])

        elif self.packet_type == self.SUBACK:
            rc = self.payload['ReturnCode']
            s += " "
            s += self.SUBACK_RETURN_CODES[rc] if rc in self.SUBACK_RETURN_CODES else f'{rc:02xs}'

        elif self.packet_type == self.PUBLISH:
            topic_name = strutils.bytes_to_escaped_str(self.topic_name)
            payload = strutils.bytes_to_escaped_str(self.payload)

            s += f" '{payload}' to topic '{topic_name}'"

        elif self.packet_type in (self.PINGREQ, self.PINGRESP, self.UNSUBACK, self.PUBACK, self.DISCONNECT):
            # just print packet type with packet identifier (if any)
            pass

        else:
            s = f"Packet type {self.NAMES[self.packet_type]} is not supported yet!"

        return s

    def _parse_length_prefixed_bytes(self, offset):
        field_length_bytes = self.buf[offset: offset + 2]
        field_length = struct.unpack("!H", field_length_bytes)[0]
        offset += 2

        field_content_bytes = self.buf[offset: offset + field_length]

        return field_length + 2, field_content_bytes

    def _parse_publish_variable_headers(self):
        offset = len(self.buf) - self.remaining_length

        field_length, field_content_bytes = self._parse_length_prefixed_bytes(offset)
        self.topic_name = field_content_bytes

        if self.qos in [0x01, 0x02]:
            offset += field_length
            self.packet_identifier = self.buf[offset: offset + 2][0]

    def _parse_publish_payload(self):
        fixed_header_length = len(self.buf) - self.remaining_length
        variable_header_length = 2 + len(self.topic_name)

        if self.qos in [0x01, 0x02]:
            variable_header_length += 2

        offset = fixed_header_length + variable_header_length

        self.payload = self.buf[offset:]

    def _parse_subscribe_payload(self, with_qos=True):
        # skip packet identifier
        offset = self.remaining_length_size
        offset += 1 # fixed header
        offset += 2 # packet identifier

        self.topic_filters = []

        while len(self.buf) - offset > 0:
            field_length, topic_filter_bytes = self._parse_length_prefixed_bytes(offset)
            offset += field_length

            topic_filter = {
                'topic': topic_filter_bytes.decode("utf-8")
            }

            if with_qos:
                topic_filter['qos'] = self.buf[offset: offset + 1][0] & 0x3
                offset += 1

            self.topic_filters.append(topic_filter)

    def _parse_suback_payload(self):
        offset = len(self.buf) - self.remaining_length + 2
        rc = self.buf[offset]
        self.payload['ReturnCode'] = rc

    # http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718030
    def _parse_connect_variable_headers(self):
        offset = len(self.buf) - self.remaining_length

        self.variable_headers = {}
        self.connect_flags = {}

        self.variable_headers["ProtocolName"] = self.buf[offset: offset + 6]
        self.variable_headers["ProtocolLevel"] = self.buf[offset + 6: offset + 7]
        self.variable_headers["ConnectFlags"] = self.buf[offset + 7: offset + 8]
        self.variable_headers["KeepAlive"] = self.buf[offset + 8: offset + 10]

        # http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc385349229
        self.connect_flags["CleanSession"] = bool(self.variable_headers["ConnectFlags"][0] & 0x02)
        self.connect_flags["Will"] = bool(self.variable_headers["ConnectFlags"][0] & 0x04)
        self.will_qos = (self.variable_headers["ConnectFlags"][0] >> 3) & 0x03
        self.connect_flags["WillRetain"] = bool(self.variable_headers["ConnectFlags"][0] & 0x20)
        self.connect_flags["Password"] = bool(self.variable_headers["ConnectFlags"][0] & 0x40)
        self.connect_flags["UserName"] = bool(self.variable_headers["ConnectFlags"][0] & 0x80)

    # http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718031
    def _parse_connect_payload(self):
        fields = []
        offset = len(self.buf) - self.remaining_length + 10

        while len(self.buf) - offset > 0:
            field_length, field_content = self._parse_length_prefixed_bytes(offset)
            fields.append(field_content)
            offset += field_length

        self.payload = {}

        for f in fields:
            # http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc385349242
            if "ClientId" not in self.payload:
                try:
                    self.payload["ClientId"] = f.decode("utf-8")
                except:
                    self.payload["ClientId"] = str(f)

            # http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc385349243
            elif self.connect_flags["Will"] and "WillTopic" not in self.payload:
                self.payload["WillTopic"] = f.decode("utf-8")

            elif self.connect_flags["Will"] and "WillMessage" not in self.payload:
                self.payload["WillMessage"] = f

            elif self.connect_flags["UserName"] and "UserName" not in self.payload:
                self.payload["UserName"] = f.decode("utf-8")

            elif self.connect_flags["Password"] and "Password" not in self.payload:
                self.payload["Password"] = f

            else:
                raise Exception("")

    # http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718035
    def _parse_connack_variable_headers(self):
        self.connack_headers = {}

        offset = len(self.buf) - self.remaining_length

        self.connack_headers["SessionPresent"] = self.buf[offset: offset + 1][0] & 0x01 == 0x01
        self.connack_headers["ReturnCode"] = self.buf[offset + 1: offset + 2][0]

    # http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718022
    def _parse_flags(self):
        dup = None
        qos = None
        retain = None

        if self.packet_type == self.PUBLISH:
            dup = (self.buf[0] >> 3) & 0x01
            qos = (self.buf[0] >> 1) & 0x03
            retain = self.buf[0] & 0x01

        return dup, qos, retain

    # http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Table_2.5_-
    def _parse_packet_identifier(self):
        offset = 1 + self.remaining_length_size
        self.packet_identifier = struct.unpack('!H', self.buf[offset: offset + 2])[0]


def _get_packet_type(buf: bytes) -> int:
    return buf[0] >> 4


def _get_packet_flags(buf: bytes) -> int:
    return buf[0] & 0xf


def _get_remaining_length(buf: bytes) -> tuple:
    multiplier = 1
    value = 0
    i = 1

    while True:
        encoded_byte = buf[i-1]
        value += (encoded_byte & 127) * multiplier
        multiplier *= 128

        if multiplier > 128 * 128 * 128:
            raise Exception("Malformed Remaining Length")

        if encoded_byte & 128 == 0:
            break

        i += 1

    return i, value


def read_packets(buf: bytes) -> List[MQTTControlPacket]:
    packets = []
    while len(buf) > 0:
        # Fixed header
        # http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718020
        packet_type = _get_packet_type(buf)
        packet_flags = _get_packet_flags(buf)
        length_size, length = _get_remaining_length(buf[1:])

        packets.append(MQTTControlPacket(buf[:1+length_size+length], packet_type, packet_flags, length, length_size=length_size))

        buf = buf[1+length_size+length:]

    return packets
