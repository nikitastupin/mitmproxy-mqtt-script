from mitmproxy import ctx
from mitmproxy import tcp
from hexdump import hexdump
from mqtt import read_packets

import traceback


def log_hexdump(buf: bytes):
    for line in hexdump(buf, result='return').split("\n"):
        ctx.log.debug(line.strip())


def tcp_message(flow: tcp.TCPFlow):
    message = flow.messages[-1]

    ports = (flow.client_conn.address[1], flow.server_conn.address[1])
    if 8883 not in ports:
        return

    try:
        packets = read_packets(message.content)
    except:
        ctx.log.error(f'Failed to parse message.content')
        ctx.log.error(traceback.format_exc().strip())
        log_hexdump(message.content)
        return

    for packet in packets:
        try:
            packet.parse()

            # This should be info(), but I use warn() to make it yellow
            ctx.log.warn(packet.pprint())
        except:
            ctx.log.error(f'Failed to parse {packet.packet_type_human}')
            ctx.log.error(traceback.format_exc().strip())
            log_hexdump(packet.buf)


    # This way we can save topics
    # if mqtt_packet.packet_type == mqtt_packet.PUBLISH:
    #     with open("topics.txt", "a") as f:
    #         f.write(f"{mqtt_packet.topic_name}\n")
    # elif mqtt_packet.packet_type == mqtt_packet.SUBSCRIBE:
    #     with open("topics.txt", "a") as f:
    #         f.write(f"{mqtt_packet.topic_filters}\n")
