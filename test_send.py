from ads_b_udp import ADSBUDPSocket
import time
from packet_generator import PacketGenerator

socket = ADSBUDPSocket()

pg = PacketGenerator(0xABCDEF)

while True:
    packet = pg.createPacket()
    socket.send_packet(packet, "192.168.0.100", 30001)
    time.sleep(0.1)