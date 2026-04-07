from ads_b_udp import ADSBUDPSocket
from packet_decoder import PacketDecoder
import pyModeS as pms

def confirm(hex_packet, addr):
    decoder = PacketDecoder()
    dec = decoder.decode_packet(hex_packet)
    print(dec)

if __name__ == "__main__":
    socket = ADSBUDPSocket(host="192.168.0.100", port=30001)
    socket.start_receiver(callback=confirm)

    input("Listening, enter to exit")

