from ads_b_udp import ADSBUDPSocket
import pyModeS as pms

def confirm(hex_packet, addr):
    print(f"Packet Receieved- {hex_packet}, {addr}")
    print(pms.tell(hex_packet))

if __name__ == "__main__":
    socket = ADSBUDPSocket(port=30001)
    socket.start_receiver(callback=confirm)

    input("Listening, entre to exit")

