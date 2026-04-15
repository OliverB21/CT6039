# This code should:
# 1. Create decryption functions for each hardcoded icao number
# 2. Read in a packet from the ads_b_udp.py, as a hex string
# 3. Parse the packet to extract the encrypted ICAO number
# 4. Decrypt the ICAO number checking all of the hardcoded decryption functions until a match is found
# 5. Decode the packet using pymodes

import custom_encryption
import pyModeS as pms
import time

class PacketDecoder():
    def __init__(self):
        self.dec_45AB3C = custom_encryption.CustomEncDec(0x45AB3C)
        self.dec_A1B2C3 = custom_encryption.CustomEncDec(0xA1B2C3)
        self.dec_7C1D2E = custom_encryption.CustomEncDec(0x7C1D2E)
        self.dec_C0FFEE = custom_encryption.CustomEncDec(0xC0FFEE)
        self.dec_A58B4D = custom_encryption.CustomEncDec(0xA58B4D)

    def decrypt_icao(self, enc_icao):
        for dec in [self.dec_45AB3C, self.dec_A1B2C3, self.dec_7C1D2E, self.dec_C0FFEE, self.dec_A58B4D]:
            decrypted = dec.decrypt_icao(enc_icao)
            print(f"Encrypted ICAO: {enc_icao}, Decrypted ICAO: {str(decrypted).upper()}")
            if decrypted in [0x45AB3C, 0xA1B2C3, 0x7C1D2E, 0xC0FFEE, 0xA58B4D]:
                return decrypted
        return 0x000000
    
    def read_icao(self, packet_hex):
        # Placeholder for reading and parsing the packet
        # This should extract the encrypted ICAO from the packet
        enc_icao = packet_hex[2:8]  # Replace with actual extraction logic
        return enc_icao
    
    def decode_packet(self, packet_hex):
        enc_icao = self.read_icao(packet_hex)
        decrypted_icao = self.decrypt_icao(enc_icao)
        #pms.tell(packet_hex)
        return decrypted_icao  # Replace with actual decoded data
    
if __name__ == "__main__":
    print("--Starting Packet Decoder Test--")
    decoder = PacketDecoder()
    test_packet_hex = "8D45AB3D0000000000000000000000000000"  # Replace with actual test packet
    decrypted_icao = decoder.decode_packet(test_packet_hex)
    print(f"Decrypted ICAO: {hex(decrypted_icao)[2:].upper()}")
    icao = decoder.read_icao(test_packet_hex)
    decrypted_icao = decoder.decrypt_icao(icao)