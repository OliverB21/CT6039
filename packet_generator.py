import random
from custom_encryption import CustomEncDec


class PacketGenerator:
    def __init__(self, icao):
        self.icao = icao

    def createPacket(self, return_params=False):
        packet = "8D"  # DF17 + CA

        encrypted_icao = self._encrypt_icao(self.icao)
        packet += str(encrypted_icao)
        packet = packet[:2] + packet[2:8].upper().zfill(6)

        adsb_params = self._random_adsb_params()
        me = self._build_me_from_params(adsb_params)
        packet += me.hex().upper()

        parity = self._crc24(bytes.fromhex(packet)) ^ self.icao
        packet += f"{parity:06X}"

        if return_params:
            return packet, adsb_params
        return packet

    def _encrypt_icao(self, icao):
        enc = CustomEncDec(icao)
        enc_icao = enc.encrypt_icao(str(hex(icao))[2:])
        return enc_icao

    def _random_adsb_params(self):
        # Airborne position message fields (Type Code 9-18)
        altitude_ft = random.randrange(0, 45025, 25)
        n = max(0, min(0x7FF, (altitude_ft + 1000) // 25))
        alt_code = ((n & 0x7FF) << 1) | 1  # simple Q=1 style encoding

        return {
            "type_code": random.randint(9, 18),
            "surveillance_status": random.randint(0, 3),
            "nic_supplement_b": random.randint(0, 1),
            "altitude_ft": altitude_ft,
            "altitude_code": alt_code & 0x0FFF,
            "time_flag": random.randint(0, 1),
            "cpr_format": random.randint(0, 1),  # 0=even, 1=odd
            "cpr_lat": random.randint(0, 0x1FFFF),
            "cpr_lon": random.randint(0, 0x1FFFF),
        }

    def _build_me_from_params(self, p):
        me_val = 0
        me_val |= (p["type_code"] & 0x1F) << 51
        me_val |= (p["surveillance_status"] & 0x03) << 49
        me_val |= (p["nic_supplement_b"] & 0x01) << 48
        me_val |= (p["altitude_code"] & 0x0FFF) << 36
        me_val |= (p["time_flag"] & 0x01) << 35
        me_val |= (p["cpr_format"] & 0x01) << 34
        me_val |= (p["cpr_lat"] & 0x1FFFF) << 17
        me_val |= (p["cpr_lon"] & 0x1FFFF)
        return me_val.to_bytes(7, byteorder="big")

    @staticmethod
    def _crc24(data: bytes) -> int:
        poly = 0xFFF409
        crc = 0
        for b in data:
            crc ^= b << 16
            for _ in range(8):
                crc <<= 1
                if crc & 0x1000000:
                    crc ^= poly
            crc &= 0xFFFFFF
        return crc


if __name__ == "__main__":
    pg = PacketGenerator(0xABCDEF)
    packet, params = pg.createPacket(return_params=True)
    print(packet)
    print(params)