# Note - this algorithm provides a simulation for an encryption algorithm,
# and does not securely generate keys or encrypt data. Proceed with caution

import datetime
import ffx

class CustomEncDec():
    def __init__(self, icao):
        key = self.generate_key(icao)
        self.key_bytes = key.to_bytes(16, byteorder='big', signed=False)
        self.ffx_obj = ffx.new(self.key_bytes, radix=16)

    def generate_key(self, icao):
        datebin = int(datetime.datetime.today().strftime('%Y-%m-%d').replace("-", ""))
        icaobin = icao*4
        return datebin ^ icaobin
    
    def encrypt_icao(self, icao):
        icao_no = ffx.FFXInteger(icao, radix=16, blocksize=6)
        tweak = ffx.FFXInteger("000000", radix=16, blocksize=6)
        encrypted = self.ffx_obj.encrypt(tweak, icao_no)
        return(encrypted)
    
    def decrypt_icao(self, enc_icao):
        enc_icao_no = ffx.FFXInteger(enc_icao, radix=16, blocksize=6)
        tweak = ffx.FFXInteger("000000", radix=16, blocksize=6)
        decrypted = self.ffx_obj.decrypt(tweak, enc_icao_no)
        return(decrypted)

if __name__ == "__main__":
    print("--Starting Encryption Test--")
    icao = 0x45ab3c
    print(f"Test ICAO No. - {hex(icao)[2:]}")
    gen = CustomEncDec(icao=icao)
    encrypted_icao = gen.encrypt_icao("45ab3c")
    print(f"Encrypted ICAO - {encrypted_icao}")
    decrypted_icao = gen.decrypt_icao(encrypted_icao)
    print(f"Decrypted ICAO - {decrypted_icao}")