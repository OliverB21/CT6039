import argparse
import random
from typing import Tuple

from custom_encryption import CustomEncDec


# Hardcoded known ICAOs used by generator and decoder examples.
KNOWN_ICAOS = [
	0x45AB3C,
	0xA1B2C3,
	0x7C1D2E,
	0xC0FFEE,
	0xBADA55,
]


def parse_icao(icao_input: str) -> int:
	"""Parse and validate ICAO input as a 24-bit integer."""
	cleaned = icao_input.strip().upper().replace("0X", "")
	if not cleaned or len(cleaned) > 6:
		raise ValueError("ICAO must be 1-6 hex characters")

	try:
		icao = int(cleaned, 16)
	except ValueError as exc:
		raise ValueError("ICAO must be a valid hexadecimal value") from exc

	if not 0 <= icao <= 0xFFFFFF:
		raise ValueError("ICAO must fit in 24 bits")

	return icao


def mode_s_crc_24(message_bits: int, bit_length: int = 88) -> int:
	"""Compute Mode S 24-bit CRC for the first 88 bits of a DF17 packet."""
	poly = 0xFFF409
	reg = message_bits

	for i in range(bit_length):
		if reg & (1 << (bit_length + 23 - i)):
			reg ^= poly << (bit_length - 1 - i)

	return reg & 0xFFFFFF


def build_adsb_packet_hex(icao_int: int) -> str:
	"""Build a 112-bit DF17 ADS-B packet and return it as a 28-char hex string."""
	ca = random.randint(0, 7)
	df_ca = (17 << 3) | ca

	# Build arbitrary but structured ME payload: type code + random data bits.
	type_code = random.randint(1, 31)
	me = (type_code << 51) | random.getrandbits(51)

	first_88 = (df_ca << 80) | (icao_int << 56) | me
	crc = mode_s_crc_24(first_88, 88)
	full_packet = (first_88 << 24) | crc

	return f"{full_packet:028X}"


def maybe_encrypt_icao(icao_int: int, mode: str) -> Tuple[int, bool]:
	"""Return ICAO chosen per mode and whether encryption was used."""
	if mode not in {"e", "u", "m"}:
		raise ValueError("Mode must be one of: e, u, m")

	use_encryption = mode == "e" or (mode == "m" and random.choice([True, False]))
	if not use_encryption:
		return icao_int, False

	# CustomEncDec expects an int-style ICAO for init and a hex string for encrypt.
	icao_init_int = int(f"0x{icao_int:06X}", 16)
	encryptor = CustomEncDec(icao_init_int)
	encrypted_hex = str(encryptor.encrypt_icao(f"{icao_int:06x}"))
	return int(encrypted_hex, 16), True


def generate_packets(icao_input: str, mode: str, count: int) -> None:
	"""Generate and print ADS-B packets using the selected ICAO handling mode."""
	base_icao = parse_icao(icao_input)

	for i in range(count):
		packet_icao, was_encrypted = maybe_encrypt_icao(base_icao, mode)
		packet_hex = build_adsb_packet_hex(packet_icao)

		status = "ENCRYPTED" if was_encrypted else "PLAIN"
		print(
			f"{i + 1:03d}. [{status}] "
			f"ICAO={packet_icao:06X} PACKET={packet_hex}"
		)


def main() -> None:
	parser = argparse.ArgumentParser(
		description=(
			"Generate simple ADS-B DF17 hex packets from an input ICAO code "
			"or from a hardcoded known ICAO list. "
			"Mode 'e' encrypts all ICAOs, 'u' keeps all unencrypted, and "
			"'m' mixes encrypted and unencrypted packets."
		)
	)
	parser.add_argument(
		"icao",
		nargs="?",
		help="Input ICAO code in hex (example: 45AB3C). If omitted, random known ICAO is used.",
	)
	parser.add_argument(
		"-o",
		"--option",
		choices=["e", "u", "m"],
		default="u",
		help="ICAO handling option: e=encrypt, u=unencrypted, m=mixed",
	)
	parser.add_argument(
		"-n",
		"--count",
		type=int,
		default=1,
		help="Number of packets to generate (default: 1)",
	)

	args = parser.parse_args()

	icao_input = args.icao
	if not icao_input:
		icao_input = f"{random.choice(KNOWN_ICAOS):06X}"
		print(f"No ICAO supplied, selected known ICAO: {icao_input}")

	if args.count < 1:
		raise ValueError("Count must be >= 1")

	generate_packets(icao_input, args.option, args.count)


if __name__ == "__main__":
	main()
