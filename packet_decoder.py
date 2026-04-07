import argparse
from typing import Optional

import pyModeS as pms

from ads_b_udp import ADSBUDPSocket
from custom_encryption import CustomEncDec


KNOWN_ICAOS = [
	0x45AB3C,
	0xA1B2C3,
	0x7C1D2E,
	0xC0FFEE,
	0xBADA55,
]


def try_decrypt_against_known(observed_icao_hex: str) -> Optional[int]:
	"""Try decrypting observed ICAO with each known ICAO key; return matched ICAO."""
	for known_icao_int in KNOWN_ICAOS:
		try:
			decryptor = CustomEncDec(known_icao_int)
			decrypted = str(decryptor.decrypt_icao(observed_icao_hex.lower())).upper().zfill(6)
		except Exception:
			continue

		if decrypted == f"{known_icao_int:06X}":
			return known_icao_int

	return None


def decode_packet(hex_packet: str, show_tell: bool = False) -> None:
	"""Decode and print packet information with known-ICAO flagging."""
	msg = hex_packet.strip().upper()
	flags = []

	if len(msg) not in {14, 28}:
		print(f"[INVALID] len={len(msg)} packet={msg}")
		return

	try:
		df = pms.df(msg)
	except Exception as exc:
		print(f"[INVALID] packet={msg} error={exc}")
		return

	icao = None
	try:
		icao = pms.icao(msg)
	except Exception:
		icao = None

	known_icao = None

	if icao:
		icao_int = int(icao, 16)
		if icao_int in KNOWN_ICAOS:
			flags.append("KNOWN_PLAIN_ICAO")
			known_icao = icao_int
		else:
			decrypted_match = try_decrypt_against_known(icao)
			if decrypted_match is not None:
				known_icao = decrypted_match
				flags.append("KNOWN_DECRYPTED_ICAO")

	flag_text = "|".join(flags) if flags else "UNFLAGGED"
	print(
		f"[{flag_text}] DF={df} ICAO={icao or 'N/A'} "
		f"PACKET={msg}"
	)

	if known_icao is not None:
		print(f"  -> matched_known_icao={known_icao:06X}")

	if show_tell:
		try:
			print("  ->", pms.tell(msg))
		except Exception as exc:
			print(f"  -> unable to generate tell(): {exc}")


def run_decoder(host: str, port: int, show_tell: bool = False) -> None:
	"""Run UDP receiver and decode each incoming packet."""

	def on_packet(hex_packet: str, addr: tuple) -> None:
		print(f"Packet received from {addr[0]}:{addr[1]}")
		decode_packet(hex_packet, show_tell=show_tell)

	socket = ADSBUDPSocket(port=port, host=host)
	socket.start_receiver(callback=on_packet)

	try:
		print(f"Listening on {host}:{port}. Press Enter to stop.")
		input()
	finally:
		socket.close()


def main() -> None:
	parser = argparse.ArgumentParser(
		description=(
			"Receive ADS-B packets over UDP, decode with pyModeS, and flag known "
			"ICAOs by plain ICAO or by decryption attempt against known ICAOs."
		)
	)
	parser.add_argument("--listen-host", default="0.0.0.0", help="Local host/IP to bind")
	parser.add_argument("--listen-port", type=int, default=30001, help="Local UDP port")
	parser.add_argument(
		"--show-tell",
		action="store_true",
		help="Print pyModeS tell() output after each decoded packet",
	)
	args = parser.parse_args()

	print("Loaded hardcoded known ICAOs:")
	for icao_int in KNOWN_ICAOS:
		print(f"  {icao_int:06X}")

	run_decoder(host=args.listen_host, port=args.listen_port, show_tell=args.show_tell)


if __name__ == "__main__":
	main()
