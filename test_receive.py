import argparse
import csv
import time
from datetime import datetime

from ads_b_udp import ADSBUDPSocket
from packet_decoder import PacketDecoder
import pyModeS as pms


KNOWN_ICAOS = {"45AB3C", "A1B2C3", "7C1D2E", "C0FFEE", "A58B4D"}
KNOWN_ICAO_ORDER = ["45AB3C", "A1B2C3", "7C1D2E", "C0FFEE", "A58B4D"]
CSV_FIELDNAMES = [
    "timestamp_utc",
    "packet_index",
    "mode",
    "selected_icao",
    "status",
    "icao_result",
    "attempted_decryptions",
    "total_packet_ms",
    "packet_hex",
]

PACKET_COUNTER = 0
LOG_FILE = "adsb_metrics_receive.csv"


def as_icao_hex(value) -> str:
    if isinstance(value, int):
        return f"{value & 0xFFFFFF:06X}"
    return str(value).strip().upper().replace("0X", "").zfill(6)[-6:]


def append_metrics_csv(log_file: str, row: dict) -> None:
    with open(log_file, "a", newline="", encoding="ascii") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=CSV_FIELDNAMES)
        if csvfile.tell() == 0:
            writer.writeheader()
        writer.writerow(row)


def packet_status(src_icao: str, decoded_icao: str) -> str:
    if decoded_icao == "000000":
        return "UNKNOWN"
    if src_icao == decoded_icao and src_icao in KNOWN_ICAOS:
        return "PLAIN"
    return "ENCRYPTED"


def attempted_decryptions(decoded_icao: str) -> int:
    if decoded_icao in KNOWN_ICAO_ORDER:
        return KNOWN_ICAO_ORDER.index(decoded_icao) + 1
    return len(KNOWN_ICAO_ORDER)

def confirm(hex_packet, addr):
    global PACKET_COUNTER

    packet_start = time.perf_counter_ns()
    decoder = PacketDecoder()
    decode_start = time.perf_counter_ns()
    dec = decoder.decode_packet(hex_packet)
    decode_end = time.perf_counter_ns()
    packet_end = time.perf_counter_ns()

    PACKET_COUNTER += 1
    src_icao = hex_packet[2:8] if len(hex_packet) >= 8 else "000000"
    decoded_icao = as_icao_hex(dec)
    status = packet_status(src_icao, decoded_icao)
    attempts = attempted_decryptions(decoded_icao)
    dec_step_ms = (decode_end - decode_start) / 1_000_000
    total_ms = (packet_end - packet_start) / 1_000_000

    print(
        f"{PACKET_COUNTER:03d}. Recv [{status}] SRC_ICAO={src_icao} "
        f"PACKET={hex_packet} "
        f"dec_step={dec_step_ms:.3f}ms attempts={attempts} "
        f"build=0.000ms send=0.000ms total={total_ms:.3f}ms"
    )
    print(dec)

    append_metrics_csv(
        LOG_FILE,
        {
            "timestamp_utc": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
            "packet_index": str(PACKET_COUNTER),
            "mode": "recv",
            "selected_icao": src_icao,
            "status": status,
            "icao_result": decoded_icao,
            "attempted_decryptions": str(attempts),
            "total_packet_ms": f"{total_ms:.6f}",
            "packet_hex": hex_packet,
        },
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Receive ADS-B packets and log metrics")
    parser.add_argument("--host", default="192.168.0.100", help="Local host/IP to bind UDP socket")
    parser.add_argument("--port", type=int, default=30001, help="Local UDP port")
    parser.add_argument("--log-file", default="adsb_metrics_receive.csv", help="CSV file for receive metrics")
    args = parser.parse_args()

    LOG_FILE = args.log_file
    socket = ADSBUDPSocket(host=args.host, port=args.port)
    socket.start_receiver(callback=confirm)

    input("Listening, enter to exit")

