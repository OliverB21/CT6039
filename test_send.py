import argparse
import csv
import random
import time
from datetime import datetime
from statistics import mean
from typing import Dict, List

from ads_b_udp import ADSBUDPSocket
from packet_generator import build_adsb_packet_hex, maybe_encrypt_icao, parse_icao


# Hardcoded ICAO pool for random packet generation.
# "COFFEE" is normalized to "C0FFEE" so it remains valid hexadecimal.
KNOWN_ICAOS = ["45AB3C", "A1B2C3", "7C1D2E", "C0FFEE", "A58B4D"]


def append_metrics_csv(log_file: str, rows: List[Dict[str, str]]) -> None:
    """Append packet timing metrics to CSV for later analysis."""
    if not rows:
        return

    fieldnames = [
        "timestamp_utc",
        "packet_index",
        "mode",
        "selected_icao",
        "status",
        "icao_result",
        "encrypt_or_select_ms",
        "packet_build_ms",
        "send_ms",
        "total_packet_ms",
        "packet_hex",
    ]

    with open(log_file, "a", newline="", encoding="ascii") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if csvfile.tell() == 0:
            writer.writeheader()
        writer.writerows(rows)


def print_timing_summary(label: str, durations_ms: List[float]) -> None:
    """Print summary stats for a timing category."""
    if not durations_ms:
        print(f"{label}: no samples")
        return

    print(
        f"{label}: count={len(durations_ms)} "
        f"avg={mean(durations_ms):.3f}ms "
        f"min={min(durations_ms):.3f}ms "
        f"max={max(durations_ms):.3f}ms"
    )


def test_send(
    option: str = "u",
    count: int = 1,
    interval_ms: int = 0,
    log_file: str = "adsb_metrics.csv",
    local_host: str = "192.168.0.101",
    local_port: int = 30001,
    remote_host: str = "192.168.0.100",
    remote_port: int = 30001,
) -> None:
    """Generate ADS-B packets and send them to the configured receiver."""
    ads_b = ADSBUDPSocket(port=local_port, host=local_host)
    try:
        if count < 1:
            raise ValueError("Count must be >= 1")
        if interval_ms < 0:
            raise ValueError("Interval must be >= 0 milliseconds")

        plain_encrypt_step_ms: List[float] = []
        encrypted_encrypt_step_ms: List[float] = []
        plain_total_ms: List[float] = []
        encrypted_total_ms: List[float] = []
        csv_rows: List[Dict[str, str]] = []

        for i in range(count):
            packet_start = time.perf_counter_ns()
            selected_icao = random.choice(KNOWN_ICAOS)
            base_icao = parse_icao(selected_icao)

            enc_start = time.perf_counter_ns()
            packet_icao, was_encrypted = maybe_encrypt_icao(base_icao, option)
            enc_end = time.perf_counter_ns()

            build_start = time.perf_counter_ns()
            packet_hex = build_adsb_packet_hex(packet_icao)
            build_end = time.perf_counter_ns()

            send_start = time.perf_counter_ns()
            ads_b.send_packet(packet_hex, remote_host, remote_port)
            send_end = time.perf_counter_ns()

            packet_end = time.perf_counter_ns()

            encrypt_step_ms = (enc_end - enc_start) / 1_000_000
            build_ms = (build_end - build_start) / 1_000_000
            send_ms = (send_end - send_start) / 1_000_000
            total_packet_ms = (packet_end - packet_start) / 1_000_000

            status = "ENCRYPTED" if was_encrypted else "PLAIN"
            if was_encrypted:
                encrypted_encrypt_step_ms.append(encrypt_step_ms)
                encrypted_total_ms.append(total_packet_ms)
            else:
                plain_encrypt_step_ms.append(encrypt_step_ms)
                plain_total_ms.append(total_packet_ms)

            csv_rows.append(
                {
                    "timestamp_utc": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
                    "packet_index": str(i + 1),
                    "mode": option,
                    "selected_icao": selected_icao,
                    "status": status,
                    "icao_result": f"{packet_icao:06X}",
                    "encrypt_or_select_ms": f"{encrypt_step_ms:.6f}",
                    "packet_build_ms": f"{build_ms:.6f}",
                    "send_ms": f"{send_ms:.6f}",
                    "total_packet_ms": f"{total_packet_ms:.6f}",
                    "packet_hex": packet_hex,
                }
            )

            print(
                f"{i + 1:03d}. Sent [{status}] SRC_ICAO={selected_icao} "
                f"PACKET={packet_hex} "
                f"enc_step={encrypt_step_ms:.3f}ms build={build_ms:.3f}ms "
                f"send={send_ms:.3f}ms total={total_packet_ms:.3f}ms"
            )

            if interval_ms > 0 and i < count - 1:
                time.sleep(interval_ms / 1000.0)

        append_metrics_csv(log_file, csv_rows)

        print("\nTiming summary")
        print_timing_summary("Plain encrypt/select step", plain_encrypt_step_ms)
        print_timing_summary("Encrypted step", encrypted_encrypt_step_ms)
        print_timing_summary("Plain total packet", plain_total_ms)
        print_timing_summary("Encrypted total packet", encrypted_total_ms)
        print(f"Metrics CSV updated: {log_file}")
    except Exception as e:
        print(f"Error sending test packet: {e}")
    finally:
        ads_b.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Send one generated ADS-B test packet over UDP")
    parser.add_argument(
        "-o",
        "--option",
        choices=["e", "u", "m"],
        default="u",
        help="ICAO handling option: e=encrypt, u=unencrypted, m=mixed",
    )
    parser.add_argument("-n", "--count", type=int, default=1, help="Number of packets to send")
    parser.add_argument(
        "-t",
        "--interval-ms",
        type=int,
        default=0,
        help="Delay in milliseconds between packet broadcasts",
    )
    parser.add_argument(
        "--log-file",
        default="adsb_metrics.csv",
        help="CSV file to append timing metrics",
    )
    parser.add_argument("--local-host", default="192.168.0.101", help="Local host/IP to bind UDP socket")
    parser.add_argument("--local-port", type=int, default=30001, help="Local UDP port")
    parser.add_argument("--remote-host", default="192.168.0.100", help="Destination host/IP")
    parser.add_argument("--remote-port", type=int, default=30001, help="Destination UDP port")
    args = parser.parse_args()

    test_send(
        option=args.option,
        count=args.count,
        interval_ms=args.interval_ms,
        log_file=args.log_file,
        local_host=args.local_host,
        local_port=args.local_port,
        remote_host=args.remote_host,
        remote_port=args.remote_port,
    )


if __name__ == "__main__":
    main()