import argparse
import random
import time

from ads_b_udp import ADSBUDPSocket
from packet_generator import build_adsb_packet_hex, maybe_encrypt_icao, parse_icao


# Hardcoded ICAO pool for random packet generation.
# "COFFEE" is normalized to "C0FFEE" so it remains valid hexadecimal.
KNOWN_ICAOS = ["45AB3C", "A1B2C3", "7C1D2E", "C0FFEE", "BADA55"]


def test_send(
    option: str = "u",
    count: int = 1,
    interval_ms: int = 0,
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

        for i in range(count):
            selected_icao = random.choice(KNOWN_ICAOS)
            base_icao = parse_icao(selected_icao)
            packet_icao, was_encrypted = maybe_encrypt_icao(base_icao, option)
            packet_hex = build_adsb_packet_hex(packet_icao)

            ads_b.send_packet(packet_hex, remote_host, remote_port)
            status = "ENCRYPTED" if was_encrypted else "PLAIN"
            print(f"{i + 1:03d}. Sent [{status}] SRC_ICAO={selected_icao} PACKET={packet_hex}")

            if interval_ms > 0 and i < count - 1:
                time.sleep(interval_ms / 1000.0)
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
    parser.add_argument("--local-host", default="192.168.0.101", help="Local host/IP to bind UDP socket")
    parser.add_argument("--local-port", type=int, default=30001, help="Local UDP port")
    parser.add_argument("--remote-host", default="192.168.0.100", help="Destination host/IP")
    parser.add_argument("--remote-port", type=int, default=30001, help="Destination UDP port")
    args = parser.parse_args()

    test_send(
        option=args.option,
        count=args.count,
        interval_ms=args.interval_ms,
        local_host=args.local_host,
        local_port=args.local_port,
        remote_host=args.remote_host,
        remote_port=args.remote_port,
    )


if __name__ == "__main__":
    main()