import socket
import threading
import random
import os
import hashlib
import time
from typing import Callable, Optional


class ADSBUDPSocket:
    """
    UDP socket class for ADS-B-like test packets with:
      - plain mode (baseline testing)
      - encrypted mode
      - mixed mode
    Packet format:
      <prefix_hex><mode_byte><icao_payload>

    mode_byte:
      00 = plain ICAO (3 bytes)
      01 = encrypted ICAO (nonce 8 bytes + ciphertext 3 bytes)
    """

    MODE_PLAIN = "00"
    MODE_ENCRYPTED = "01"

    def __init__(
        self,
        port: int = 30001,
        host: str = "0.0.0.0",
        icao_codes: Optional[list[str]] = None,
        encryption_key: str = "change-this-key",
        packet_prefix_hex: str = "8D",
    ):
        self.port = port
        self.host = host
        self.packet_prefix_hex = packet_prefix_hex.upper()

        # Validate prefix hex
        if len(self.packet_prefix_hex) % 2 != 0:
            raise ValueError("packet_prefix_hex must have even hex length")
        if self.packet_prefix_hex:
            int(self.packet_prefix_hex, 16)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))

        self.receiving = False
        self.receive_thread = None
        self.receive_callback = None

        self.icao_codes = icao_codes or ["4CA6B8", "40621D", "A1B2C3", "7C6B5A", "3D2E1F"]
        if len(self.icao_codes) != 5:
            raise ValueError("icao_codes must contain exactly 5 ICAO codes")
        for code in self.icao_codes:
            if len(code) != 6:
                raise ValueError(f"Invalid ICAO code length: {code}")
            int(code, 16)

        self.encryption_key = encryption_key.encode("utf-8")

        # Simple in-memory timing logs
        self.tx_log = []
        self.rx_log = []

    def _encrypt_icao(self, icao_hex: str) -> str:
        icao_bytes = bytes.fromhex(icao_hex)  # 3 bytes
        nonce = os.urandom(8)
        keystream = hashlib.sha256(self.encryption_key + nonce).digest()[: len(icao_bytes)]
        ciphertext = bytes(a ^ b for a, b in zip(icao_bytes, keystream))
        return (nonce + ciphertext).hex().upper()  # 11 bytes => 22 hex chars

    def decrypt_icao(self, encrypted_hex: str) -> str:
        data = bytes.fromhex(encrypted_hex)
        if len(data) != 11:
            raise ValueError("Encrypted ICAO payload must be 11 bytes")
        nonce = data[:8]
        ciphertext = data[8:11]
        keystream = hashlib.sha256(self.encryption_key + nonce).digest()[: len(ciphertext)]
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream))
        return plaintext.hex().upper()

    def _build_packet(self, selected_icao: str, mode: str) -> str:
        if mode == self.MODE_PLAIN:
            payload = selected_icao
        elif mode == self.MODE_ENCRYPTED:
            payload = self._encrypt_icao(selected_icao)
        else:
            raise ValueError("mode must be '00' (plain) or '01' (encrypted)")
        return f"{self.packet_prefix_hex}{mode}{payload}"

    def send_packet(self, hex_packet: str, remote_host: str, remote_port: int) -> None:
        packet_bytes = bytes.fromhex(hex_packet)
        self.socket.sendto(packet_bytes, (remote_host, remote_port))

    def send_random_icao_broadcast(
        self,
        remote_host: str,
        remote_port: int,
        mode: str = "encrypted",
    ) -> dict:
        """
        mode: 'plain' | 'encrypted' | 'mixed'
        """
        selected_icao = random.choice(self.icao_codes)

        if mode == "plain":
            mode_byte = self.MODE_PLAIN
        elif mode == "encrypted":
            mode_byte = self.MODE_ENCRYPTED
        elif mode == "mixed":
            mode_byte = random.choice([self.MODE_PLAIN, self.MODE_ENCRYPTED])
        else:
            raise ValueError("mode must be 'plain', 'encrypted', or 'mixed'")

        t0 = time.perf_counter_ns()
        hex_packet = self._build_packet(selected_icao, mode_byte)
        t1 = time.perf_counter_ns()
        self.send_packet(hex_packet, remote_host, remote_port)
        t2 = time.perf_counter_ns()

        tx_entry = {
            "timestamp": time.time(),
            "mode": "encrypted" if mode_byte == self.MODE_ENCRYPTED else "plain",
            "icao": selected_icao,
            "packet_len_bytes": len(hex_packet) // 2,
            "build_ns": t1 - t0,
            "send_ns": t2 - t1,
            "total_ns": t2 - t0,
        }
        self.tx_log.append(tx_entry)

        print(
            f"TX {tx_entry['mode']} -> {remote_host}:{remote_port}, "
            f"ICAO={selected_icao}, total={tx_entry['total_ns']}ns"
        )
        return tx_entry

    def parse_packet(self, hex_packet: str) -> dict:
        pkt = hex_packet.upper()

        if self.packet_prefix_hex and not pkt.startswith(self.packet_prefix_hex):
            return {"valid": False, "reason": "prefix mismatch", "raw": pkt}

        body = pkt[len(self.packet_prefix_hex):]
        if len(body) < 2:
            return {"valid": False, "reason": "missing mode byte", "raw": pkt}

        mode_byte = body[:2]
        payload = body[2:]

        if mode_byte == self.MODE_PLAIN:
            if len(payload) != 6:
                return {"valid": False, "reason": "plain payload length invalid", "raw": pkt}
            return {"valid": True, "mode": "plain", "icao": payload}
        elif mode_byte == self.MODE_ENCRYPTED:
            if len(payload) != 22:
                return {"valid": False, "reason": "encrypted payload length invalid", "raw": pkt}
            try:
                icao = self.decrypt_icao(payload)
                return {"valid": True, "mode": "encrypted", "icao": icao}
            except Exception as e:
                return {"valid": False, "reason": f"decrypt error: {e}", "raw": pkt}
        else:
            return {"valid": False, "reason": f"unknown mode byte {mode_byte}", "raw": pkt}

    def start_receiver(self, callback: Optional[Callable] = None) -> None:
        if self.receiving:
            print("Receiver already running")
            return
        self.receiving = True
        self.receive_callback = callback
        self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.receive_thread.start()
        print(f"Receiver started on {self.host}:{self.port}")

    def stop_receiver(self) -> None:
        self.receiving = False
        if self.receive_thread:
            self.receive_thread.join(timeout=2)
        print("Receiver stopped")

    def _receive_loop(self) -> None:
        while self.receiving:
            try:
                data, addr = self.socket.recvfrom(1500)
                t0 = time.perf_counter_ns()
                hex_packet = data.hex().upper()
                parsed = self.parse_packet(hex_packet)
                t1 = time.perf_counter_ns()

                rx_entry = {
                    "timestamp": time.time(),
                    "from": addr,
                    "packet_len_bytes": len(data),
                    "parse_ns": t1 - t0,
                    "parsed": parsed,
                }
                self.rx_log.append(rx_entry)

                print(f"RX from {addr[0]}:{addr[1]} parse={rx_entry['parse_ns']}ns -> {parsed}")

                if self.receive_callback:
                    try:
                        self.receive_callback(hex_packet, addr, parsed)
                    except TypeError:
                        # backward compatibility with old callback(hex_packet, addr)
                        self.receive_callback(hex_packet, addr)

            except Exception as e:
                if self.receiving:
                    print(f"Error receiving packet: {e}")

    def close(self) -> None:
        self.stop_receiver()
        self.socket.close()
        print("Socket closed")


if __name__ == "__main__":
    def packet_handler(hex_packet: str, addr: tuple, parsed: dict):
        print(f"Handler parsed={parsed}")

    ads_b = ADSBUDPSocket(
        port=30001,
        host="0.0.0.0",
        icao_codes=["4CA6B8", "40621D", "A1B2C3", "7C6B5A", "3D2E1F"],
        encryption_key="my-secret-key",
        packet_prefix_hex="8D",
    )

    ads_b.start_receiver(callback=packet_handler)

    try:
        # plain baseline
        for _ in range(3):
            ads_b.send_random_icao_broadcast("127.0.0.1", 30001, mode="plain")

        # encrypted
        for _ in range(3):
            ads_b.send_random_icao_broadcast("127.0.0.1", 30001, mode="encrypted")

        # mixed
        for _ in range(6):
            ads_b.send_random_icao_broadcast("127.0.0.1", 30001, mode="mixed")

        print(f"TX log entries: {len(ads_b.tx_log)}")
        print(f"RX log entries: {len(ads_b.rx_log)}")
    finally:
        ads_b.close()