import socket
import threading
from typing import Callable, Optional


class ADSBUDPSocket:
    """
    Simple UDP socket class for sending and receiving ADS-B hex packets.
    
    Designed for a three-script workflow:
    1. External script generates ADS-B hex packets
    2. This class sends and receives packets
    3. External script decodes received packets
    """
    
    def __init__(self, port: int = 30001, host: str = "0.0.0.0"):
        """
        Initialize the UDP socket.
        
        Args:
            port: UDP port to listen on (default: 30001)
            host: Host to bind to (default: "0.0.0.0" for all interfaces)
        """
        self.port = port
        self.host = host
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        
        self.receiving = False
        self.receive_thread = None
        self.receive_callback = None
        
    def send_packet(self, hex_packet: str, remote_host: str, remote_port: int) -> None:
        """
        Send a hex packet to a remote address.
        
        Args:
            hex_packet: Hex string (e.g., "8D4CA6B8...")
            remote_host: Destination host/IP
            remote_port: Destination port
        """
        try:
            # Convert hex string to bytes
            packet_bytes = bytes.fromhex(hex_packet)
            self.socket.sendto(packet_bytes, (remote_host, remote_port))
            print(f"Sent packet to {remote_host}:{remote_port} - {hex_packet[:20]}...")
        except ValueError as e:
            print(f"Error: Invalid hex string - {e}")
        except Exception as e:
            print(f"Error sending packet: {e}")
    
    def start_receiver(self, callback: Optional[Callable[[str, tuple], None]] = None) -> None:
        """
        Start listening for incoming packets in a background thread.
        
        Args:
            callback: Optional function to call when packet is received.
                     Function signature: callback(hex_packet: str, (host, port): tuple)
        """
        if self.receiving:
            print("Receiver already running")
            return
        
        self.receiving = True
        self.receive_callback = callback
        self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.receive_thread.start()
        print(f"Receiver started on {self.host}:{self.port}")
    
    def stop_receiver(self) -> None:
        """Stop the receiver thread."""
        self.receiving = False
        if self.receive_thread:
            self.receive_thread.join(timeout=2)
        print("Receiver stopped")
    
    def _receive_loop(self) -> None:
        """Internal loop for receiving packets."""
        while self.receiving:
            try:
                # Receive up to 1500 bytes (typical UDP packet size for ADS-B)
                data, addr = self.socket.recvfrom(1500)
                hex_packet = data.hex().upper()
                
                print(f"Received packet from {addr[0]}:{addr[1]} - {hex_packet[:20]}...")
                
                # Call callback if provided
                if self.receive_callback:
                    self.receive_callback(hex_packet, addr)
                    
            except Exception as e:
                if self.receiving:
                    print(f"Error receiving packet: {e}")
    
    def close(self) -> None:
        """Close the socket and stop all operations."""
        self.stop_receiver()
        self.socket.close()
        print("Socket closed")


if __name__ == "__main__":
    # Example usage
    
    def packet_handler(hex_packet: str, addr: tuple):
        """Handle received packets - pass to your decoder script."""
        print(f"Handler: Got packet {hex_packet}")
    
    # Create socket instance
    ads_b = ADSBUDPSocket(port=30001, host="0.0.0.0")
    
    # Start receiver with callback
    ads_b.start_receiver(callback=packet_handler)
    
    # Send a test packet (to localhost for testing)
    try:
        test_hex = "8D4CA6B8E7A92E5D9A6F1C3B2E5A7C9D"
        ads_b.send_packet(test_hex, "127.0.0.1", 30001)
    except KeyboardInterrupt:
        pass
    finally:
        ads_b.close()