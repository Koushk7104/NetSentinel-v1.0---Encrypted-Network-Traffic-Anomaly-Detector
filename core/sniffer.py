"""
NetSentinel v1.0 — Live Packet Sniffer
Threaded Scapy packet capture with thread-safe buffer.
Requires Administrator privileges and Npcap on Windows.
"""

import threading
import time
from collections import deque
from datetime import datetime


class PacketCapture:
    """Threaded live packet capture using Scapy."""

    def __init__(self, interface=None, max_packets=10000):
        self.interface = interface
        self.max_packets = max_packets
        self.packet_buffer = deque(maxlen=max_packets)
        self._lock = threading.Lock()
        self._running = False
        self._thread = None
        self._packet_count = 0
        self._start_time = None
        self._last_error = None

    def start(self):
        """Start capturing packets in a background thread."""
        if self._running:
            return
        self._running = True
        self._last_error = None
        self._start_time = time.time()
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the capture."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)

    def is_running(self) -> bool:
        return self._running

    def get_error(self) -> str:
        """Return last error message, if any."""
        with self._lock:
            return self._last_error

    def get_packets(self) -> list:
        """Get all captured packets as structured dicts (thread-safe)."""
        with self._lock:
            return list(self.packet_buffer)

    def get_packet_count(self) -> int:
        return self._packet_count

    def get_elapsed_time(self) -> float:
        if self._start_time:
            return time.time() - self._start_time
        return 0

    def clear(self):
        """Clear the packet buffer."""
        with self._lock:
            self.packet_buffer.clear()
            self._packet_count = 0
            self._last_error = None

    def _capture_loop(self):
        """Internal capture loop — runs in a background thread."""
        try:
            from scapy.all import sniff, conf

            # On Windows, use conf.iface if no interface specified
            iface = self.interface
            if not iface or iface == "default":
                iface = conf.iface

            sniff(
                iface=iface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            self._running = False
            with self._lock:
                self._last_error = str(e)

    def _process_packet(self, pkt):
        """Process a single Scapy packet into a structured dict."""
        try:
            record = _packet_to_dict(pkt)
            if record:
                with self._lock:
                    self.packet_buffer.append(record)
                    self._packet_count += 1
        except Exception:
            pass


def _packet_to_dict(pkt) -> dict:
    """Convert a Scapy packet to a structured dictionary."""
    try:
        record = {
            "timestamp": float(pkt.time),
            "size": len(pkt),
            "protocol": "UNKNOWN",
            "src_ip": "",
            "dst_ip": "",
            "src_port": 0,
            "dst_port": 0,
            "flags": "",
            "payload_size": 0,
        }

        # IP layer
        if pkt.haslayer("IP"):
            ip = pkt["IP"]
            record["src_ip"] = ip.src
            record["dst_ip"] = ip.dst
            record["protocol"] = _proto_name(ip.proto)

        # TCP layer
        if pkt.haslayer("TCP"):
            tcp = pkt["TCP"]
            record["src_port"] = tcp.sport
            record["dst_port"] = tcp.dport
            record["flags"] = str(tcp.flags)
            record["protocol"] = "TCP"
            record["payload_size"] = len(tcp.payload) if tcp.payload else 0

        # UDP layer
        elif pkt.haslayer("UDP"):
            udp = pkt["UDP"]
            record["src_port"] = udp.sport
            record["dst_port"] = udp.dport
            record["protocol"] = "UDP"
            record["payload_size"] = len(udp.payload) if udp.payload else 0

        # ICMP layer
        elif pkt.haslayer("ICMP"):
            record["protocol"] = "ICMP"

        # DNS
        if pkt.haslayer("DNS"):
            record["protocol"] = "DNS"

        # ARP
        if pkt.haslayer("ARP"):
            arp = pkt["ARP"]
            record["protocol"] = "ARP"
            record["src_ip"] = arp.psrc
            record["dst_ip"] = arp.pdst

        return record
    except Exception:
        return None


def _proto_name(proto_num: int) -> str:
    """Convert IP protocol number to name."""
    names = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH"}
    return names.get(proto_num, f"PROTO_{proto_num}")


def check_capture_prerequisites() -> dict:
    """Check if live capture prerequisites are met."""
    result = {
        "scapy_available": False,
        "npcap_available": False,
        "is_admin": False,
        "errors": [],
        "warnings": [],
    }

    # Check Scapy
    try:
        import scapy.all
        result["scapy_available"] = True
    except ImportError:
        result["errors"].append("Scapy is not installed. Run: pip install scapy")

    # Check Admin
    try:
        import ctypes
        result["is_admin"] = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        # Non-Windows or can't check — assume ok and let Scapy fail naturally
        result["is_admin"] = True
    if not result["is_admin"]:
        result["warnings"].append("⚠️ Not running as Administrator — live capture may fail. Right-click terminal → Run as Administrator.")

    # Check Npcap
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
        result["npcap_available"] = len(ifaces) > 0
    except Exception:
        result["warnings"].append("⚠️ Npcap not detected — install from https://npcap.com/ if live capture fails.")

    return result


def get_interfaces_for_display() -> list:
    """Get network interfaces formatted for UI display."""
    try:
        from scapy.all import get_if_list, conf
        ifaces = get_if_list()
        results = []
        
        # Add default interface first
        default = str(conf.iface)
        results.append(("default", f"Default ({default})"))
        
        # Add all detected interfaces
        for iface in ifaces:
            name = str(iface)
            if name != default:
                results.append((name, name))
        
        return results if results else [("default", "Default Interface")]
    except Exception:
        pass

    # Fallback: try Windows-specific detection
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
        results = [("default", "Default Interface")]
        for iface in ifaces:
            desc = iface.get("description", iface.get("name", "Unknown"))
            name = iface.get("name", desc)
            results.append((name, desc))
        return results
    except Exception:
        return [("default", "Default Interface")]
