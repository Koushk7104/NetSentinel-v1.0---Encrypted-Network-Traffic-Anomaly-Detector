"""
NetSentinel v1.0 — PCAP File Parser
Parses .pcap files using Scapy and converts to structured packet records.
"""

import os
from core.sniffer import _packet_to_dict
from core.ja3_extractor import extract_ja3_from_scapy_packet


def parse_pcap(filepath: str, progress_callback=None) -> dict:
    """
    Parse a PCAP file and extract structured packet records + JA3 fingerprints.
    
    Args:
        filepath: Path to .pcap file
        progress_callback: Optional callable(current, total) for progress updates
    
    Returns:
        dict with 'packets', 'ja3_fingerprints', 'metadata'
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"PCAP file not found: {filepath}")

    from scapy.all import rdpcap

    # Read packets
    raw_packets = rdpcap(filepath)
    total = len(raw_packets)

    packets = []
    ja3_fingerprints = []

    for i, pkt in enumerate(raw_packets):
        # Convert to dict
        record = _packet_to_dict(pkt)
        if record:
            record["packet_index"] = i
            packets.append(record)

        # Try JA3 extraction
        ja3 = extract_ja3_from_scapy_packet(pkt)
        if ja3:
            ja3["packet_index"] = i
            ja3["src_ip"] = record["src_ip"] if record else ""
            ja3["dst_ip"] = record["dst_ip"] if record else ""
            ja3["timestamp"] = record["timestamp"] if record else 0
            ja3_fingerprints.append(ja3)

        if progress_callback and i % 100 == 0:
            progress_callback(i + 1, total)

    if progress_callback:
        progress_callback(total, total)

    # Metadata
    metadata = {
        "filename": os.path.basename(filepath),
        "filepath": os.path.abspath(filepath),
        "total_packets": total,
        "parsed_packets": len(packets),
        "ja3_extracted": len(ja3_fingerprints),
        "filesize_bytes": os.path.getsize(filepath),
    }

    if packets:
        timestamps = [p["timestamp"] for p in packets if p.get("timestamp")]
        if timestamps:
            metadata["start_time"] = min(timestamps)
            metadata["end_time"] = max(timestamps)
            metadata["duration_seconds"] = max(timestamps) - min(timestamps)

    return {"packets": packets, "ja3_fingerprints": ja3_fingerprints, "metadata": metadata}


def validate_pcap(filepath: str) -> dict:
    """Validate that a file is a valid PCAP."""
    result = {"valid": False, "error": None, "format": None}

    if not os.path.exists(filepath):
        result["error"] = "File not found"
        return result

    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)

        if magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
            result["valid"] = True
            result["format"] = "pcap"
        elif magic in (b'\x0a\x0d\x0d\x0a',):
            result["valid"] = True
            result["format"] = "pcapng"
        else:
            # Try loading with Scapy as fallback
            try:
                from scapy.all import rdpcap
                pkts = rdpcap(filepath, count=1)
                result["valid"] = True
                result["format"] = "pcap (scapy-detected)"
            except Exception:
                result["error"] = "Not a valid PCAP file"
    except Exception as e:
        result["error"] = str(e)

    return result
