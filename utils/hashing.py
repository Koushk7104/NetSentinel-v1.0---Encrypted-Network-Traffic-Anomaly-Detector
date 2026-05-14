"""
NetSentinel v1.0 — Chain-of-Custody Hashing
SHA-256 hashing for evidence integrity and report signing.
"""

import hashlib
import os
from datetime import datetime, timezone


def compute_file_hash(filepath: str) -> dict:
    """
    Compute SHA-256 hash of a file for chain-of-custody.
    
    Returns:
        dict with 'hash', 'algorithm', 'filename', 'filesize', 'timestamp'
    """
    sha256 = hashlib.sha256()
    filesize = 0

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
            filesize += len(chunk)

    return {
        "hash": sha256.hexdigest(),
        "algorithm": "SHA-256",
        "filename": os.path.basename(filepath),
        "filepath": os.path.abspath(filepath),
        "filesize_bytes": filesize,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def compute_data_hash(data: bytes) -> dict:
    """
    Compute SHA-256 hash of raw bytes (e.g., in-memory PDF).
    
    Returns:
        dict with 'hash', 'algorithm', 'size', 'timestamp'
    """
    sha256 = hashlib.sha256(data)
    return {
        "hash": sha256.hexdigest(),
        "algorithm": "SHA-256",
        "size_bytes": len(data),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def build_chain_of_custody(pcap_path: str = None, pcap_bytes: bytes = None,
                           report_bytes: bytes = None) -> dict:
    """
    Build a complete chain-of-custody record for a forensic analysis run.
    
    Args:
        pcap_path: Path to the analyzed PCAP file
        pcap_bytes: Raw bytes of the PCAP (if loaded in memory)
        report_bytes: Raw bytes of the generated PDF report
    
    Returns:
        dict containing all custody hashes and metadata
    """
    custody = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "NetSentinel v1.0",
        "evidence": {},
        "report": {},
    }

    # Hash the evidence (PCAP)
    if pcap_path and os.path.exists(pcap_path):
        custody["evidence"] = compute_file_hash(pcap_path)
    elif pcap_bytes:
        custody["evidence"] = compute_data_hash(pcap_bytes)

    # Hash the report (PDF)
    if report_bytes:
        custody["report"] = compute_data_hash(report_bytes)

    return custody
