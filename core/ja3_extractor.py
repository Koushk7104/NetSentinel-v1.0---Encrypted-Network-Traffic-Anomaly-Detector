"""
NetSentinel v1.0 — JA3 TLS Fingerprint Extractor
Extracts JA3 fingerprints from TLS ClientHello messages and cross-references
against known malware signatures. No payload decryption needed.
"""

import hashlib
import json
import os
import struct


# ── Load known malicious JA3 hashes ──────────────────────────────────────────
_MALWARE_DB = {}
_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "ja3_malware_hashes.json")

def _load_malware_db():
    """Load the JA3 malware hash database from disk."""
    global _MALWARE_DB
    if _MALWARE_DB:
        return
    try:
        with open(_DB_PATH, "r") as f:
            entries = json.load(f)
            _MALWARE_DB = {entry["hash"]: entry for entry in entries}
    except (FileNotFoundError, json.JSONDecodeError):
        _MALWARE_DB = {}


def extract_ja3_from_packet(packet_bytes: bytes) -> dict | None:
    """
    Extract JA3 fingerprint from a raw packet containing a TLS ClientHello.
    
    The JA3 hash is computed from:
        TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    
    Args:
        packet_bytes: Raw packet bytes (starting from IP header or raw TLS)
    
    Returns:
        dict with 'ja3_string', 'ja3_hash', 'tls_version', 'ciphers', etc.
        or None if not a TLS ClientHello.
    """
    try:
        # Try to find TLS record in the packet
        tls_data = _find_tls_record(packet_bytes)
        if tls_data is None:
            return None

        return _parse_client_hello(tls_data)
    except Exception:
        return None


def extract_ja3_from_scapy_packet(pkt) -> dict | None:
    """
    Extract JA3 from a Scapy packet object.
    Handles the Scapy-specific layer traversal.
    """
    try:
        # Get raw bytes from TCP payload
        if pkt.haslayer("TCP"):
            tcp = pkt["TCP"]
            payload = bytes(tcp.payload)
            if len(payload) < 6:
                return None
            
            # Check if this looks like a TLS record
            content_type = payload[0]
            if content_type != 22:  # Handshake
                return None
            
            return _parse_client_hello(payload)
        return None
    except Exception:
        return None


def check_ja3_reputation(ja3_hash: str) -> dict:
    """
    Check a JA3 hash against the known malware database.
    
    Returns:
        dict with 'is_malicious', 'malware', 'description', 'source'
    """
    _load_malware_db()
    
    if ja3_hash in _MALWARE_DB:
        entry = _MALWARE_DB[ja3_hash]
        return {
            "is_malicious": True,
            "ja3_hash": ja3_hash,
            "malware": entry.get("malware", "Unknown"),
            "description": entry.get("description", ""),
            "source": entry.get("source", "unknown"),
        }
    
    return {
        "is_malicious": False,
        "ja3_hash": ja3_hash,
        "malware": None,
        "description": "No known malware association",
        "source": "local_db",
    }


def batch_check_ja3(ja3_hashes: list) -> list:
    """Check multiple JA3 hashes against the malware DB."""
    _load_malware_db()
    return [check_ja3_reputation(h) for h in ja3_hashes if h]


def get_malware_db_stats() -> dict:
    """Return statistics about the loaded malware JA3 database."""
    _load_malware_db()
    families = set(entry.get("malware", "Unknown") for entry in _MALWARE_DB.values())
    return {
        "total_hashes": len(_MALWARE_DB),
        "malware_families": len(families),
        "families": sorted(families),
    }


# ── Internal TLS Parsing ─────────────────────────────────────────────────────

def _find_tls_record(data: bytes) -> bytes | None:
    """Find a TLS record within raw packet bytes."""
    # Skip Ethernet + IP + TCP headers to find TLS payload
    # Try common offsets
    for offset in [0, 14, 34, 54, 66]:
        if offset >= len(data):
            continue
        remaining = data[offset:]
        if len(remaining) > 5:
            content_type = remaining[0]
            if content_type == 22:  # TLS Handshake
                return remaining
    return None


def _parse_client_hello(tls_data: bytes) -> dict | None:
    """
    Parse a TLS ClientHello and extract JA3 components.
    
    TLS Record:
        [ContentType(1)][Version(2)][Length(2)][HandshakeType(1)][Length(3)][ClientVersion(2)]...
    """
    if len(tls_data) < 6:
        return None

    # TLS Record Header
    content_type = tls_data[0]
    if content_type != 22:  # Not a Handshake
        return None

    record_version = struct.unpack("!H", tls_data[1:3])[0]
    record_length = struct.unpack("!H", tls_data[3:5])[0]

    # Handshake header
    if len(tls_data) < 10:
        return None

    handshake_type = tls_data[5]
    if handshake_type != 1:  # Not ClientHello
        return None

    # Handshake length (3 bytes)
    hs_length = struct.unpack("!I", b'\x00' + tls_data[6:9])[0]

    # Client version
    if len(tls_data) < 11:
        return None
    client_version = struct.unpack("!H", tls_data[9:11])[0]

    # Skip random (32 bytes)
    pos = 11 + 32  # Position after random

    if pos >= len(tls_data):
        return None

    # Session ID
    session_id_len = tls_data[pos]
    pos += 1 + session_id_len

    if pos + 2 > len(tls_data):
        return None

    # Cipher Suites
    cipher_suites_len = struct.unpack("!H", tls_data[pos:pos+2])[0]
    pos += 2

    if pos + cipher_suites_len > len(tls_data):
        return None

    cipher_suites = []
    for i in range(0, cipher_suites_len, 2):
        if pos + i + 2 <= len(tls_data):
            cs = struct.unpack("!H", tls_data[pos+i:pos+i+2])[0]
            # Skip GREASE values (0x?a?a pattern)
            if (cs & 0x0f0f) != 0x0a0a:
                cipher_suites.append(cs)
    pos += cipher_suites_len

    if pos >= len(tls_data):
        return None

    # Compression Methods
    comp_len = tls_data[pos]
    pos += 1 + comp_len

    # Extensions
    extensions = []
    elliptic_curves = []
    ec_point_formats = []

    if pos + 2 <= len(tls_data):
        extensions_len = struct.unpack("!H", tls_data[pos:pos+2])[0]
        pos += 2

        ext_end = pos + extensions_len
        while pos + 4 <= ext_end and pos + 4 <= len(tls_data):
            ext_type = struct.unpack("!H", tls_data[pos:pos+2])[0]
            ext_len = struct.unpack("!H", tls_data[pos+2:pos+4])[0]
            pos += 4

            # Skip GREASE
            if (ext_type & 0x0f0f) != 0x0a0a:
                extensions.append(ext_type)

            ext_data = tls_data[pos:pos+ext_len]

            # Supported Groups (Elliptic Curves) — ext_type 0x000a
            if ext_type == 0x000a and len(ext_data) >= 2:
                curves_len = struct.unpack("!H", ext_data[0:2])[0]
                for i in range(2, min(2 + curves_len, len(ext_data)), 2):
                    if i + 2 <= len(ext_data):
                        curve = struct.unpack("!H", ext_data[i:i+2])[0]
                        if (curve & 0x0f0f) != 0x0a0a:
                            elliptic_curves.append(curve)

            # EC Point Formats — ext_type 0x000b
            if ext_type == 0x000b and len(ext_data) >= 1:
                formats_len = ext_data[0]
                for i in range(1, min(1 + formats_len, len(ext_data))):
                    ec_point_formats.append(ext_data[i])

            pos += ext_len

    # Build JA3 string
    ja3_string = ",".join([
        str(client_version),
        "-".join(str(c) for c in cipher_suites),
        "-".join(str(e) for e in extensions),
        "-".join(str(c) for c in elliptic_curves),
        "-".join(str(f) for f in ec_point_formats),
    ])

    ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

    return {
        "ja3_string": ja3_string,
        "ja3_hash": ja3_hash,
        "tls_version": _tls_version_name(client_version),
        "tls_version_raw": client_version,
        "cipher_count": len(cipher_suites),
        "extension_count": len(extensions),
        "ciphers": cipher_suites,
        "extensions": extensions,
        "elliptic_curves": elliptic_curves,
        "ec_point_formats": ec_point_formats,
    }


def _tls_version_name(version: int) -> str:
    """Convert TLS version number to human-readable name."""
    versions = {
        0x0300: "SSL 3.0",
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3",
    }
    return versions.get(version, f"Unknown (0x{version:04x})")
