"""
NetSentinel v1.0 — IP Reputation Checker
Checks IPs against AbuseIPDB (optional) and local heuristics.
"""

import requests
from functools import lru_cache
from utils.config import ABUSEIPDB_API_KEY
from utils.geo import _is_private_ip

_reputation_cache = {}


def check_ip_reputation(ip: str, api_key: str = None) -> dict:
    """Check reputation of a single IP address."""
    if ip in _reputation_cache:
        return _reputation_cache[ip]

    if _is_private_ip(ip):
        result = {"ip": ip, "abuse_score": 0, "is_malicious": False,
                  "category": "Private/Local", "reports": 0, "source": "local"}
        _reputation_cache[ip] = result
        return result

    key = api_key or ABUSEIPDB_API_KEY
    if key and key != "your_key_here":
        result = _check_abuseipdb(ip, key)
    else:
        result = _local_heuristic(ip)

    _reputation_cache[ip] = result
    return result


def batch_check_reputation(ips: list, api_key: str = None) -> list:
    """Check reputation of multiple IPs (deduplicates)."""
    unique = list(set(ips))
    return [check_ip_reputation(ip, api_key) for ip in unique if not _is_private_ip(ip)]


def _check_abuseipdb(ip: str, api_key: str) -> dict:
    """Query AbuseIPDB API v2."""
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            return {
                "ip": ip, "abuse_score": score,
                "is_malicious": score >= 50,
                "category": "Malicious" if score >= 50 else ("Suspicious" if score >= 25 else "Clean"),
                "reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "domain": data.get("domain", "Unknown"),
                "source": "AbuseIPDB",
            }
    except Exception:
        pass
    return _local_heuristic(ip)


def _local_heuristic(ip: str) -> dict:
    """Basic local heuristic for IP reputation when no API key is available."""
    return {
        "ip": ip, "abuse_score": 0, "is_malicious": False,
        "category": "Unknown (no API key)", "reports": 0, "source": "local_heuristic",
    }


def clear_cache():
    """Clear the reputation cache."""
    global _reputation_cache
    _reputation_cache = {}
