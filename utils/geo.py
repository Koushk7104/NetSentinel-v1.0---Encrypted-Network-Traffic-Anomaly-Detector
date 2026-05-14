"""
NetSentinel v1.0 — GeoIP Lookups & Map Generation
Uses ipinfo.io free tier for IP geolocation and Plotly for mapping.
"""

import requests
import plotly.graph_objects as go
from functools import lru_cache


# ── GeoIP Cache ───────────────────────────────────────────────────────────────
_geo_cache = {}


def lookup_ip_geo(ip: str) -> dict:
    """
    Look up geographic information for an IP address.
    Uses ipinfo.io free tier (no key needed for basic lookups, ~50k/month).
    
    Returns:
        dict with 'ip', 'city', 'region', 'country', 'loc' (lat,lng), 'org'
    """
    # Skip private/reserved IPs
    if _is_private_ip(ip):
        return {
            "ip": ip,
            "city": "Private",
            "region": "Local Network",
            "country": "N/A",
            "loc": "0,0",
            "org": "Private Network",
            "is_private": True,
        }

    # Check cache
    if ip in _geo_cache:
        return _geo_cache[ip]

    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            result = {
                "ip": ip,
                "city": data.get("city", "Unknown"),
                "region": data.get("region", "Unknown"),
                "country": data.get("country", "Unknown"),
                "loc": data.get("loc", "0,0"),
                "org": data.get("org", "Unknown"),
                "is_private": False,
            }
            _geo_cache[ip] = result
            return result
    except Exception:
        pass

    # Fallback
    result = {
        "ip": ip,
        "city": "Unknown",
        "region": "Unknown",
        "country": "Unknown",
        "loc": "0,0",
        "org": "Unknown",
        "is_private": False,
    }
    _geo_cache[ip] = result
    return result


def batch_lookup_geo(ips: list) -> list:
    """Look up geo info for a batch of IPs. Deduplicates automatically."""
    unique_ips = list(set(ips))
    return [lookup_ip_geo(ip) for ip in unique_ips]


def create_geo_map(geo_data: list, title: str = "Network Communication Endpoints") -> go.Figure:
    """
    Create a Plotly scatter_geo map from GeoIP results.
    
    Args:
        geo_data: List of dicts from lookup_ip_geo()
        title: Map title
    
    Returns:
        Plotly Figure object
    """
    # Filter out private/unknown IPs
    valid = [g for g in geo_data if not g.get("is_private") and g["loc"] != "0,0"]

    if not valid:
        # Return empty map with message
        fig = go.Figure(go.Scattergeo())
        fig.update_layout(
            title=title,
            geo=dict(
                showframe=False,
                showcoastlines=True,
                projection_type="natural earth",
                bgcolor="rgba(0,0,0,0)",
                landcolor="#1a1a2e",
                oceancolor="#0a0a1a",
                coastlinecolor="#333366",
            ),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e0e0e0"),
            margin=dict(l=0, r=0, t=40, b=0),
        )
        return fig

    lats = []
    lons = []
    texts = []
    for g in valid:
        try:
            lat, lon = g["loc"].split(",")
            lats.append(float(lat))
            lons.append(float(lon))
            texts.append(f"{g['ip']}<br>{g['city']}, {g['country']}<br>{g['org']}")
        except (ValueError, AttributeError):
            continue

    fig = go.Figure(
        go.Scattergeo(
            lat=lats,
            lon=lons,
            text=texts,
            hoverinfo="text",
            marker=dict(
                size=10,
                color="#ff4757",
                line=dict(width=1, color="#ff6b81"),
                opacity=0.85,
                symbol="circle",
            ),
            mode="markers",
        )
    )

    fig.update_layout(
        title=dict(text=title, font=dict(size=16, color="#e0e0e0")),
        geo=dict(
            showframe=False,
            showcoastlines=True,
            projection_type="natural earth",
            bgcolor="rgba(0,0,0,0)",
            landcolor="#1a1a2e",
            oceancolor="#0a0a1a",
            coastlinecolor="#333366",
            countrycolor="#333366",
            showland=True,
            showocean=True,
            showcountries=True,
        ),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e0e0e0"),
        margin=dict(l=0, r=0, t=40, b=0),
        height=450,
    )

    return fig


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/reserved (RFC 1918 + loopback + link-local)."""
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return True  # Treat non-IPv4 as private for simplicity
        
        first = int(parts[0])
        second = int(parts[1])

        # 10.0.0.0/8
        if first == 10:
            return True
        # 172.16.0.0/12
        if first == 172 and 16 <= second <= 31:
            return True
        # 192.168.0.0/16
        if first == 192 and second == 168:
            return True
        # 127.0.0.0/8 (loopback)
        if first == 127:
            return True
        # 169.254.0.0/16 (link-local)
        if first == 169 and second == 254:
            return True
        # 0.0.0.0
        if ip == "0.0.0.0":
            return True
        
        return False
    except (ValueError, IndexError):
        return True
