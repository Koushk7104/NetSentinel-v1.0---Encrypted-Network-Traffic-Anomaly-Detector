"""
NetSentinel v1.0 — Configuration & Environment
Loads settings from .env and provides app-wide defaults.
"""

import os
from dotenv import load_dotenv

# Load .env file if present
load_dotenv()


# ── API Keys ─────────────────────────────────────────────────────────────────
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# ── Application Defaults ─────────────────────────────────────────────────────
APP_NAME = "NetSentinel"
APP_VERSION = "1.0"
APP_TAGLINE = "Encrypted Network Traffic Anomaly Detector & Forensic Analyzer"

# ── Isolation Forest Defaults ─────────────────────────────────────────────────
DEFAULT_CONTAMINATION = 0.05       # 5% expected anomaly rate
DEFAULT_N_ESTIMATORS = 100         # Trees in the forest
DEFAULT_RANDOM_STATE = 42

# ── Statistical Profiler Defaults ─────────────────────────────────────────────
DEVIATION_THRESHOLD = 3.0          # Standard deviations for flagging
RISK_WEIGHT_IF = 0.4               # Isolation Forest weight in composite score
RISK_WEIGHT_JA3 = 0.3              # JA3 match weight
RISK_WEIGHT_STAT = 0.3             # Statistical deviation weight

# ── Live Capture Defaults ─────────────────────────────────────────────────────
MAX_PACKETS_BUFFER = 10000         # Max packets held in memory
CAPTURE_REFRESH_INTERVAL = 2       # Dashboard refresh (seconds)
DEFAULT_CAPTURE_TIMEOUT = 300      # 5-minute default capture window

# ── Network Interface Detection ───────────────────────────────────────────────
def get_available_interfaces():
    """
    Detect available network interfaces using Scapy.
    Returns a list of (name, description) tuples.
    """
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
        result = []
        for iface in ifaces:
            name = iface.get("name", "Unknown")
            desc = iface.get("description", name)
            guid = iface.get("guid", "")
            if guid:
                result.append((guid, f"{desc}"))
        return result if result else [("default", "Default Interface")]
    except ImportError:
        try:
            from scapy.all import get_if_list
            ifaces = get_if_list()
            return [(iface, iface) for iface in ifaces]
        except Exception:
            return [("default", "Default Interface")]
    except Exception:
        return [("default", "Default Interface")]


# ── Path Helpers ──────────────────────────────────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
REPORT_DIR = os.path.join(PROJECT_ROOT, "report")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "output")

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)
