"""
NetSentinel v1.0 — Sidebar
Mode selector, settings, capture controls, and file uploader.
"""

import streamlit as st
from utils.config import DEFAULT_CONTAMINATION
from core.sniffer import get_interfaces_for_display


def render_sidebar():
    """Render the sidebar and return the current configuration."""
    with st.sidebar:
        st.markdown("""
        <div style="text-align:center;padding:10px 0;">
            <span style="font-size:32px;">🛡️</span>
            <h2 style="background:linear-gradient(135deg,#667eea,#764ba2);
                        -webkit-background-clip:text;-webkit-text-fill-color:transparent;
                        margin:0;font-size:22px;">NetSentinel v1.0</h2>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("---")

        # Mode selector
        mode = st.radio(
            "🎯 Analysis Mode",
            ["🔴 Live Capture", "📁 Forensic (PCAP)"],
            index=1,
            help="Live Capture requires admin privileges and Npcap."
        )

        st.markdown("---")

        config = {"mode": "live" if "Live" in mode else "forensic"}

        if config["mode"] == "live":
            _render_live_controls(config)
        else:
            _render_forensic_controls(config)

        st.markdown("---")

        # Analysis settings
        with st.expander("⚙️ Analysis Settings", expanded=False):
            config["contamination"] = st.slider(
                "Anomaly Sensitivity",
                min_value=0.01, max_value=0.20,
                value=DEFAULT_CONTAMINATION, step=0.01,
                help="Expected % of anomalous traffic (lower = stricter)"
            )
            config["max_packets"] = st.number_input(
                "Max Packets", min_value=100, max_value=100000,
                value=10000, step=1000
            )

        # API Keys
        with st.expander("🔑 API Keys (Optional)", expanded=False):
            config["abuseipdb_key"] = st.text_input(
                "AbuseIPDB API Key",
                type="password",
                help="Free tier: 1000 checks/day at abuseipdb.com"
            )

        # Report settings
        with st.expander("📄 Report Settings", expanded=False):
            config["case_id"] = st.text_input("Case ID", value=f"NS-2026-001")
            config["analyst_name"] = st.text_input("Analyst Name", value="Security Analyst")
            config["classification"] = st.selectbox(
                "Classification",
                ["CONFIDENTIAL", "INTERNAL", "PUBLIC", "RESTRICTED"]
            )
            config["analyst_notes"] = st.text_area(
                "Analyst Notes",
                placeholder="Add investigation notes here...",
                height=100
            )

        return config


def _render_live_controls(config):
    """Render live capture specific controls."""
    st.markdown("### 📡 Live Capture Settings")

    # Interface selection
    try:
        interfaces = get_interfaces_for_display()
        iface_names = [desc for _, desc in interfaces]
        iface_ids = [id for id, _ in interfaces]
        selected = st.selectbox("Network Interface", iface_names)
        idx = iface_names.index(selected) if selected in iface_names else 0
        config["interface"] = iface_ids[idx] if idx < len(iface_ids) else "default"
    except Exception as e:
        config["interface"] = "default"
        st.info(f"Using default interface. ({e})")

    # Capture controls
    col1, col2 = st.columns(2)
    with col1:
        config["start_capture"] = st.button("▶ Start", use_container_width=True, type="primary")
    with col2:
        config["stop_capture"] = st.button("⏹ Stop", use_container_width=True)

    config["reset_capture"] = st.button("🔄 Reset", use_container_width=True)


def _render_forensic_controls(config):
    """Render forensic PCAP analysis controls."""
    st.markdown("### 📂 PCAP File Upload")

    uploaded = st.file_uploader(
        "Upload .pcap file",
        type=["pcap", "pcapng", "cap"],
        help="Supports PCAP and PCAPNG formats"
    )
    config["uploaded_file"] = uploaded

    if uploaded:
        st.success(f"📎 {uploaded.name} ({uploaded.size / 1024:.1f} KB)")
        config["analyze_pcap"] = st.button(
            "🔍 Analyze PCAP",
            use_container_width=True,
            type="primary"
        )
    else:
        config["analyze_pcap"] = False
