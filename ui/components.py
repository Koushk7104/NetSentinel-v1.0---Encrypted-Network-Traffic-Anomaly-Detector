"""
NetSentinel v1.0 — Shared UI Components
Reusable styled widgets for the Streamlit dashboard.
"""

import streamlit as st


def metric_card(label: str, value, delta=None, icon="📊", color="#667eea"):
    """Render a styled metric card."""
    delta_html = ""
    if delta is not None:
        d_color = "#27ae60" if delta >= 0 else "#e74c3c"
        d_arrow = "▲" if delta >= 0 else "▼"
        delta_html = f'<div style="font-size:12px;color:{d_color};">{d_arrow} {abs(delta)}</div>'

    st.markdown(f"""
    <div style="background:linear-gradient(135deg,{color}22,{color}11);
                border:1px solid {color}44;border-radius:12px;padding:16px;text-align:center;">
        <div style="font-size:24px;margin-bottom:4px;">{icon}</div>
        <div style="font-size:28px;font-weight:700;color:{color};">{value}</div>
        <div style="font-size:12px;color:#888;margin-top:4px;">{label}</div>
        {delta_html}
    </div>
    """, unsafe_allow_html=True)


def anomaly_badge(score: float) -> str:
    """Return HTML badge for anomaly severity."""
    if score >= 70:
        return f'<span style="background:#e74c3c22;color:#e74c3c;padding:2px 10px;border-radius:12px;font-weight:600;font-size:12px;">🔴 Critical ({score:.0f})</span>'
    elif score >= 40:
        return f'<span style="background:#f39c1222;color:#f39c12;padding:2px 10px;border-radius:12px;font-weight:600;font-size:12px;">🟡 Warning ({score:.0f})</span>'
    else:
        return f'<span style="background:#27ae6022;color:#27ae60;padding:2px 10px;border-radius:12px;font-weight:600;font-size:12px;">🟢 Low ({score:.0f})</span>'


def section_header(title: str, icon: str = ""):
    """Render a styled section header."""
    st.markdown(f"""
    <div style="border-bottom:2px solid #667eea;padding-bottom:8px;margin:24px 0 16px 0;">
        <span style="font-size:20px;font-weight:700;color:#e0e0e0;">{icon} {title}</span>
    </div>
    """, unsafe_allow_html=True)


def status_dot(is_active: bool, label: str = ""):
    """Render a live/stopped status indicator."""
    color = "#27ae60" if is_active else "#e74c3c"
    pulse = "animation:pulse 1.5s infinite;" if is_active else ""
    status = "LIVE" if is_active else "STOPPED"
    st.markdown(f"""
    <style>@keyframes pulse{{0%,100%{{opacity:1;}}50%{{opacity:0.4;}}}}</style>
    <div style="display:flex;align-items:center;gap:8px;">
        <div style="width:10px;height:10px;border-radius:50%;background:{color};{pulse}"></div>
        <span style="font-size:13px;color:{color};font-weight:600;">{status}</span>
        <span style="font-size:12px;color:#888;">{label}</span>
    </div>
    """, unsafe_allow_html=True)


def info_box(message: str, box_type: str = "info"):
    """Render a styled info/warning/error box."""
    colors = {
        "info": ("#667eea", "#667eea22"),
        "warning": ("#f39c12", "#f39c1222"),
        "error": ("#e74c3c", "#e74c3c22"),
        "success": ("#27ae60", "#27ae6022"),
    }
    border, bg = colors.get(box_type, colors["info"])
    icons = {"info": "ℹ️", "warning": "⚠️", "error": "❌", "success": "✅"}
    icon = icons.get(box_type, "ℹ️")
    st.markdown(f"""
    <div style="background:{bg};border-left:4px solid {border};padding:12px 16px;
                border-radius:0 8px 8px 0;margin:8px 0;">
        {icon} {message}
    </div>
    """, unsafe_allow_html=True)


def render_app_header():
    """Render the main app header."""
    st.markdown("""
    <div style="text-align:center;padding:20px 0 10px 0;">
        <div style="font-size:48px;margin-bottom:4px;">🛡️</div>
        <h1 style="background:linear-gradient(135deg,#667eea,#764ba2);
                    -webkit-background-clip:text;-webkit-text-fill-color:transparent;
                    font-size:36px;margin:0;font-weight:800;">NetSentinel</h1>
        <p style="color:#888;font-size:14px;margin-top:4px;">
            Encrypted Network Traffic Anomaly Detector & Forensic Analyzer
        </p>
        <p style="color:#555;font-size:11px;font-style:italic;margin-top:2px;">
            "Detect malicious behavior without decrypting a single packet"
        </p>
    </div>
    """, unsafe_allow_html=True)
