"""
NetSentinel v1.0 — Main Application
Encrypted Network Traffic Anomaly Detector & Forensic Analyzer

Run with: streamlit run app.py
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import streamlit as st

# ── Page Configuration ────────────────────────────────────────────────────────
st.set_page_config(
    page_title="NetSentinel — Network Forensic Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    /* Dark theme overrides */
    .stApp {
        background: linear-gradient(180deg, #0a0a1a 0%, #0d0d2b 50%, #0a0a1a 100%);
    }
    
    /* Header styling */
    header[data-testid="stHeader"] {
        background: rgba(10, 10, 26, 0.8);
        backdrop-filter: blur(10px);
    }
    
    /* Sidebar */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d0d2b 0%, #1a1a3e 100%);
        border-right: 1px solid #333366;
    }
    
    /* Cards and containers */
    .stMetric {
        background: rgba(102, 126, 234, 0.08);
        border: 1px solid rgba(102, 126, 234, 0.2);
        border-radius: 12px;
        padding: 16px;
    }
    
    /* Dataframe styling */
    .stDataFrame {
        border-radius: 8px;
        overflow: hidden;
    }
    
    /* Buttons */
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #667eea, #764ba2);
        border: none;
        font-weight: 600;
    }
    .stButton > button[kind="primary"]:hover {
        background: linear-gradient(135deg, #764ba2, #667eea);
    }
    
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background: rgba(255,255,255,0.02);
        border-radius: 12px;
        padding: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        font-weight: 600;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #667eea22, #764ba222);
    }
    
    /* Progress bar */
    .stProgress > div > div {
        background: linear-gradient(135deg, #667eea, #764ba2);
    }
    
    /* Expander */
    .streamlit-expanderHeader {
        font-weight: 600;
        color: #e0e0e0;
    }
    
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Smooth scrolling */
    html { scroll-behavior: smooth; }
    
    /* Animations */
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    .main .block-container {
        animation: fadeIn 0.5s ease-out;
    }
</style>
""", unsafe_allow_html=True)

# ── Import UI modules ─────────────────────────────────────────────────────────
from ui.components import render_app_header
from ui.sidebar import render_sidebar
from ui.live_view import render_live_view
from ui.forensic_view import render_forensic_view
from ui.report_view import render_report_view

# ── Render App ────────────────────────────────────────────────────────────────

# Header
render_app_header()

# Sidebar (returns config dict)
config = render_sidebar()

# Main content area with tabs
if config["mode"] == "live":
    tab1, tab2 = st.tabs(["📡 Live Dashboard", "📄 Report"])
    with tab1:
        render_live_view(config)
    with tab2:
        render_report_view(config)
else:
    tab1, tab2 = st.tabs(["🔍 Forensic Analysis", "📄 Report"])
    with tab1:
        render_forensic_view(config)
    with tab2:
        render_report_view(config)
