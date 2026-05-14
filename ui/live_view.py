"""
NetSentinel v1.0 — Live Capture View
Real-time dashboard for live packet capture with auto-refreshing metrics and charts.
"""

import time
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from ui.components import metric_card, section_header, status_dot, info_box, anomaly_badge
from core.sniffer import PacketCapture, check_capture_prerequisites
from core.flow_aggregator import aggregate_packets_to_flows
from core.anomaly_detector import AnomalyDetector
from core.statistical_profiler import StatisticalProfiler


def render_live_view(config: dict):
    """Render the live capture dashboard."""

    # Check prerequisites — show warnings but don't block
    prereqs = check_capture_prerequisites()
    if prereqs.get("errors"):
        for err in prereqs["errors"]:
            info_box(err, "error")
        return
    if prereqs.get("warnings"):
        for warn in prereqs["warnings"]:
            st.warning(warn)

    # Initialize capture in session state
    if "capture" not in st.session_state:
        st.session_state.capture = PacketCapture(
            interface=config.get("interface"),
            max_packets=config.get("max_packets", 10000),
        )
        st.session_state.capture_detector = AnomalyDetector(
            contamination=config.get("contamination")
        )
        st.session_state.capture_profiler = StatisticalProfiler()

    capture = st.session_state.capture

    # Handle controls
    if config.get("start_capture"):
        iface = config.get("interface")
        capture.interface = iface
        capture.start()
        # Small delay to let thread start
        time.sleep(0.5)
        # Check if it immediately failed
        err = capture.get_error()
        if err:
            st.error(f"❌ Capture failed to start: {err}")
        else:
            st.rerun()

    if config.get("stop_capture"):
        capture.stop()
        st.rerun()

    if config.get("reset_capture"):
        capture.stop()
        capture.clear()
        st.session_state.pop("capture", None)
        st.rerun()

    # Show errors from capture thread
    err = capture.get_error()
    if err:
        st.error(f"❌ Capture error: {err}")
        info_box("Try: 1) Run as Administrator  2) Check Npcap is installed  3) Select a different interface", "warning")

    # Status
    status_dot(capture.is_running(), f"Capturing on {config.get('interface', 'default')}")

    # Metrics row
    packets = capture.get_packets()
    elapsed = capture.get_elapsed_time()

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        metric_card("Packets Captured", f"{len(packets):,}", icon="📦", color="#667eea")
    with col2:
        rate = len(packets) / max(elapsed, 1)
        metric_card("Packets/sec", f"{rate:.1f}", icon="⚡", color="#764ba2")
    with col3:
        metric_card("Elapsed Time", f"{elapsed:.0f}s", icon="⏱️", color="#00b4d8")
    with col4:
        anomaly_count = st.session_state.get("live_anomaly_count", 0)
        metric_card("Anomalies", str(anomaly_count), icon="🚨", color="#e74c3c")

    if not packets:
        if not capture.is_running() and not err:
            info_box("Press ▶ Start in the sidebar to begin live capture.", "info")
        elif capture.is_running():
            info_box("Capturing... waiting for packets. Browse the web to generate traffic!", "info")
            time.sleep(2)
            st.rerun()
        return

    # Aggregate into flows
    flow_df = aggregate_packets_to_flows(packets)

    if flow_df.empty:
        info_box("Processing packets...", "info")
        if capture.is_running():
            time.sleep(2)
            st.rerun()
        return

    # Run detection
    detector = st.session_state.capture_detector
    predicted = detector.predict(flow_df)
    anomalies = predicted[predicted["anomaly_label"] == -1]
    st.session_state.live_anomaly_count = len(anomalies)

    # Store results for report generation
    st.session_state.analysis_results = {
        "flow_df": predicted,
        "anomalies_df": anomalies,
        "ja3_results": [],
        "ip_reputations": [],
        "geo_data": [],
        "geo_fig": None,
        "timeline_fig": None,
        "protocol_fig": None,
        "protocol_stats": [],
        "evidence_hash": {},
        "metadata": {"total_packets": len(packets)},
        "model_params": detector.get_model_params(),
        "baseline_summary": st.session_state.capture_profiler.get_baseline_summary(),
        "total_packets": len(packets),
        "total_flows": len(predicted),
        "total_anomalies": len(anomalies),
        "ja3_matches_count": 0,
        "analysis_duration": f"{elapsed:.1f}s (live)",
        "source_file": "Live Capture",
    }

    # Charts
    col_left, col_right = st.columns(2)

    with col_left:
        section_header("Protocol Distribution", "📊")
        proto_counts = predicted["protocol"].value_counts()
        fig = px.pie(
            values=proto_counts.values, names=proto_counts.index,
            color_discrete_sequence=px.colors.sequential.Plasma_r,
            hole=0.4,
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e0e0e0"), height=300,
            margin=dict(l=20, r=20, t=30, b=20),
        )
        st.plotly_chart(fig, use_container_width=True)

    with col_right:
        section_header("Top Talkers", "🗣️")
        top_src = predicted.groupby("src_ip")["byte_count"].sum().nlargest(10)
        if not top_src.empty:
            fig2 = px.bar(
                x=top_src.values, y=top_src.index, orientation="h",
                color=top_src.values, color_continuous_scale="Plasma",
            )
            fig2.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e0e0e0"), height=300, showlegend=False,
                xaxis_title="Total Bytes", yaxis_title="",
                margin=dict(l=20, r=20, t=30, b=20),
            )
            st.plotly_chart(fig2, use_container_width=True)

    # Live flow table
    section_header("Live Network Flows", "📋")
    display_cols = ["src_ip", "dst_ip", "dst_port", "protocol",
                    "packet_count", "byte_count", "anomaly_score_normalized"]
    avail_cols = [c for c in display_cols if c in predicted.columns]
    st.dataframe(
        predicted[avail_cols].sort_values("anomaly_score_normalized", ascending=False).head(30),
        use_container_width=True,
        hide_index=True,
    )

    # Anomaly feed
    if not anomalies.empty:
        section_header("🚨 Anomaly Feed", "")
        avail_cols2 = [c for c in display_cols if c in anomalies.columns]
        st.dataframe(
            anomalies[avail_cols2].head(20),
            use_container_width=True,
            hide_index=True,
        )

    # Auto-refresh
    if capture.is_running():
        time.sleep(2)
        st.rerun()
