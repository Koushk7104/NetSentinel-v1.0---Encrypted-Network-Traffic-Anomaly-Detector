"""
NetSentinel v1.0 — Forensic (PCAP) Analysis View
Full analysis pipeline with visualizations for uploaded PCAP files.
"""

import time
import tempfile
import os
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

from ui.components import metric_card, section_header, info_box, anomaly_badge
from core.pcap_parser import parse_pcap, validate_pcap
from core.flow_aggregator import aggregate_packets_to_flows
from core.anomaly_detector import AnomalyDetector
from core.ja3_extractor import check_ja3_reputation
from core.statistical_profiler import StatisticalProfiler
from core.ip_reputation import batch_check_reputation
from utils.geo import batch_lookup_geo, create_geo_map
from utils.hashing import compute_file_hash


def render_forensic_view(config: dict):
    """Render the forensic PCAP analysis dashboard."""

    if not config.get("uploaded_file"):
        _render_empty_state()
        return

    # Check if analysis should run
    if config.get("analyze_pcap"):
        _run_analysis(config)

    # Display results if available
    if "analysis_results" in st.session_state:
        _render_results(st.session_state.analysis_results, config)
    else:
        info_box("Upload a PCAP file and click **🔍 Analyze PCAP** to begin.", "info")


def _render_empty_state():
    """Show the empty state when no file is uploaded."""
    st.markdown("""
    <div style="text-align:center;padding:60px 20px;">
        <div style="font-size:64px;margin-bottom:16px;">📁</div>
        <h2 style="color:#667eea;">Upload a PCAP File</h2>
        <p style="color:#888;max-width:500px;margin:0 auto;">
            Use the sidebar to upload a .pcap file for forensic analysis.
            NetSentinel will analyze all packets, detect anomalies, extract
            JA3 fingerprints, and generate a complete threat assessment.
        </p>
    </div>
    """, unsafe_allow_html=True)


def _run_analysis(config: dict):
    """Execute the full analysis pipeline."""
    uploaded = config["uploaded_file"]
    start_time = time.time()

    # Save uploaded file to temp
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    tmp.write(uploaded.read())
    tmp.close()
    tmp_path = tmp.name

    # Reset file position
    uploaded.seek(0)

    progress = st.progress(0, text="🔍 Initializing analysis...")

    try:
        # Step 1: Parse PCAP
        progress.progress(10, text="📦 Parsing PCAP file...")
        def update_progress(current, total):
            pct = 10 + int(30 * current / max(total, 1))
            progress.progress(min(pct, 40), text=f"📦 Parsing packets... ({current}/{total})")

        parsed = parse_pcap(tmp_path, progress_callback=update_progress)
        packets = parsed["packets"]
        ja3_fps = parsed["ja3_fingerprints"]
        meta = parsed["metadata"]

        # Step 2: Aggregate flows
        progress.progress(45, text="🔄 Aggregating network flows...")
        flow_df = aggregate_packets_to_flows(packets)

        if flow_df.empty:
            info_box("No valid network flows found in the PCAP.", "warning")
            progress.empty()
            return

        # Step 3: Isolation Forest
        progress.progress(55, text="🌲 Running Isolation Forest...")
        detector = AnomalyDetector(contamination=config.get("contamination", 0.05))
        flow_df = detector.predict(flow_df)

        # Step 4: JA3 Analysis
        progress.progress(65, text="🔐 Analyzing JA3 fingerprints...")
        ja3_results = []
        ja3_flags = pd.Series(0, index=flow_df.index)
        for fp in ja3_fps:
            rep = check_ja3_reputation(fp["ja3_hash"])
            rep["src_ip"] = fp.get("src_ip", "")
            rep["dst_ip"] = fp.get("dst_ip", "")
            rep["tls_version"] = fp.get("tls_version", "")
            ja3_results.append(rep)
            if rep["is_malicious"]:
                mask = flow_df["src_ip"] == fp.get("src_ip", "")
                ja3_flags[mask] = 1

        # Step 5: Statistical Profiler
        progress.progress(75, text="📈 Building statistical baseline...")
        profiler = StatisticalProfiler()
        flow_df = profiler.compute_deviations(flow_df)

        # Composite risk score
        flow_df["risk_score"] = profiler.compute_risk_score(
            flow_df,
            if_scores=flow_df["anomaly_score_normalized"],
            ja3_flags=ja3_flags,
        )
        flow_df["ja3_malicious"] = ja3_flags

        # Step 6: IP Reputation
        progress.progress(82, text="🌐 Checking IP reputation...")
        all_ips = list(set(flow_df["src_ip"].tolist() + flow_df["dst_ip"].tolist()))
        ip_reps = batch_check_reputation(all_ips, api_key=config.get("abuseipdb_key"))

        # Step 7: GeoIP
        progress.progress(88, text="🗺️ Resolving geographic locations...")
        geo_data = batch_lookup_geo(all_ips[:50])  # Limit to 50 for free tier
        geo_fig = create_geo_map(geo_data)

        # Step 8: Compute evidence hash
        progress.progress(92, text="🔗 Computing chain of custody...")
        evidence_hash = compute_file_hash(tmp_path)

        # Build protocol stats
        proto_stats = []
        if not flow_df.empty:
            proto_counts = flow_df["protocol"].value_counts()
            total = proto_counts.sum()
            for proto, count in proto_counts.items():
                proto_stats.append({
                    "protocol": proto,
                    "count": int(count),
                    "percentage": round(100 * count / total, 1),
                    "bytes": int(flow_df[flow_df["protocol"] == proto]["byte_count"].sum()),
                })

        # Build charts
        anomalies_df = flow_df[flow_df["anomaly_label"] == -1].sort_values("risk_score", ascending=False)

        # Timeline figure
        timeline_fig = None
        if not flow_df.empty and "start_time" in flow_df.columns:
            flow_df["time_dt"] = pd.to_datetime(flow_df["start_time"], unit="s", errors="coerce")
            timeline_fig = px.scatter(
                flow_df, x="time_dt", y="risk_score",
                color="anomaly_label",
                color_discrete_map={-1: "#e74c3c", 1: "#27ae60"},
                size="byte_count", size_max=15,
                labels={"time_dt": "Time", "risk_score": "Risk Score", "anomaly_label": "Status"},
                hover_data=["src_ip", "dst_ip", "protocol"],
            )
            timeline_fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e0e0e0"), height=400,
                xaxis=dict(gridcolor="#333"), yaxis=dict(gridcolor="#333"),
            )

        # Protocol figure
        protocol_fig = None
        if proto_stats:
            protocol_fig = px.pie(
                pd.DataFrame(proto_stats), values="count", names="protocol",
                color_discrete_sequence=px.colors.sequential.Plasma_r, hole=0.4,
            )
            protocol_fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e0e0e0"), height=350,
            )

        elapsed = time.time() - start_time

        # Store results
        st.session_state.analysis_results = {
            "flow_df": flow_df,
            "anomalies_df": anomalies_df,
            "ja3_results": ja3_results,
            "ip_reputations": ip_reps,
            "geo_data": geo_data,
            "geo_fig": geo_fig,
            "timeline_fig": timeline_fig,
            "protocol_fig": protocol_fig,
            "protocol_stats": proto_stats,
            "evidence_hash": evidence_hash,
            "metadata": meta,
            "model_params": detector.get_model_params(),
            "baseline_summary": profiler.get_baseline_summary(),
            "total_packets": meta.get("total_packets", 0),
            "total_flows": len(flow_df),
            "total_anomalies": len(anomalies_df),
            "ja3_matches_count": sum(1 for r in ja3_results if r.get("is_malicious")),
            "analysis_duration": f"{elapsed:.1f} seconds",
            "pcap_path": tmp_path,
            "source_file": uploaded.name,
        }

        progress.progress(100, text="✅ Analysis complete!")
        time.sleep(0.5)
        progress.empty()
        st.rerun()

    except Exception as e:
        progress.empty()
        st.error(f"Analysis failed: {str(e)}")
        import traceback
        st.code(traceback.format_exc())


def _render_results(results: dict, config: dict):
    """Render all analysis results."""
    flow_df = results["flow_df"]
    anomalies_df = results["anomalies_df"]

    # Top metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        metric_card("Packets", f"{results['total_packets']:,}", icon="📦", color="#667eea")
    with col2:
        metric_card("Flows", f"{results['total_flows']:,}", icon="🔄", color="#764ba2")
    with col3:
        metric_card("Anomalies", f"{results['total_anomalies']:,}", icon="🚨", color="#e74c3c")
    with col4:
        metric_card("JA3 Matches", str(results["ja3_matches_count"]), icon="🔐", color="#f39c12")
    with col5:
        metric_card("Duration", results["analysis_duration"], icon="⏱️", color="#00b4d8")

    # Threat Timeline
    section_header("Threat Timeline", "📅")
    if results.get("timeline_fig"):
        st.plotly_chart(results["timeline_fig"], use_container_width=True)

    # Two-column layout
    col_left, col_right = st.columns(2)

    with col_left:
        section_header("Protocol Distribution", "📊")
        if results.get("protocol_fig"):
            st.plotly_chart(results["protocol_fig"], use_container_width=True)

    with col_right:
        section_header("Anomaly Score Distribution", "📉")
        if not flow_df.empty and "risk_score" in flow_df.columns:
            fig = px.histogram(
                flow_df, x="risk_score", nbins=30,
                color_discrete_sequence=["#667eea"],
                labels={"risk_score": "Risk Score", "count": "Flows"},
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e0e0e0"), height=350, showlegend=False,
                xaxis=dict(gridcolor="#333"), yaxis=dict(gridcolor="#333"),
            )
            st.plotly_chart(fig, use_container_width=True)

    # Top Anomalous Flows
    section_header("Top Anomalous Flows", "🚨")
    if not anomalies_df.empty:
        display_cols = ["src_ip", "dst_ip", "dst_port", "protocol",
                        "packet_count", "byte_count", "risk_score", "anomaly_score_normalized"]
        avail_cols = [c for c in display_cols if c in anomalies_df.columns]
        st.dataframe(anomalies_df[avail_cols].head(25), use_container_width=True, hide_index=True)
    else:
        info_box("No anomalies detected. Your traffic looks clean! ✅", "success")

    # JA3 Results
    section_header("JA3 TLS Fingerprints", "🔐")
    ja3_results = results.get("ja3_results", [])
    if ja3_results:
        ja3_df = pd.DataFrame(ja3_results)
        st.dataframe(ja3_df, use_container_width=True, hide_index=True)
    else:
        info_box("No TLS ClientHello packets found in the capture.", "info")

    # Geographic Map
    section_header("Geographic Analysis", "🗺️")
    if results.get("geo_fig"):
        st.plotly_chart(results["geo_fig"], use_container_width=True)

    # IP Reputation
    section_header("IP Reputation", "🌐")
    ip_reps = results.get("ip_reputations", [])
    if ip_reps:
        ip_df = pd.DataFrame(ip_reps)
        st.dataframe(ip_df, use_container_width=True, hide_index=True)
    else:
        info_box("No external IPs found or no API key provided.", "info")

    # Evidence Integrity
    section_header("Chain of Custody", "🔗")
    evidence = results.get("evidence_hash", {})
    if evidence:
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**File:** `{evidence.get('filename', 'N/A')}`")
            st.markdown(f"**Size:** `{evidence.get('filesize_bytes', 0):,} bytes`")
        with col2:
            st.markdown(f"**Algorithm:** `{evidence.get('algorithm', 'SHA-256')}`")
            st.markdown(f"**SHA-256:** `{evidence.get('hash', 'N/A')}`")
