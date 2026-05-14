"""
NetSentinel v1.0 — Report View
Preview and download the autopsy-style PDF forensic report.
"""

import streamlit as st
from ui.components import section_header, info_box
from report.generator import ForensicReportGenerator


def render_report_view(config: dict):
    """Render the report generation and download page."""

    if "analysis_results" not in st.session_state:
        st.markdown("""
        <div style="text-align:center;padding:60px 20px;">
            <div style="font-size:64px;margin-bottom:16px;">📄</div>
            <h2 style="color:#667eea;">No Analysis Results</h2>
            <p style="color:#888;">Run an analysis first (Live or Forensic) to generate a report.</p>
        </div>
        """, unsafe_allow_html=True)
        return

    section_header("Generate Forensic Report", "📄")

    results = st.session_state.analysis_results

    # Report summary
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Flows", f"{results['total_flows']:,}")
    with col2:
        st.metric("Anomalies", f"{results['total_anomalies']:,}")
    with col3:
        st.metric("JA3 Matches", str(results["ja3_matches_count"]))

    st.markdown("---")

    # Generate button
    if st.button("📝 Generate PDF Report", type="primary", use_container_width=True):
        with st.spinner("Generating forensic report..."):
            try:
                generator = ForensicReportGenerator()

                # Add config to results
                report_data = {**results}
                report_data["case_id"] = config.get("case_id", "NS-2026-001")
                report_data["analyst_name"] = config.get("analyst_name", "Security Analyst")
                report_data["classification"] = config.get("classification", "CONFIDENTIAL")
                report_data["analyst_notes"] = config.get("analyst_notes", "")
                report_data["analysis_mode"] = "Live Capture" if config.get("mode") == "live" else "Forensic (PCAP)"

                result = generator.generate(report_data)

                st.session_state.generated_report = result
                st.success(f"✅ Report generated successfully!")

            except Exception as e:
                st.error(f"Report generation failed: {str(e)}")
                import traceback
                st.code(traceback.format_exc())

    # Download button
    if "generated_report" in st.session_state:
        report = st.session_state.generated_report
        fmt = report.get("format", "pdf")

        if report.get("message"):
            info_box(report["message"], "warning")

        st.download_button(
            label=f"⬇️ Download Report (.{fmt})",
            data=report["pdf_bytes"],
            file_name=f"NetSentinel_Report.{fmt}",
            mime="application/pdf" if fmt == "pdf" else "text/html",
            use_container_width=True,
        )

        # Show custody info
        custody = report.get("custody", {})
        if custody:
            section_header("Chain of Custody", "🔗")

            ev = custody.get("evidence", {})
            rp = custody.get("report", {})

            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Evidence (PCAP)**")
                st.code(f"SHA-256: {ev.get('hash', 'N/A')}\nFile: {ev.get('filename', 'N/A')}\nTime: {ev.get('timestamp', 'N/A')}")
            with col2:
                st.markdown("**Report (PDF)**")
                st.code(f"SHA-256: {rp.get('hash', 'N/A')}\nSize: {rp.get('size_bytes', 'N/A')} bytes\nTime: {rp.get('timestamp', 'N/A')}")
