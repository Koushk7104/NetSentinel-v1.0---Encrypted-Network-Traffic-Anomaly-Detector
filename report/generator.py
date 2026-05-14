"""
NetSentinel v1.0 — Forensic Report Generator
Produces autopsy-style signed PDF reports using WeasyPrint + Jinja2.
"""

import os
import tempfile
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader
from utils.config import REPORT_DIR, OUTPUT_DIR
from utils.hashing import compute_file_hash, compute_data_hash, build_chain_of_custody


class ForensicReportGenerator:
    """Generates a structured, signed PDF forensic report."""

    def __init__(self):
        self.template_dir = REPORT_DIR
        self.env = Environment(loader=FileSystemLoader(self.template_dir))
        self.template = self.env.get_template("template.html")

    def generate(self, analysis_data: dict, output_path: str = None) -> dict:
        """
        Generate the forensic PDF report.
        
        Args:
            analysis_data: Dict containing all analysis results
            output_path: Where to save the PDF (defaults to output/ dir)
        
        Returns:
            dict with 'pdf_path', 'pdf_bytes', 'custody'
        """
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            case_id = analysis_data.get("case_id", "NS")
            output_path = os.path.join(OUTPUT_DIR, f"NetSentinel_Report_{case_id}_{timestamp}.pdf")

        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # Prepare template data
        template_data = self._prepare_template_data(analysis_data)

        # Save charts as temp images for embedding
        chart_paths = self._save_charts(analysis_data)
        template_data.update(chart_paths)

        # Render HTML
        html_content = self.template.render(**template_data)

        # Generate PDF
        pdf_bytes = None

        # Method 1: Try xhtml2pdf (pure Python, no system deps)
        try:
            from xhtml2pdf import pisa
            import io
            pdf_buffer = io.BytesIO()
            pisa_status = pisa.CreatePDF(
                io.BytesIO(html_content.encode("utf-8")),
                dest=pdf_buffer,
                encoding="utf-8",
            )
            if not pisa_status.err:
                pdf_bytes = pdf_buffer.getvalue()
        except ImportError:
            pass
        except Exception:
            pass

        # Method 2: Try WeasyPrint as fallback
        if pdf_bytes is None:
            try:
                from weasyprint import HTML
                pdf_bytes = HTML(
                    string=html_content,
                    base_url=self.template_dir
                ).write_pdf()
            except Exception:
                pass

        # Method 3: Fall back to HTML
        if pdf_bytes is None:
            html_path = output_path.replace(".pdf", ".html")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            custody = _build_custody_data(analysis_data)
            return {
                "pdf_path": html_path,
                "pdf_bytes": html_content.encode("utf-8"),
                "custody": custody,
                "format": "html",
                "message": "Saved as HTML report. Install xhtml2pdf for PDF: pip install xhtml2pdf",
            }

        # Write PDF
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)

        # Build chain of custody
        pcap_path = analysis_data.get("pcap_path")
        custody = build_chain_of_custody(
            pcap_path=pcap_path,
            report_bytes=pdf_bytes,
        )

        # Cleanup temp chart files
        for path in chart_paths.values():
            if path and os.path.exists(str(path)):
                try:
                    os.remove(path)
                except Exception:
                    pass

        return {
            "pdf_path": output_path,
            "pdf_bytes": pdf_bytes,
            "custody": custody,
            "format": "pdf",
        }

    def _prepare_template_data(self, data: dict) -> dict:
        """Map analysis data to template variables."""
        total_anomalies = data.get("total_anomalies", 0)
        total_flows = data.get("total_flows", 0)
        ja3_matches = data.get("ja3_matches_count", 0)

        # Determine risk level
        if total_anomalies > total_flows * 0.2 or ja3_matches > 0:
            risk_level, risk_class = "HIGH", "risk-high"
        elif total_anomalies > total_flows * 0.05:
            risk_level, risk_class = "MEDIUM", "risk-medium"
        else:
            risk_level, risk_class = "LOW", "risk-low"

        # Executive summary
        summary = (
            f"NetSentinel analyzed {data.get('total_packets', 0):,} packets across "
            f"{total_flows:,} network flows. The Isolation Forest algorithm flagged "
            f"{total_anomalies:,} anomalous flows ({100*total_anomalies/max(total_flows,1):.1f}% of traffic). "
        )
        if ja3_matches > 0:
            summary += f"{ja3_matches} JA3 fingerprint(s) matched known malware signatures. "
        summary += "See detailed findings below."

        # Anomaly table (top 20)
        anomaly_table = []
        for _, row in data.get("anomalies_df", __import__("pandas").DataFrame()).head(20).iterrows():
            score = row.get("anomaly_score_normalized", 0)
            sc = "risk-high" if score > 70 else ("risk-medium" if score > 40 else "risk-low")
            anomaly_table.append({
                "src_ip": row.get("src_ip", ""),
                "dst_ip": row.get("dst_ip", ""),
                "dst_port": row.get("dst_port", ""),
                "protocol": row.get("protocol", ""),
                "packet_count": row.get("packet_count", 0),
                "byte_count": row.get("byte_count", 0),
                "anomaly_score_normalized": round(score, 1),
                "score_class": sc,
            })

        # Timeline events
        timeline_events = []
        for _, row in data.get("anomalies_df", __import__("pandas").DataFrame()).head(30).iterrows():
            score = row.get("risk_score", row.get("anomaly_score_normalized", 0))
            rc = "risk-high" if score > 70 else ("risk-medium" if score > 40 else "risk-low")
            timeline_events.append({
                "timestamp": _format_timestamp(row.get("start_time", 0)),
                "src": f"{row.get('src_ip', '')}:{row.get('src_port', '')}",
                "dst": f"{row.get('dst_ip', '')}:{row.get('dst_port', '')}",
                "protocol": row.get("protocol", ""),
                "risk_score": round(score, 1),
                "risk_class": rc,
                "trigger": _determine_trigger(row),
            })

        # JA3 table
        ja3_table = data.get("ja3_results", [])

        # IP reputation table
        ip_rep_table = []
        for rep in data.get("ip_reputations", []):
            score = rep.get("abuse_score", 0)
            sc = "risk-high" if score >= 50 else ("risk-medium" if score >= 25 else "risk-low")
            rep["score_class"] = sc
            ip_rep_table.append(rep)

        # Protocol table
        protocol_table = data.get("protocol_stats", [])

        # Baseline table
        baseline_table = []
        baseline = data.get("baseline_summary", {}).get("baseline", {})
        for feature, stats in baseline.items():
            baseline_table.append({
                "feature": feature,
                "mean": f"{stats['mean']:.4f}",
                "std": f"{stats['std']:.4f}",
                "median": f"{stats['median']:.4f}",
                "iqr": f"{stats['iqr']:.4f}",
            })

        # Recommendations
        recommendations = _generate_recommendations(data)

        return {
            "case_id": data.get("case_id", f"NS-{datetime.now().strftime('%Y%m%d')}"),
            "analyst_name": data.get("analyst_name", "NetSentinel Automated Analysis"),
            "report_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "classification": data.get("classification", "CONFIDENTIAL"),
            "analysis_mode": data.get("analysis_mode", "Forensic (PCAP)"),
            "source_file": data.get("source_file", "N/A"),
            "total_packets": f"{data.get('total_packets', 0):,}",
            "total_flows": f"{total_flows:,}",
            "total_anomalies": f"{total_anomalies:,}",
            "risk_level": risk_level,
            "risk_class": risk_class,
            "executive_summary": summary,
            "ja3_matches": ja3_matches,
            "flagged_ips": len(ip_rep_table),
            "analysis_duration": data.get("analysis_duration", "N/A"),
            "model_params": data.get("model_params", {}),
            "anomaly_table": anomaly_table,
            "timeline_events": timeline_events,
            "ja3_table": ja3_table,
            "ip_reputation_table": ip_rep_table,
            "protocol_table": protocol_table,
            "baseline_table": baseline_table,
            "recommendations": recommendations,
            "custody": _build_custody_data(data),
            "analyst_notes": data.get("analyst_notes", ""),
            "timeline_chart": None,
            "protocol_chart": None,
            "geo_chart": None,
        }

    def _save_charts(self, data: dict) -> dict:
        """Save Plotly charts as temporary PNG images."""
        charts = {}
        try:
            for key in ["timeline_fig", "protocol_fig", "geo_fig"]:
                fig = data.get(key)
                if fig:
                    tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
                    fig.write_image(tmp.name, width=800, height=400)
                    chart_key = key.replace("_fig", "_chart")
                    charts[chart_key] = tmp.name
        except Exception:
            pass
        return charts


def _format_timestamp(ts):
    """Convert unix timestamp to readable string."""
    try:
        if ts and ts > 0:
            return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    return "N/A"


def _determine_trigger(row) -> str:
    """Determine what triggered the anomaly flag."""
    triggers = []
    if row.get("anomaly_label") == -1:
        triggers.append("Isolation Forest")
    if row.get("ja3_malicious"):
        triggers.append("JA3 Match")
    if row.get("stat_anomaly"):
        triggers.append("Statistical Deviation")
    return ", ".join(triggers) if triggers else "Anomaly Score"


def _generate_recommendations(data: dict) -> list:
    """Generate automated recommendations based on findings."""
    recs = []
    anomalies = data.get("total_anomalies", 0)
    ja3 = data.get("ja3_matches_count", 0)
    flagged = len(data.get("ip_reputations", []))

    if ja3 > 0:
        recs.append("CRITICAL: JA3 fingerprints matching known malware were detected. Immediately isolate affected hosts and conduct a full incident response investigation.")
        recs.append("Block identified malicious JA3 hashes at the network perimeter using TLS inspection policies.")

    if flagged > 0:
        recs.append(f"Review and consider blocking {flagged} IP addresses flagged for suspicious reputation.")

    if anomalies > 0:
        recs.append("Investigate the top anomalous flows for potential data exfiltration, C2 communication, or lateral movement.")
        recs.append("Cross-reference anomalous IPs with your organization's threat intelligence feeds.")

    recs.append("Continue monitoring network traffic to refine the behavioral baseline and reduce false positives over time.")
    recs.append("Ensure all endpoints have up-to-date security agents and EDR telemetry enabled.")
    recs.append("Review firewall and IDS/IPS rules to incorporate indicators from this analysis.")

    return recs


def _build_custody_data(data: dict) -> dict:
    """Build a properly structured custody dict for the template."""
    # Default structure that the template expects
    custody = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence": {
            "algorithm": "SHA-256",
            "filename": data.get("source_file", "N/A"),
            "hash": "N/A (Live capture — no file to hash)",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "report": {
            "algorithm": "SHA-256",
            "hash": "Computed after generation",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    }

    # Override with actual evidence hash if available
    evidence_hash = data.get("evidence_hash", {})
    if evidence_hash and evidence_hash.get("hash"):
        custody["evidence"] = {
            "algorithm": evidence_hash.get("algorithm", "SHA-256"),
            "filename": evidence_hash.get("filename", "N/A"),
            "hash": evidence_hash.get("hash", "N/A"),
            "filepath": evidence_hash.get("filepath", "N/A"),
            "filesize_bytes": evidence_hash.get("filesize_bytes", 0),
            "timestamp": evidence_hash.get("timestamp", "N/A"),
        }

    # Override with actual custody data if available
    existing = data.get("custody", {})
    if existing and existing.get("evidence", {}).get("hash"):
        custody = existing

    return custody
