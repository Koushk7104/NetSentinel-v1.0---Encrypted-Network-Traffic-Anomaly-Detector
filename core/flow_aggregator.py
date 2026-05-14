"""
NetSentinel v1.0 — Flow Aggregator
Converts raw packet records into bidirectional network flows with computed features
for the ML anomaly detection pipeline.
"""

import pandas as pd
import numpy as np
from collections import defaultdict
from datetime import datetime


def aggregate_packets_to_flows(packets: list) -> pd.DataFrame:
    """
    Group individual packet records into bidirectional network flows.
    Each flow is identified by a 5-tuple: (src_ip, dst_ip, src_port, dst_port, protocol).
    
    Args:
        packets: List of packet dicts with keys:
            src_ip, dst_ip, src_port, dst_port, protocol, size, timestamp, flags, payload_size
    
    Returns:
        DataFrame with one row per flow and computed features.
    """
    if not packets:
        return _empty_flow_df()

    flows = defaultdict(lambda: {
        "packets": [],
        "timestamps": [],
        "sizes": [],
        "payload_sizes": [],
        "flags": [],
    })

    for pkt in packets:
        # Create canonical flow key (bidirectional — sort IPs to merge directions)
        src = (pkt.get("src_ip", ""), pkt.get("src_port", 0))
        dst = (pkt.get("dst_ip", ""), pkt.get("dst_port", 0))
        proto = pkt.get("protocol", "UNKNOWN")

        if src > dst:
            key = (dst[0], src[0], dst[1], src[1], proto)
        else:
            key = (src[0], dst[0], src[1], dst[1], proto)

        flow = flows[key]
        flow["packets"].append(pkt)
        flow["timestamps"].append(pkt.get("timestamp", 0))
        flow["sizes"].append(pkt.get("size", 0))
        flow["payload_sizes"].append(pkt.get("payload_size", 0))
        flow["flags"].append(pkt.get("flags", ""))

    # Compute flow features
    records = []
    for (src_ip, dst_ip, src_port, dst_port, protocol), flow_data in flows.items():
        timestamps = sorted(flow_data["timestamps"])
        sizes = flow_data["sizes"]
        payload_sizes = flow_data["payload_sizes"]
        flags_list = flow_data["flags"]

        packet_count = len(sizes)
        byte_count = sum(sizes)
        payload_byte_count = sum(payload_sizes)
        duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.001

        # Inter-arrival times
        if len(timestamps) > 1:
            inter_arrivals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            avg_inter_arrival = np.mean(inter_arrivals)
            std_inter_arrival = np.std(inter_arrivals) if len(inter_arrivals) > 1 else 0
        else:
            avg_inter_arrival = 0
            std_inter_arrival = 0

        # TCP flags
        all_flags = " ".join(str(f) for f in flags_list)
        syn_count = all_flags.count("S") if all_flags else 0
        fin_count = all_flags.count("F") if all_flags else 0
        rst_count = all_flags.count("R") if all_flags else 0
        ack_count = all_flags.count("A") if all_flags else 0
        psh_count = all_flags.count("P") if all_flags else 0

        records.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "protocol": protocol,
            "start_time": min(timestamps),
            "end_time": max(timestamps),
            "duration": round(duration, 6),
            "packet_count": packet_count,
            "byte_count": byte_count,
            "payload_byte_count": payload_byte_count,
            "avg_packet_size": round(byte_count / packet_count, 2) if packet_count else 0,
            "max_packet_size": max(sizes) if sizes else 0,
            "min_packet_size": min(sizes) if sizes else 0,
            "std_packet_size": round(float(np.std(sizes)), 2) if len(sizes) > 1 else 0,
            "packet_rate": round(packet_count / duration, 2) if duration > 0 else 0,
            "byte_rate": round(byte_count / duration, 2) if duration > 0 else 0,
            "payload_ratio": round(payload_byte_count / byte_count, 4) if byte_count > 0 else 0,
            "avg_inter_arrival": round(avg_inter_arrival, 6),
            "std_inter_arrival": round(std_inter_arrival, 6),
            "syn_count": syn_count,
            "fin_count": fin_count,
            "rst_count": rst_count,
            "ack_count": ack_count,
            "psh_count": psh_count,
        })

    df = pd.DataFrame(records)

    # Add derived features
    if not df.empty:
        # Port scan indicator: many unique dst_ports from same src
        port_scan = df.groupby("src_ip")["dst_port"].transform("nunique")
        df["unique_dst_ports_from_src"] = port_scan

        # Connection density: many flows to same dst_ip
        conn_density = df.groupby("dst_ip")["src_ip"].transform("count")
        df["connection_density_to_dst"] = conn_density

    return df


def get_feature_columns() -> list:
    """Return the list of numeric feature column names used for ML input."""
    return [
        "duration",
        "packet_count",
        "byte_count",
        "payload_byte_count",
        "avg_packet_size",
        "max_packet_size",
        "min_packet_size",
        "std_packet_size",
        "packet_rate",
        "byte_rate",
        "payload_ratio",
        "avg_inter_arrival",
        "std_inter_arrival",
        "syn_count",
        "fin_count",
        "rst_count",
        "ack_count",
        "psh_count",
        "unique_dst_ports_from_src",
        "connection_density_to_dst",
    ]


def _empty_flow_df() -> pd.DataFrame:
    """Return an empty DataFrame with the correct schema."""
    columns = [
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "start_time", "end_time",
    ] + get_feature_columns()
    return pd.DataFrame(columns=columns)
