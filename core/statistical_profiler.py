"""
NetSentinel v1.0 — Statistical Profiler
Layer 3: Builds a personalized baseline of normal network behavior
and computes composite risk scores to reduce false positives.
"""

import numpy as np
import pandas as pd
from utils.config import DEVIATION_THRESHOLD, RISK_WEIGHT_IF, RISK_WEIGHT_JA3, RISK_WEIGHT_STAT
from core.flow_aggregator import get_feature_columns


class StatisticalProfiler:
    """Builds a per-session baseline from your traffic, not generic datasets."""

    def __init__(self, deviation_threshold=None):
        self.threshold = deviation_threshold or DEVIATION_THRESHOLD
        self.baseline = {}
        self.is_baselined = False

    def build_baseline(self, flow_df: pd.DataFrame):
        """Compute per-feature statistics from the flow data."""
        features = get_feature_columns()
        for col in features:
            if col in flow_df.columns:
                data = flow_df[col].replace([np.inf, -np.inf], np.nan).dropna()
                if len(data) > 0:
                    self.baseline[col] = {
                        "mean": float(data.mean()),
                        "std": float(data.std()) if len(data) > 1 else 0.0,
                        "median": float(data.median()),
                        "q1": float(data.quantile(0.25)),
                        "q3": float(data.quantile(0.75)),
                        "iqr": float(data.quantile(0.75) - data.quantile(0.25)),
                        "min": float(data.min()),
                        "max": float(data.max()),
                    }
        self.is_baselined = True
        return self

    def compute_deviations(self, flow_df: pd.DataFrame) -> pd.DataFrame:
        """Flag flows deviating > threshold sigma from baseline."""
        result = flow_df.copy()
        if not self.is_baselined:
            self.build_baseline(flow_df)

        deviation_counts = np.zeros(len(result))
        max_deviation = np.zeros(len(result))

        for col, stats in self.baseline.items():
            if col in result.columns and stats["std"] > 0:
                z_scores = np.abs((result[col].values - stats["mean"]) / max(stats["std"], 1e-10))
                deviation_counts += (z_scores > self.threshold).astype(int)
                max_deviation = np.maximum(max_deviation, z_scores)

        result["deviation_count"] = deviation_counts.astype(int)
        result["max_deviation_sigma"] = np.round(max_deviation, 2)
        result["stat_anomaly"] = (deviation_counts >= 2).astype(int)
        return result

    def compute_risk_score(self, flow_df: pd.DataFrame,
                           if_scores: pd.Series = None,
                           ja3_flags: pd.Series = None) -> pd.Series:
        """
        Composite risk score (0-100) combining all three layers:
          - Isolation Forest anomaly score (weight: 0.4)
          - JA3 malware match flag (weight: 0.3)
          - Statistical deviation (weight: 0.3)
        """
        n = len(flow_df)

        # Layer 1: IF score (0-100, already normalized)
        if if_scores is not None:
            if_component = if_scores.clip(0, 100).values
        else:
            if_component = np.zeros(n)

        # Layer 2: JA3 match (binary → 0 or 100)
        if ja3_flags is not None:
            ja3_component = ja3_flags.values * 100
        else:
            ja3_component = np.zeros(n)

        # Layer 3: Statistical deviation (normalize deviation_count)
        if "deviation_count" in flow_df.columns:
            dev_counts = flow_df["deviation_count"].values
            max_dev = dev_counts.max() if dev_counts.max() > 0 else 1
            stat_component = (dev_counts / max_dev) * 100
        else:
            stat_component = np.zeros(n)

        # Weighted composite
        risk = (RISK_WEIGHT_IF * if_component +
                RISK_WEIGHT_JA3 * ja3_component +
                RISK_WEIGHT_STAT * stat_component)

        return pd.Series(np.round(risk.clip(0, 100), 1), index=flow_df.index, name="risk_score")

    def get_baseline_summary(self) -> dict:
        """Return baseline statistics for the report."""
        return {
            "is_baselined": self.is_baselined,
            "features_profiled": len(self.baseline),
            "threshold_sigma": self.threshold,
            "baseline": self.baseline,
        }
