"""
NetSentinel v1.0 — Isolation Forest Anomaly Detector
Layer 1 of the hybrid detection pipeline.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from utils.config import DEFAULT_CONTAMINATION, DEFAULT_N_ESTIMATORS, DEFAULT_RANDOM_STATE
from core.flow_aggregator import get_feature_columns


class AnomalyDetector:
    def __init__(self, contamination=None, n_estimators=None, random_state=None):
        self.contamination = contamination or DEFAULT_CONTAMINATION
        self.n_estimators = n_estimators or DEFAULT_N_ESTIMATORS
        self.random_state = random_state or DEFAULT_RANDOM_STATE
        self.model = IsolationForest(
            n_estimators=self.n_estimators, contamination=self.contamination,
            random_state=self.random_state, n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.feature_columns = get_feature_columns()

    def fit(self, flow_df: pd.DataFrame):
        features = self._extract_features(flow_df)
        if features is None or len(features) < 2:
            return self
        scaled = self.scaler.fit_transform(features)
        self.model.fit(scaled)
        self.is_fitted = True
        return self

    def predict(self, flow_df: pd.DataFrame) -> pd.DataFrame:
        result = flow_df.copy()
        features = self._extract_features(flow_df)
        if features is None or len(features) == 0:
            result["anomaly_label"] = 1
            result["anomaly_score"] = 0.0
            result["anomaly_score_normalized"] = 0.0
            return result
        if not self.is_fitted:
            self.fit(flow_df)
        scaled = self.scaler.transform(features)
        labels = self.model.predict(scaled)
        scores = self.model.decision_function(scaled)
        result["anomaly_label"] = labels
        result["anomaly_score"] = scores
        min_s, max_s = scores.min(), scores.max()
        if max_s != min_s:
            normalized = 100 * (1 - (scores - min_s) / (max_s - min_s))
        else:
            normalized = np.where(labels == -1, 75.0, 25.0)
        result["anomaly_score_normalized"] = np.round(normalized, 2)
        return result

    def get_anomalies(self, flow_df: pd.DataFrame) -> pd.DataFrame:
        predicted = self.predict(flow_df)
        anomalies = predicted[predicted["anomaly_label"] == -1]
        return anomalies.sort_values("anomaly_score_normalized", ascending=False)

    def get_model_params(self) -> dict:
        return {
            "algorithm": "Isolation Forest", "n_estimators": self.n_estimators,
            "contamination": self.contamination, "is_fitted": self.is_fitted,
            "feature_count": len(self.feature_columns), "features": self.feature_columns,
        }

    def _extract_features(self, flow_df: pd.DataFrame):
        available = [c for c in self.feature_columns if c in flow_df.columns]
        if not available:
            return None
        features = flow_df[available].copy()
        features = features.replace([np.inf, -np.inf], np.nan).fillna(0)
        return features.values
