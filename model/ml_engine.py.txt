import os
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_recall_fscore_support, confusion_matrix,
    roc_auc_score, roc_curve
)
import plotly.graph_objects as go
import plotly.express as px

# Feature keys must match core/analyzer.py extract_25_features output
FEATURE_KEYS = [
    "url_length",
    "host_length",
    "domain_length",
    "path_length",
    "query_length",
    "has_https",
    "has_http",
    "ip_address_like",
    "punycode_present",
    "port_present",
    "shortener_present",
    "suspicious_token_hits",
    "at_symbol_count",
    "hyphen_count",
    "underscore_count",
    "digits_ratio",
    "alpha_ratio",
    "dots_ratio",
    "hyphen_ratio",
    "url_entropy",
    "domain_entropy",
    "unique_chars_ratio",
    "domain_age_days",
    "domain_age_missing_flag",
    "saudi_spoof_score",
]

MODEL_DIR = "model"
MODEL_PATH = os.path.join(MODEL_DIR, "random_forest_url_detector.joblib")
META_PATH = os.path.join(MODEL_DIR, "model_metrics_cache.joblib")


class MLEngine:
    def __init__(self):
        self.model = None
        self.metrics_cache = None

    # -----------------------------
    # Ensure model exists
    # -----------------------------
    def ensure_model_exists(self):
        os.makedirs(MODEL_DIR, exist_ok=True)
        if os.path.exists(MODEL_PATH) and os.path.exists(META_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
                self.metrics_cache = joblib.load(META_PATH)
                return
            except Exception:
                pass

        # Train a resilient initial model on synthetic/heuristic labeled dataset
        self.model, metrics = self._train_model_resilient()
        joblib.dump(self.model, MODEL_PATH)
        joblib.dump(metrics, META_PATH)
        self.metrics_cache = metrics

    # -----------------------------
    # Predict
    # -----------------------------
    def predict_threat_probability(self, features: dict):
        if self.model is None:
            self.ensure_model_exists()

        x = np.array([[float(features.get(k, -1)) for k in FEATURE_KEYS]], dtype=float)
        # probability of class 1 (malicious/threat)
        proba = self.model.predict_proba(x)[0][1]
        # keep in [0,1]
        proba = float(max(0.0, min(1.0, proba)))
        return proba

    # -----------------------------
    # Metrics
    # -----------------------------
    def get_metrics(self):
        if self.metrics_cache is None:
            # load if possible
            if os.path.exists(META_PATH):
                try:
                    self.metrics_cache = joblib.load(META_PATH)
                except Exception:
                    return None
            else:
                return None
        return self.metrics_cache

    # -----------------------------
    # Training
    # -----------------------------
    def _train_model_resilient(self):
        # Create dataset based on heuristics: map features to label probability
        # This keeps the system functional on Streamlit Cloud without needing external datasets.
        rng = np.random.default_rng(42)

        n_samples = 2400
        X = []
        y = []

        for _ in range(n_samples):
            # Sample features with ranges that resemble URL signals
            # url_length
            url_length = rng.integers(10, 320)
            host_length = rng.integers(5, 60)
            domain_length = rng.integers(5, 50)
            path_length = rng.integers(0, 160)
            query_length = rng.integers(0, 200)

            has_https = rng.integers(0, 2)
            has_http = 1 - has_https if rng.random() < 0.7 else rng.integers(0, 2)

            ip_address_like = 1 if rng.random() < 0.08 else 0
            punycode_present = 1 if rng.random() < 0.06 else 0
            port_present = 1 if rng.random() < 0.06 else 0
            shortener_present = 1 if rng.random() < 0.12 else 0

            suspicious_token_hits = int(rng.integers(0, 6))  # 0..5
            at_symbol_count = int(rng.integers(0, 3))
            hyphen_count = int(rng.integers(0, 20))
            underscore_count = int(rng.integers(0, 10))

            digits_ratio = float(rng.uniform(0, 0.8))
            alpha_ratio = float(rng.uniform(0, 0.9))
            dots_ratio = float(rng.uniform(0, 0.35))
            hyphen_ratio = float(rng.uniform(0, 0.25))

            url_entropy = float(rng.uniform(1.0, 6.0))
            domain_entropy = float(rng.uniform(0.5, 5.0))
            unique_chars_ratio = float(rng.uniform(0.1, 1.0))

            # Domain age days: -1 means missing WHOIS
            if rng.random() < 0.18:
                domain_age_days = -1
                domain_age_missing_flag = 1
            else:
                domain_age_missing_flag = 0
                domain_age_days = int(rng.integers(0, 1200))
            saudi_spoof_score = float(rng.uniform(0, 1))

            row = [
                url_length, host_length, domain_length, path_length, query_length,
                has_https, has_http,
                ip_address_like, punycode_present, port_present, shortener_present,
                suspicious_token_hits,
                at_symbol_count, hyphen_count, underscore_count,
                digits_ratio, alpha_ratio, dots_ratio, hyphen_ratio,
                url_entropy, domain_entropy, unique_chars_ratio,
                domain_age_days, domain_age_missing_flag, saudi_spoof_score
            ]

            # Heuristic labeling:
            # Critical indicators push to malicious
            score = 0.0
            if has_https == 0:
                score += 1.2
            if ip_address_like == 1:
                score += 1.6
            if punycode_present == 1:
                score += 2.0
            if shortener_present == 1:
                score += 1.2
            if suspicious_token_hits >= 2:
                score += 1.1 + 0.25 * suspicious_token_hits
            if url_length > 200:
                score += 1.2
            if url_entropy > 4.0:
                score += 0.9
            if at_symbol_count >= 1:
                score += 1.0
            if hyphen_count >= 10:
                score += 0.8
            if domain_age_days != -1 and domain_age_days < 30:
                score += 1.4
            if domain_age_missing_flag == 1:
                score += 0.5
            if saudi_spoof_score >= 0.8:
                score += 3.0

            # Convert score to probability then label
            prob = 1 / (1 + np.exp(- (score - 3.0)))
            label = 1 if rng.random() < prob else 0

            X.append(row)
            y.append(label)

        X = np.array(X, dtype=float)
        y = np.array(y, dtype=int)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.22, random_state=42, stratify=y
        )

        model = RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            min_samples_split=3,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X_train, y_train)

        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)[:, 1]

        acc = float(accuracy_score(y_test, y_pred))
        pr, rc, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary", zero_division=0)
        roc_auc = float(roc_auc_score(y_test, y_proba))

        cm = confusion_matrix(y_test, y_pred, labels=[0, 1])

        # Confusion matrix figure
        cm_fig = go.Figure(
            data=go.Heatmap(
                z=cm,
                x=["Predicted Safe(0)", "Predicted Threat(1)"],
                y=["Actual Safe(0)", "Actual Threat(1)"],
                colorscale="Blues" if False else "Viridis",
                showscale=True,
            )
        )
        cm_fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=340,
            margin=dict(l=20, r=20, t=30, b=20),
        )

        # ROC curve
        fpr, tpr, _ = roc_curve(y_test, y_proba)
        roc_fig = go.Figure()
        roc_fig.add_trace(go.Scatter(x=fpr, y=tpr, mode="lines", name=f"ROC (AUC={roc_auc:.3f})"))
        roc_fig.add_trace(go.Scatter(x=[0, 1], y=[0, 1], mode="lines", name="Random", line=dict(dash="dash")))
        roc_fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=340,
            margin=dict(l=20, r=20, t=30, b=20),
            xaxis_title="False Positive Rate",
            yaxis_title="True Positive Rate",
        )

        # Feature importance
        importances = model.feature_importances_
        fi_df = pd.DataFrame({"feature": FEATURE_KEYS, "importance": importances})
        fi_df = fi_df.sort_values("importance", ascending=False)

        report = {
            "accuracy": round(acc, 4),
            "precision": round(float(pr), 4),
            "recall": round(float(rc), 4),
            "f1": round(float(f1), 4),
            "roc_auc": round(float(roc_auc), 4),
            "n_train": int(len(X_train)),
            "n_test": int(len(X_test)),
        }

        metrics = {
            "report": report,
            "cm_fig": cm_fig,
            "roc_fig": roc_fig,
            "feature_importance_df": fi_df,
        }
        return model, metrics
