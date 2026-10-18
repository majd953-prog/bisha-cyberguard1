import os
import io
import json
import re
import math
import time
import base64
import hashlib
from datetime import datetime

import numpy as np
import pandas as pd
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px

from PIL import Image

import requests

from core.analyzer import URLAnalyzer
from model.ml_engine import MLEngine

# -----------------------------
# Page configuration
# -----------------------------
st.set_page_config(
    page_title="Bisha CyberGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------
# Session state init
# -----------------------------
if "theme" not in st.session_state:
    st.session_state["theme"] = "light"  # default: Academic Light (بني غامق للأزرار)

if "session_history" not in st.session_state:
    st.session_history = []

if "model_ready" not in st.session_state:
    st.session_model_ready = False


# -----------------------------
# Theme system (CSS + Plotly template)
# -----------------------------
DARK_BG = "#0A0F1D"
LIGHT_BG = "#F8FAFC"

NEON = "#00E5FF"
NEON_2 = "#7CFF6B"
GOLD = "#D4AF37"
INK = "#0F172A"

PLOTLY_DARK_TEMPLATE = "plotly_dark"
PLOTLY_LIGHT_TEMPLATE = "plotly_white"

# COCO Brown (Bisha-inspired) for Light mode buttons
COCO_BROWN = "#3B1F14"
COCO_BROWN_2 = "#2B140E"


def apply_theme(theme: str):
    st.session_state["theme"] = theme

    if theme == "dark":
        bg = DARK_BG
        fg = "#EAF2FF"
        muted = "#93A4C7"
        border = "rgba(0,229,255,0.25)"
        card = "rgba(255,255,255,0.04)"
        card2 = "rgba(0,229,255,0.07)"
        gold = GOLD
        neon = NEON
        neon2 = NEON_2
        plot_template = PLOTLY_DARK_TEMPLATE

        # keep your original dark-mode button gradient
        button_bg_css = "linear-gradient(90deg, rgba(0,229,255,0.15), rgba(212,175,55,0.10))"

    else:
        bg = LIGHT_BG
        fg = "#0B1220"
        muted = "#475569"
        border = "rgba(13,74,99,0.20)"
        card = "rgba(13,74,99,0.05)"
        card2 = "rgba(212,175,55,0.12)"
        gold = GOLD
        neon = "#0B3D6B"
        neon2 = "#0F766E"
        plot_template = PLOTLY_LIGHT_TEMPLATE

        # make Light mode buttons dark brown (طلبك)
        button_bg_css = f"linear-gradient(90deg, {COCO_BROWN}, {COCO_BROWN_2})"

    css = f"""
    <style>
      .main {{
        background-color: {bg} !important;
        color: {fg} !important;
      }}
      section[data-testid="stSidebar"] {{
        background: {bg} !important;
        color: {fg} !important;
        border-right: 1px solid {border} !important;
      }}
      .sidebar-card {{
        background: {card} !important;
        border: 1px solid {border} !important;
        border-radius: 14px;
        padding: 14px;
        box-shadow: 0 8px 30px rgba(0,0,0,0.18);
      }}
      .card-soft {{
        background: {card} !important;
        border: 1px solid {border} !important;
        border-radius: 14px;
        padding: 16px;
      }}
      .card-accent {{
        background: {card2} !important;
        border: 1px solid {border} !important;
        border-radius: 14px;
        padding: 16px;
      }}
      .stButton>button {{
        border: 1px solid {border} !important;
        background: {button_bg_css} !important;
        color: {fg} !important;
      }}
      .stTextInput>div>div>input {{
        border: 1px solid {border} !important;
        background: rgba(255,255,255,0.03) !important;
        color: {fg} !important;
      }}
      .stMarkdown {{
        color: {fg} !important;
      }}
      .muted {{
        color: {muted} !important;
      }}
      .badge {{
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 8px 12px;
        border-radius: 999px;
        border: 1px solid {border};
        background: {card} ;
        font-weight: 700;
      }}
      .danger {{
        background: rgba(231, 76, 60, 0.15) !important;
        border-color: rgba(231, 76, 60, 0.35) !important;
        color: #FFD1D1 !important;
      }}
      .critical {{
        background: rgba(255, 0, 72, 0.18) !important;
        border-color: rgba(255, 0, 72, 0.50) !important;
        color: #FFE0EA !important;
      }}
      .safe {{
        background: rgba(124,255,107,0.12) !important;
        border-color: rgba(124,255,107,0.35) !important;
        color: #DFFFE4 !important;
      }}
      .low {{
        background: rgba(0,229,255,0.10) !important;
        border-color: rgba(0,229,255,0.35) !important;
        color: #D9FCFF !important;
      }}
      .medium {{
        background: rgba(212,175,55,0.12) !important;
        border-color: rgba(212,175,55,0.40) !important;
        color: #FFF6D6 !important;
      }}
      .high {{
        background: rgba(244, 114, 182, 0.12) !important;
        border-color: rgba(244, 114, 182, 0.40) !important;
        color: #FFDDF1 !important;
      }}
      .mono {{
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      }}
      .small {{
        font-size: 0.95rem;
      }}
      .hr {{
        height: 1px;
        background: {border};
        margin: 12px 0;
      }}
      .title-glow {{
        text-shadow: 0 0 18px rgba(0,229,255,0.30);
      }}
    </style>
    """
    st.markdown(css, unsafe_allow_html=True)
    return plot_template, fg, muted, neon, neon2, gold


plot_template, FG, MUTED, NEON_COLOR, NEON2_COLOR, GOLD_COLOR = apply_theme(st.session_state["theme"])

# -----------------------------
# Identity header + sidebar
# -----------------------------
with st.sidebar:
    st.markdown("### 🛡️ Bisha CyberGuard")
    st.markdown(
        """
        <div class="muted small">
        University of Bisha · College of Computing & IT · Department of Cybersecurity
        </div>
        """,
        unsafe_allow_html=True
    )

    with st.container():
        st.markdown('<div class="sidebar-card">', unsafe_allow_html=True)

        default_student = os.environ.get("STUDENT_NAME", "اسم الطالب")
        default_student_id = os.environ.get("STUDENT_ID", "الرقم الجامعي")
        default_supervisor = os.environ.get("SUPERVISOR_NAME", "اسم الدكتور المشرف")
        default_year = os.environ.get("ACADEMIC_YEAR", "2024/2025")

        student_name = st.text_input("اسم الطالب", value=default_student, key="student_name")
        student_id = st.text_input("الرقم الجامعي", value=default_student_id, key="student_id")
        supervisor_name = st.text_input("اسم الدكتور المشرف", value=default_supervisor, key="supervisor_name")
        academic_year = st.text_input("العام الجامعي", value=default_year, key="academic_year")

        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("---")
    st.caption("Navigation (5 Sections)")

    nav = st.radio(
        "اختر القسم:",
        options=[
            "🔍 Live URL Threat Scanner",
            "📊 Threat Intelligence & Statistics Dashboard",
            "📱 Quishing QR & Bulk CSV Scanner",
            "🏛️ Academic Metrics & ML Architecture",
            "🎓 Project Overview & Documentation",
        ],
        index=0,
    )

# -----------------------------
# Top theme toggle
# -----------------------------
st.markdown(
    """
    <div class="card-soft" style="margin-bottom: 14px;">
      <div style="display:flex; align-items:center; justify-content:space-between; gap:12px;">
        <div>
          <div class="title-glow" style="font-size: 1.6rem; font-weight: 900;">Bisha CyberGuard</div>
          <div class="muted small">Intelligent Phishing & Malicious URL Detection Platform</div>
        </div>
        <div style="text-align:right;">
          <div class="badge mono">
            <span>🌓</span>
            <span>Day/Night</span>
          </div>
        </div>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

toggle_col1, toggle_col2 = st.columns([1, 3])

with toggle_col1:
    theme_label = "🌙 SOC Dark" if st.session_state["theme"] == "dark" else "☀️ Academic Light"

with toggle_col2:
    new_theme = "light" if st.session_state["theme"] == "dark" else "dark"
    if st.button(
        f"Switch to {'Academic Light Mode' if st.session_state['theme']=='dark' else 'SOC Dark Mode'}",
        use_container_width=True
    ):
        apply_theme(new_theme)
        st.rerun()


# -----------------------------
# Instantiate core modules
# -----------------------------
@st.cache_resource(show_spinner=False)
def get_analyzer():
    return URLAnalyzer()


@st.cache_resource(show_spinner=True)
def get_ml_engine():
    engine = MLEngine()
    engine.ensure_model_exists()
    return engine


analyzer = get_analyzer()
ml_engine = get_ml_engine()

# -----------------------------
# Helpers
# -----------------------------
def normalize_url(u: str) -> str:
    u = (u or "").strip()
    if not u:
        return u

    # If user typed domain only, add scheme
    if not re.match(r"^https?://", u, re.IGNORECASE):
        u_try = "https://" + u
        return u_try

    return u


def severity_badge(severity: str):
    if severity == "Safe":
        cls = "safe"
        icon = "✅"
    elif severity == "Low":
        cls = "low"
        icon = "🟦"
    elif severity == "Medium":
        cls = "medium"
        icon = "🟨"
    elif severity == "High":
        cls = "high"
        icon = "🟪"
    elif severity == "Critical Block":
        cls = "critical"
        icon = "⛔"
    else:
        cls = ""
        icon = "⚠️"

    return f'<span class="badge {cls}">{icon} {severity}</span>'


def plot_threat_gauge(threat_pct: float, severity: str):
    threat_pct = max(0.0, min(100.0, float(threat_pct)))
    color_map = {
        "Safe": "#7CFF6B",
        "Low": "#00E5FF",
        "Medium": "#D4AF37",
        "High": "#F472B6",
        "Critical Block": "#FF0048",
    }
    bar_color = color_map.get(severity, "#00E5FF")
    bg_color = "rgba(255,255,255,0.06)"

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=threat_pct,
            number={"suffix": "%", "font": {"color": "white"}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "rgba(255,255,255,0.4)"},
                "bar": {"color": bar_color},
                "bgcolor": bg_color,
                "steps": [
                    {"range": [0, 20], "color": "rgba(124,255,107,0.18)"},
                    {"range": [20, 40], "color": "rgba(0,229,255,0.16)"},
                    {"range": [40, 65], "color": "rgba(212,175,55,0.18)"},
                    {"range": [65, 85], "color": "rgba(244,114,182,0.16)"},
                    {"range": [85, 100], "color": "rgba(255,0,72,0.18)"},
                ],
                "threshold": {"line": {"color": bar_color, "width": 6}, "thickness": 0.75, "value": threat_pct},
            },
        )
    )

    fig.update_layout(
        template=plot_template,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10, r=10, t=20, b=10),
        height=320,
    )
    return fig


def add_history(entry: dict):
    st.session_history.insert(0, entry)
    st.session_history = st.session_history[:50]


def compute_reason_table(reasons: list):
    # reasons: [{reason, weight, detail}]
    rows = []
    total_weight = sum(r.get("weight", 0) for r in reasons) if reasons else 0
    for r in reasons:
        rows.append(
            {
                "السبب": r.get("reason", ""),
                "الوزن (ساهم في الخطورة)": r.get("weight", 0),
                "النسبة من مجموع الأوزان": (round((r.get("weight", 0) / total_weight) * 100, 1) if total_weight else 0),
                "تفاصيل تقنية": r.get("detail", ""),
            }
        )
    return pd.DataFrame(rows)


# -----------------------------
# NAVIGATION: 5 sections
# -----------------------------
if nav == "🔍 Live URL Threat Scanner":
    st.subheader("🔍 Live URL Threat Scanner")
    st.caption("Live URL Threat Scanner: 25-Feature Hybrid ML + Explainable AI + WHOIS/SSL Intelligence (with resilient fallback).")

    colA, colB = st.columns([2.2, 1])
    with colA:
        url_input = st.text_input("أدخل الرابط للفحص", placeholder="مثال: https://ub.edu.sa أو رابط تصيد/خبيث")
    with colB:
        scan_btn = st.button("ابدأ الفحص", use_container_width=True)

    demo_col1, demo_col2, demo_col3, demo_col4 = st.columns(4)

    demo_urls = [
        "https://www.ub.edu.sa",
        "https://ub-portal-login.com",  # phishing-like (demo)
        "http://93.184.216.34/login",  # direct IP demo
        "https://xn--pple-43d.com",  # punycode demo
    ]
    demo_labels = ["Sليم (UB)", "📣 تصيد (Demo)", "IP مباشر (Demo)", "Punycode (Demo)"]

    for i, (lbl, du) in enumerate(zip(demo_labels, demo_urls)):
        c = [demo_col1, demo_col2, demo_col3, demo_col4][i]
        if c.button(lbl, use_container_width=True):
            st.session_state["url_to_scan"] = du
            st.rerun()

    # ensure url_to_scan
    if "url_to_scan" in st.session_state:
        if not url_input:
            url_input = st.session_state["url_to_scan"]

    if scan_btn or ("url_to_scan" in st.session_state and url_input):
        url_to_scan = normalize_url(url_input)
        st.session_state["url_to_scan"] = url_to_scan

        if not url_to_scan:
            st.warning("يرجى إدخال رابط صحيح.")
        else:
            with st.spinner("جاري الفحص والتحليل (Hybrid ML + Explainable AI) ..."):
                threat_pct, severity, explain, features, artifacts = analyzer.analyze_url_with_explanations(
                    url=url_to_scan,
                    ml_engine=ml_engine,
                )

            # Main decision display
            dec_col1, dec_col2 = st.columns([1.4, 1.7])

            with dec_col1:
                st.markdown("### Threat Percentage (0% - 100%)")
                st.plotly_chart(plot_threat_gauge(threat_pct, severity), use_container_width=True)

                st.markdown("### Risk Severity Level")
                st.markdown(severity_badge(severity), unsafe_allow_html=True)

                st.markdown("<div class='hr'></div>", unsafe_allow_html=True)
                st.markdown("### Domain Age & WHOIS Intelligence")
                # artifacts contains whois/ssl/etc
                whois_info = artifacts.get("whois", {})
                ssl_info = artifacts.get("ssl", {})
                domain_info = artifacts.get("domain", {})

                domain = domain_info.get("domain", "")
                reg_date = whois_info.get("registration_date")
                registrar = whois_info.get("registrar")
                whois_status = whois_info.get("status", "unknown")
                domain_age_days = whois_info.get("age_days")
                ssl_status = ssl_info.get("tls_status", "unknown")
                ssl_issuer = ssl_info.get("issuer", "")
                ssl_not_after = ssl_info.get("not_after", "")

                age_warning = False
                if isinstance(domain_age_days, (int, float)):
                    if domain_age_days < 30:
                        age_warning = True
                if whois_status == "unavailable":
                    age_warning = True

                if age_warning:
                    st.markdown('<div class="card-accent critical" style="padding:12px; border-radius:12px;">', unsafe_allow_html=True)
                    st.markdown("**⚠️ تنبيه:**")
                    if whois_status == "unavailable":
                        st.markdown("- تعذر التحقق من سجلات WHOIS (fallback تم تفعيله).")
                    if isinstance(domain_age_days, (int, float)) and domain_age_days < 30:
                        st.markdown(f"- عمر النطاق حديث جداً: **{int(domain_age_days)} يوم** (< 30).")
                    st.markdown("</div>", unsafe_allow_html=True)

                st.markdown(
                    f"""
                    <div class="mono small">
                    <div><b>Domain:</b> {domain}</div>
                    <div><b>WHOIS Status:</b> {whois_status}</div>
                    <div><b>Registration Date:</b> {reg_date or "N/A"}</div>
                    <div><b>Age:</b> {whois_info.get('age_years','N/A')} ({domain_age_days if domain_age_days is not None else 'N/A'} days)</div>
                    <div><b>Registrar:</b> {registrar or "N/A"}</div>
                    <div><b>SSL/TLS:</b> {ssl_status}</div>
                    <div><b>Issuer:</b> {ssl_issuer or "N/A"}</div>
                    <div><b>Cert Not After:</b> {ssl_not_after or "N/A"}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            with dec_col2:
                st.markdown("### Explainable Block Reasons (Why was this blocked?)")
                reasons = explain.get("reasons", [])
                total_weight = sum(r.get("weight", 0) for r in reasons) if reasons else 0
                if not reasons:
                    st.info("لا توجد أسباب واضحة من قواعد التفسير في هذه الحالة. (قد يعتمد القرار على ML features)")
                else:
                    df = compute_reason_table(reasons)
                    st.dataframe(df, use_container_width=True, height=240)

                st.markdown("<div class='hr'></div>", unsafe_allow_html=True)

                st.markdown("### Feature Snapshot (Top Signals)")
                weighted = sorted(reasons, key=lambda x: x.get("weight", 0), reverse=True)[:6]
                top_rows = []
                for r in weighted:
                    key = r.get("feature_key")
                    if key and features and key in features:
                        top_rows.append((key, features[key], r.get("reason")))
                if not top_rows:
                    top_rows = [("N/A", "N/A", "No top-weighted feature mapped")]
                for k, v, reason in top_rows:
                    st.markdown(f"- <span class='mono'>{k}</span>: <b>{v}</b> — {reason}", unsafe_allow_html=True)

                st.markdown("<div class='hr'></div>", unsafe_allow_html=True)
                st.markdown("### Extracted 25 Features (Preview)")
                feat_df = pd.DataFrame([features])
                cols = list(feat_df.columns)
                show_cols = cols[:18]
                st.dataframe(feat_df[show_cols], height=220, use_container_width=True)

            entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "url": url_to_scan,
                "threat_pct": float(threat_pct),
                "severity": severity,
                "reasons": explain.get("reasons", []),
                "features": features,
            }
            add_history(entry)

            st.success("تم حفظ نتيجة الفحص ضمن سجل الجلسة.")

elif nav == "📊 Threat Intelligence & Statistics Dashboard":
    st.subheader("📊 Threat Intelligence & Statistics Dashboard")
    st.caption("Session-level Threat Intelligence with KPIs, charts, and searchable history.")

    hist = st.session_history
    if not hist:
        st.info("لا توجد نتائج ضمن هذه الجلسة حتى الآن. انتقل لقسم Live URL Threat Scanner أولاً.")
    else:
        df = pd.DataFrame(hist)
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
        df["url_host"] = df["url"].apply(lambda x: analyzer.extract_domain(x).get("domain", "") if x else "")

        sev_order = ["Critical Block", "High", "Medium", "Low", "Safe"]
        sev_counts = df["severity"].value_counts().to_dict()
        total = len(df)

        def sev_to_type(sev):
            if sev == "Critical Block":
                return "Malicious / Blocked (Critical)"
            if sev == "High":
                return "Suspicious (High)"
            if sev == "Medium":
                return "Suspicious (Medium)"
            if sev == "Low":
                return "Low-risk (Possible)"
            return "Safe"

        df["threat_type"] = df["severity"].apply(sev_to_type)

        kpi_col1, kpi_col2, kpi_col3, kpi_col4 = st.columns(4)
        blocked_count = sum(1 for s in df["severity"] if s == "Critical Block")
        avg_threat = float(df["threat_pct"].mean())
        critical_count = blocked_count

        with kpi_col1:
            st.markdown(
                '<div class="card-soft"><div class="muted small">Total Scanned</div><div style="font-size:2rem; font-weight:900;">{}</div></div>'.format(total),
                unsafe_allow_html=True
            )
        with kpi_col2:
            st.markdown(
                '<div class="card-soft"><div class="muted small">Blocked</div><div style="font-size:2rem; font-weight:900;">{}</div></div>'.format(blocked_count),
                unsafe_allow_html=True
            )
        with kpi_col3:
            st.markdown(
                '<div class="card-soft"><div class="muted small">Avg Threat %</div><div style="font-size:2rem; font-weight:900;">{:.1f}%</div></div>'.format(avg_threat),
                unsafe_allow_html=True
            )
        with kpi_col4:
            st.markdown(
                '<div class="card-soft"><div class="muted small">Critical Threats</div><div style="font-size:2rem; font-weight:900;">{}</div></div>'.format(critical_count),
                unsafe_allow_html=True
            )

        pie_df = pd.DataFrame({"severity": df["severity"].value_counts().index, "count": df["severity"].value_counts().values})
        pie_df["severity"] = pd.Categorical(pie_df["severity"], categories=sev_order, ordered=True)
        pie_df = pie_df.sort_values("severity")

        p1, p2 = st.columns([1.25, 1.15])
        with p1:
            st.markdown("### Severity Distribution")
            fig = px.pie(
                pie_df,
                names="severity",
                values="count",
                hole=0.35,
                color="severity",
                color_discrete_map={
                    "Safe": "#7CFF6B",
                    "Low": "#00E5FF",
                    "Medium": "#D4AF37",
                    "High": "#F472B6",
                    "Critical Block": "#FF0048",
                },
            )
            fig.update_layout(template=plot_template, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)

        with p2:
            st.markdown("### Threat Level Summary (Avg)")
            avg_fig = plot_threat_gauge(avg_threat, "Medium" if avg_threat < 40 else "High" if avg_threat < 70 else "Critical Block")
            st.plotly_chart(avg_fig, use_container_width=True)

        reason_list = []
        for r in df["reasons"]:
            for item in (r or []):
                reason_list.append(item.get("reason", "Unknown"))
        reason_series = pd.Series(reason_list)
        reason_counts = reason_series.value_counts().head(8)

        c1, c2 = st.columns([1.15, 1.2])
        with c1:
            st.markdown("### Top Block/Threat Reasons (Frequency)")
            if len(reason_counts) == 0:
                st.info("لا توجد بيانات أسباب في سجل الجلسة.")
            else:
                fig = px.bar(
                    x=reason_counts.index,
                    y=reason_counts.values,
                    labels={"x": "Reason", "y": "Count"},
                    template=plot_template,
                )
                fig.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    height=360,
                )
                fig.update_traces(marker_color="#00E5FF")
                st.plotly_chart(fig, use_container_width=True)

        with c2:
            st.markdown("### Domain Age Trend (Malicious vs Safe)")
            if "features" in df.columns:
                ages = []
                labels = []
                for item in df["features"]:
                    if not item:
                        continue
                    age_days = item.get("domain_age_days", None)
                    if age_days is None:
                        continue
                    ages.append(float(age_days))
                    labels.append(item.get("label_hint", ""))

                if len(ages) < 2:
                    st.info("لا توجد أعمار نطاق كافية في سجل الجلسة.")
                else:
                    fig = px.scatter(
                        df,
                        x="threat_pct",
                        y=df["features"].apply(lambda x: (x or {}).get("domain_age_days", np.nan)),
                        color="severity",
                        color_discrete_map={
                            "Safe": "#7CFF6B",
                            "Low": "#00E5FF",
                            "Medium": "#D4AF37",
                            "High": "#F472B6",
                            "Critical Block": "#FF0048",
                        },
                        labels={"x": "Threat %", "y": "Domain Age (days)"},
                    )
                    fig.update_layout(template=plot_template, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=360)
                    st.plotly_chart(fig, use_container_width=True)

        st.markdown("<div class='hr'></div>", unsafe_allow_html=True)

        st.markdown("### Session History (Search & Filter)")
        with st.form("history_filter_form", clear_on_submit=False):
            q = st.text_input("ابحث عن رابط/نطاق", value="")
            sev_filter = st.multiselect("Severity Filter", options=sev_order, default=sev_order)
            min_threat = st.slider("Minimum Threat %", 0, 100, 0, step=1)

            submitted = st.form_submit_button("Apply Filters")

        if submitted or True:
            fdf = df.copy()
            if q.strip():
                q_lower = q.strip().lower()
                fdf = fdf[
                    fdf["url"].astype(str).str.lower().str.contains(q_lower)
                    | fdf["url_host"].astype(str).str.lower().str.contains(q_lower)
                ]
            fdf = fdf[fdf["severity"].isin(sev_filter)]
            fdf = fdf[fdf["threat_pct"] >= min_threat]

            if fdf.empty:
                st.warning("لا نتائج مطابقة للبحث/الفلاتر.")
            else:
                show_cols = ["timestamp", "url_host", "url", "threat_pct", "severity"]
                st.dataframe(fdf[show_cols].sort_values("timestamp", ascending=False), use_container_width=True, height=360)

elif nav == "📱 Quishing QR & Bulk CSV Scanner":
    st.subheader("📱 Quishing QR & Bulk CSV Scanner")
    st.caption("Upload QR image to decode URL, or upload CSV for bulk scanning.")

    tab1, tab2 = st.tabs(["🔳 QR Code Scanner", "📄 Bulk CSV Scanner"])

    with tab1:
        st.markdown("### QR Decoder → Extract URL → Analyze")
        qr_file = st.file_uploader("ارفع صورة QR Code", type=["png", "jpg", "jpeg", "webp"], accept_multiple_files=False)

        if qr_file:
            img = Image.open(qr_file).convert("RGB")
            st.image(img, caption="Uploaded QR Image", use_container_width=True)

            decode_btn = st.button("Decode & Scan", use_container_width=True)
            if decode_btn:
                try:
                    import cv2
                    from pyzbar.pyzbar import decode as zbar_decode
                except Exception:
                    st.error("تعذر تفعيل فك QR. يرجى التأكد من مكتبات pyzbar/opencv في المتطلبات.")
                    st.stop()

                arr = np.array(img)
                bgr = cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)
                decoded = zbar_decode(bgr)

                if not decoded:
                    st.error("لم يتم العثور على نص/رابط داخل QR.")
                else:
                    payloads = [d.data.decode("utf-8", errors="ignore") for d in decoded if d.data]
                    st.success(f"تم استخراج {len(payloads)} نتيجة من QR.")

                    for p in payloads:
                        url_to_scan = normalize_url(p)
                        with st.spinner("Analyzing extracted QR URL ..."):
                            threat_pct, severity, explain, features, artifacts = analyzer.analyze_url_with_explanations(
                                url=url_to_scan,
                                ml_engine=ml_engine,
                            )
                        st.markdown("### QR Extracted Link Result")
                        st.markdown(f"- <span class='mono'>Extracted URL:</span> <b class='mono'>{url_to_scan}</b>", unsafe_allow_html=True)
                        st.markdown(severity_badge(severity), unsafe_allow_html=True)
                        st.plotly_chart(plot_threat_gauge(threat_pct, severity), use_container_width=True)

                        entry = {
                            "timestamp": datetime.utcnow().isoformat(),
                            "url": url_to_scan,
                            "threat_pct": float(threat_pct),
                            "severity": severity,
                            "reasons": explain.get("reasons", []),
                            "features": features,
                        }
                        add_history(entry)

    with tab2:
        st.markdown("### Upload CSV → Bulk Scan → Download Results")
        st.markdown("<div class='muted small'>Expected CSV columns: url (or URL). You can upload any file; we will attempt to detect the column.</div>", unsafe_allow_html=True)

        csv_file = st.file_uploader("ارفع ملف CSV يحتوي روابط", type=["csv"], accept_multiple_files=False)

        if csv_file:
            df_in = pd.read_csv(csv_file)
            st.write(df_in.head(5))

            url_col = None
            for c in df_in.columns:
                if c.strip().lower() in ["url", "uri", "link", "href", "destination", "malicious_url"]:
                    url_col = c
                    break
            if url_col is None:
                url_col = df_in.columns[0]

            st.info(f"Using URL column: <b>{url_col}</b>", unsafe_allow_html=True)

            run_btn = st.button("Start Bulk Scan", use_container_width=True)
            if run_btn:
                results = []
                progress = st.progress(0)
                total = len(df_in)

                for i, row in enumerate(df_in.itertuples(index=False), start=1):
                    raw_url = getattr(row, url_col) if hasattr(row, url_col) else row[0]
                    url_to_scan = normalize_url(str(raw_url))
                    if not url_to_scan or url_to_scan.lower() == "nan":
                        results.append({
                            "input_url": raw_url,
                            "url": "",
                            "threat_pct": None,
                            "severity": "Unknown",
                            "reasons": "Invalid URL",
                        })
                        progress.progress(i / total)
                        continue

                    try:
                        threat_pct, severity, explain, features, artifacts = analyzer.analyze_url_with_explanations(
                            url=url_to_scan,
                            ml_engine=ml_engine,
                        )
                        reasons = explain.get("reasons", [])
                        reasons_text = " | ".join([f"{r.get('reason','')}(w={r.get('weight',0)})" for r in reasons[:6]])
                        results.append({
                            "input_url": raw_url,
                            "url": url_to_scan,
                            "threat_pct": float(threat_pct),
                            "severity": severity,
                            "reasons": reasons_text,
                        })

                        entry = {
                            "timestamp": datetime.utcnow().isoformat(),
                            "url": url_to_scan,
                            "threat_pct": float(threat_pct),
                            "severity": severity,
                            "reasons": explain.get("reasons", []),
                            "features": features,
                        }
                        add_history(entry)
                    except Exception as e:
                        results.append({
                            "input_url": raw_url,
                            "url": url_to_scan,
                            "threat_pct": None,
                            "severity": "Error",
                            "reasons": f"Exception: {str(e)}",
                        })

                    progress.progress(i / total)

                progress.empty()
                df_out = pd.DataFrame(results)
                st.success("Bulk scan completed!")

                st.dataframe(df_out, use_container_width=True, height=380)

                out_buf = io.StringIO()
                df_out.to_csv(out_buf, index=False)
                st.download_button(
                    label="Download Results CSV",
                    data=out_buf.getvalue().encode("utf-8"),
                    file_name=f"bisha_cyberguard_bulk_results_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    use_container_width=True,
                )

elif nav == "🏛️ Academic Metrics & ML Architecture":
    st.subheader("🏛️ Academic Metrics & ML Architecture")
    st.caption("Confusion Matrix, ROC-AUC, and Feature Importance for the trained RandomForest model.")

    metrics = ml_engine.get_metrics()
    if not metrics:
        st.warning("Model metrics غير متاحة حالياً.")
    else:
        mcol1, mcol2 = st.columns(2)
        with mcol1:
            st.markdown("### Model Performance Metrics")
            mt = metrics.get("report", {})
            if mt:
                st.markdown(
                    f"""
                <div class="card-soft">
                  <div><b>Accuracy:</b> {mt.get('accuracy', 'N/A')}</div>
                  <div><b>Precision:</b> {mt.get('precision', 'N/A')}</div>
                  <div><b>Recall:</b> {mt.get('recall', 'N/A')}</div>
                  <div><b>F1-Score:</b> {mt.get('f1', 'N/A')}</div>
                </div>
                """,
                    unsafe_allow_html=True,
                )

            st.markdown("### ROC-AUC")
            st.plotly_chart(metrics.get("roc_fig"), use_container_width=True)

        with mcol2:
            st.markdown("### Confusion Matrix")
            st.plotly_chart(metrics.get("cm_fig"), use_container_width=True)

            st.markdown("### Feature Importance (Top Signals)")
            fi_df = metrics.get("feature_importance_df", pd.DataFrame())
            if fi_df is None or fi_df.empty:
                st.info("No feature importance available.")
            else:
                fi_df = fi_df.sort_values("importance", ascending=False).head(15)
                st.dataframe(fi_df, use_container_width=True, height=260)

        st.markdown("<div class='hr'></div>", unsafe_allow_html=True)
        st.markdown("## Explainability: Shannon Entropy & Decision Logic")
        st.markdown(
            """
            <div class="card-soft">
            <div><b>Shannon Entropy (الحساسية للتوزيع العشوائي للحروف):</b></div>
            <div class="muted small">
            تمثل درجة تعقيد/عشوائية الرابط. رياضيًا:
            </div>
            <div class="mono small" style="margin-top:10px;">
            H = - Σ (p_i * log2(p_i))
            </div>
            <div class="muted small" style="margin-top:10px;">
            حيث p_i هي احتمالية ظهور الرمز i ضمن نص الرابط/الدومين.
            </div>

            <div class="muted small" style="margin-top:10px;">
            كما يتم دمج إشارات أخرى (HTTPS/Domain Age/Punycode/Port/IP/Pattern Indicators)
            مع <b>RandomForestClassifier</b> لتوليد درجة الخطورة.
            </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("<div class='hr'></div>", unsafe_allow_html=True)
        st.markdown("### Model Details (Hybrid Pipeline)")
        st.markdown(
            """
            <div class="card-soft">
              <div><b>Hybrid Signals:</b></div>
              <ul class="muted small">
                <li>Static URL/Text features (length, entropy, char distributions)</li>
                <li>Transport & SSL signals (scheme, TLS reachable, certificate presence)</li>
                <li>WHOIS-derived intelligence (registration date/age/registrar) with fallback</li>
                <li>Saudi domain spoofing detector (Typosquatting + Homograph distance)</li>
                <li>Explainable reasons with weighted contributions</li>
              </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

elif nav == "🎓 Project Overview & Documentation":
    st.subheader("🎓 Project Overview & Documentation")
    st.caption("System architecture, goals, methodology, and academic documentation.")

    col1, col2 = st.columns([1.1, 1.2])
    with col1:
        st.markdown("## أهداف المشروع")
        st.markdown(
            """
            <div class="card-soft">
              <ul class="muted small">
                <li>تحويل فحص الروابط من تحليل يدوي إلى <b>منظومة ذكية</b> تعتمد على التعلم الآلي الهجين.</li>
                <li>خفض المخاطر عبر كشف التصيد والروابط الخبيثة والتمويه (Punycode/Patterns/IP).</li>
                <li>إتاحة تفسير واضح للأسباب التي تقود للقرار باستخدام Explainable AI.</li>
                <li>دمج ذكاء WHOIS/SSL مع fallback لضمان الاستمرارية حتى عند انقطاع الاتصال الخارجي.</li>
                <li>حماية النطاقات السعودية الحساسة من Typosquatting/Homograph عبر مسافة التشابه النصي.</li>
              </ul>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.markdown("## المنهجية والمعمارية")
        st.markdown(
            """
            <div class="card-soft">
              <div><b>Pipeline:</b></div>
              <ol class="muted small">
                <li>استخراج خصائص URL (25 Feature signals).</li>
                <li>جمع إشارات WHOIS/SSL (إن توفر) مع fallback عند فشل الاستعلام.</li>
                <li>Saudi Domain Spoofing Detector (Similarity + Critical raise).</li>
                <li>التنبؤ باستخدام RandomForestClassifier.</li>
                <li>توليد أسباب تفسيرية وزيادة/خفض درجة الخطورة بناءً على الأوزان.</li>
              </ol>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col2:
        st.markdown("## بيانات المشروع والهوية الأكاديمية")
        st.markdown(
            f"""
            <div class="card-soft">
              <div><b>الجامعة:</b> جامعة بيشة</div>
              <div><b>الكلية:</b> كلية الحاسبات وتقنية المعلومات</div>
              <div><b>القسم:</b> قسم الأمن السيبراني</div>
              <div class="hr"></div>
              <div><b>الطالب:</b> {st.session_state.get('student_name','')}</div>
              <div><b>الرقم الجامعي:</b> {st.session_state.get('student_id','')}</div>
              <div><b>المشرف:</b> {st.session_state.get('supervisor_name','')}</div>
              <div><b>العام الجامعي:</b> {st.session_state.get('academic_year','')}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("## مكونات النظام")
        st.markdown(
            """
            <div class="card-soft">
              <ul class="muted small">
                <li><b>Core Analyzer:</b> استخراج الخصائص + WHOIS/SSL + Explainable reasons</li>
                <li><b>ML Engine:</b> تدريب/حفظ نموذج RandomForest + Metrics</li>
                <li><b>Streamlit UI:</b> 5 قوائم + Day/Night + الرسوم والتاريخ</li>
              </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("## ملاحظة حول التشغيل في Streamlit Cloud")
        st.markdown(
            """
            <div class="card-soft">
              <div class="muted small">
              تم تصميم الاستعلامات الخارجية (WHOIS/SSL) بحيث لا تتسبب بتوقف النظام عند فشل الشبكة.
              في حال تعذر WHOIS، يتم الاعتماد على Features نصية/لغوية والنموذج المدرب.
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
