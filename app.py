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
    page_title="Bisha CyberGuard | منصة كشف التصيد والروابط الخبيثة",
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
    st.session_state["session_history"] = []

if "model_ready" not in st.session_state:
    st.session_state["model_ready"] = False

# تثبيت البيانات الأكاديمية للباحث بشكل افتراضي
if "student_name" not in st.session_state:
    st.session_state["student_name"] = os.environ.get("STUDENT_NAME", "عبدالرحمن ماجد آل حامد")
if "student_id" not in st.session_state:
    st.session_state["student_id"] = os.environ.get("STUDENT_ID", "441000000")
if "supervisor_name" not in st.session_state:
    st.session_state["supervisor_name"] = os.environ.get("SUPERVISOR_NAME", "د. مشرف المشروع")
if "academic_year" not in st.session_state:
    st.session_state["academic_year"] = os.environ.get("ACADEMIC_YEAR", "2025 / 2026")


# -----------------------------
# Theme system (CSS + Plotly template)
# -----------------------------
DARK_BG = "#0A0F1D"
LIGHT_BG = "#F4F6F9"

NEON = "#00E5FF"
NEON_2 = "#7CFF6B"
GOLD = "#D4AF37"
INK = "#0F172A"

PLOTLY_DARK_TEMPLATE = "plotly_dark"
PLOTLY_LIGHT_TEMPLATE = "plotly_white"

# COCO Brown (Bisha-inspired) for Light mode
COCO_BROWN = "#3B1F14"
COCO_BROWN_2 = "#24110A"


def apply_theme(theme: str):
    st.session_state["theme"] = theme

    if theme == "dark":
        bg = DARK_BG
        sidebar_bg = "#0D1426"
        fg = "#EAF2FF"
        muted = "#93A4C7"
        border = "rgba(0, 229, 255, 0.25)"
        card = "rgba(17, 26, 46, 0.85)"
        card2 = "rgba(0, 229, 255, 0.08)"
        gold = GOLD
        neon = NEON
        neon2 = NEON_2
        plot_template = PLOTLY_DARK_TEMPLATE

        banner_bg = "linear-gradient(135deg, #0D1527 0%, #162447 100%)"
        banner_border = "rgba(0, 229, 255, 0.4)"
        button_bg_css = "linear-gradient(135deg, rgba(0, 229, 255, 0.20) 0%, rgba(212, 175, 55, 0.15) 100%)"
        button_fg_css = "#EAF2FF"
        button_border_css = "rgba(0, 229, 255, 0.45)"
        input_bg = "#111A2E"

        # ألوان الشارات في الوضع الليلي
        safe_fg, low_fg, med_fg, high_fg, crit_fg = "#7CFF6B", "#00E5FF", "#FFE066", "#F472B6", "#FF4D79"

    else:
        bg = LIGHT_BG
        sidebar_bg = "#FFFFFF"
        fg = "#1E293B"
        muted = "#475569"
        border = "rgba(212, 175, 55, 0.35)"
        card = "#FFFFFF"
        card2 = "rgba(212, 175, 55, 0.10)"
        gold = GOLD
        neon = COCO_BROWN
        neon2 = "#0F766E"
        plot_template = PLOTLY_LIGHT_TEMPLATE

        banner_bg = f"linear-gradient(135deg, {COCO_BROWN} 0%, {COCO_BROWN_2} 100%)"
        banner_border = GOLD
        button_bg_css = f"linear-gradient(135deg, {COCO_BROWN} 0%, {COCO_BROWN_2} 100%)"
        button_fg_css = "#FFFFFF"
        button_border_css = GOLD
        input_bg = "#FFFFFF"

        # ألوان الشارات في الوضع النهاري (تباين عالٍ للقراءة الواضحة)
        safe_fg, low_fg, med_fg, high_fg, crit_fg = "#15803D", "#0369A1", "#92400E", "#9D174D", "#B91C1C"

    css = f"""
    <style>
      @import url('https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&display=swap');

      html, body, [class*="css"] {{
        font-family: 'Cairo', -apple-system, BlinkMacSystemFont, sans-serif;
      }}

      .stApp, .main {{
        background-color: {bg} !important;
        color: {fg} !important;
      }}

      section[data-testid="stSidebar"] {{
        background: {sidebar_bg} !important;
        color: {fg} !important;
        border-right: 1px solid {border} !important;
      }}

      /* البطاقة الأكاديمية الفخمة في القائمة الجانبية */
      .academic-id-card {{
        background: {banner_bg} !important;
        border: 1.5px solid {gold} !important;
        border-radius: 14px;
        padding: 18px 16px;
        color: #FFFFFF !important;
        box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        direction: rtl;
        text-align: right;
        margin-bottom: 12px;
      }}
      .academic-id-card .uni-title {{
        color: {gold};
        font-size: 0.85rem;
        font-weight: 700;
        letter-spacing: 0.3px;
        margin-bottom: 4px;
      }}
      .academic-id-card .dept-title {{
        color: rgba(255,255,255,0.85);
        font-size: 0.8rem;
        margin-bottom: 12px;
        padding-bottom: 10px;
        border-bottom: 1px solid rgba(212, 175, 55, 0.3);
      }}
      .academic-id-card .student-name {{
        font-size: 1.15rem;
        font-weight: 800;
        color: #FFFFFF;
        margin-bottom: 8px;
      }}
      .academic-id-card .meta-row {{
        display: flex;
        justify-content: space-between;
        font-size: 0.82rem;
        color: rgba(255,255,255,0.9);
        margin-top: 5px;
        background: rgba(0,0,0,0.2);
        padding: 5px 10px;
        border-radius: 6px;
      }}
      .academic-id-card .meta-label {{
        color: {gold};
        font-weight: 600;
      }}

      /* البانر العلوي الرئيسي (Hero Header) */
      .hero-banner {{
        background: {banner_bg};
        border: 1.5px solid {banner_border};
        border-radius: 16px;
        padding: 22px 28px;
        color: #FFFFFF;
        box-shadow: 0 12px 30px rgba(0,0,0,0.12);
        margin-bottom: 18px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 16px;
      }}
      .hero-title {{
        font-size: 1.85rem;
        font-weight: 800;
        color: #FFFFFF;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 10px;
      }}
      .hero-subtitle {{
        color: rgba(255,255,255,0.85);
        font-size: 0.95rem;
        margin-top: 4px;
      }}
      .hero-badge {{
        background: rgba(212, 175, 55, 0.18);
        border: 1px solid {gold};
        color: {gold};
        padding: 6px 14px;
        border-radius: 999px;
        font-size: 0.85rem;
        font-weight: 700;
      }}

      /* البطاقات الداخلية */
      .card-soft {{
        background: {card} !important;
        border: 1px solid {border} !important;
        border-radius: 14px;
        padding: 18px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.04);
      }}
      .card-accent {{
        background: {card2} !important;
        border: 1px solid {border} !important;
        border-radius: 14px;
        padding: 16px;
      }}

      /* توحيد تنسيق الأزرار ومنع التعارض */
      div.stButton > button, div.stDownloadButton > button, div[data-testid="stFormSubmitButton"] > button {{
        background: {button_bg_css} !important;
        color: {button_fg_css} !important;
        border: 1px solid {button_border_css} !important;
        border-radius: 10px !important;
        padding: 0.55rem 1rem !important;
        font-weight: 700 !important;
        transition: all 0.25s ease-in-out !important;
        box-shadow: 0 4px 10px rgba(0,0,0,0.10) !important;
        unicode-bidi: plaintext !important;
      }}
      div.stButton > button *, div.stDownloadButton > button *, div[data-testid="stFormSubmitButton"] > button * {{
        color: {button_fg_css} !important;
        font-weight: 700 !important;
      }}
      div.stButton > button:hover, div.stDownloadButton > button:hover, div[data-testid="stFormSubmitButton"] > button:hover {{
        border-color: {gold} !important;
        box-shadow: 0 6px 16px rgba(212, 175, 55, 0.30) !important;
        transform: translateY(-1px);
      }}

      /* حقول الإدخال */
      .stTextInput > div > div > input {{
        border: 1.5px solid {border} !important;
        background: {input_bg} !important;
        color: {fg} !important;
        border-radius: 10px !important;
        padding: 0.55rem 0.85rem !important;
      }}
      .stTextInput label, .stSelectbox label, .stMultiSelect label, .stSlider label, .stRadio label {{
        color: {fg} !important;
        font-weight: 700 !important;
      }}

      .stMarkdown, h1, h2, h3, h4 {{
        color: {fg} !important;
      }}
      .muted {{
        color: {muted} !important;
      }}

      /* شارات التقييم (Badges) */
      .badge {{
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 8px 16px;
        border-radius: 999px;
        border: 1px solid {border};
        background: {card};
        font-weight: 800;
        font-size: 0.95rem;
      }}
      .danger, .critical {{
        background: rgba(239, 68, 68, 0.14) !important;
        border-color: rgba(239, 68, 68, 0.50) !important;
        color: {crit_fg} !important;
      }}
      .safe {{
        background: rgba(34, 197, 94, 0.14) !important;
        border-color: rgba(34, 197, 94, 0.45) !important;
        color: {safe_fg} !important;
      }}
      .low {{
        background: rgba(14, 165, 233, 0.14) !important;
        border-color: rgba(14, 165, 233, 0.45) !important;
        color: {low_fg} !important;
      }}
      .medium {{
        background: rgba(212, 175, 55, 0.16) !important;
        border-color: rgba(212, 175, 55, 0.55) !important;
        color: {med_fg} !important;
      }}
      .high {{
        background: rgba(236, 72, 153, 0.14) !important;
        border-color: rgba(236, 72, 153, 0.45) !important;
        color: {high_fg} !important;
      }}

      .mono {{
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      }}
      .small {{
        font-size: 0.92rem;
      }}
      .hr {{
        height: 1px;
        background: {border};
        margin: 16px 0;
      }}
    </style>
    """
    st.markdown(css, unsafe_allow_html=True)
    return plot_template, fg, muted, neon, neon2, gold


plot_template, FG, MUTED, NEON_COLOR, NEON2_COLOR, GOLD_COLOR = apply_theme(st.session_state["theme"])

# -----------------------------
# Sidebar: Academic Identity Card & Navigation
# -----------------------------
with st.sidebar:
    # بطاقة الهوية الأكاديمية الثابتة والرسومية
    st.markdown(
        """
        <div class="academic-id-card">
          <div class="uni-title">🏛️ جامعة بيشة · University of Bisha</div>
          <div class="dept-title">كلية الحاسبات وتقنية المعلومات · قسم الأمن السيبراني</div>
          <div class="student-name">🎓 م/ عبدالرحمن ماجد آل حامد</div>
          <div class="meta-row">
            <span class="meta-label">الرقم الجامعي:</span>
            <span class="mono">447807111</span>
          </div>
          <div class="meta-row">
            <span class="meta-label">إشراف:</span>
            <span>د. منير عبدالله القباطي</span>
          </div>
          <div class="meta-row">
            <span class="meta-label">العام الجامعي:</span>
            <span class="mono">2026 / 2025</span>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("<div class='hr'></div>", unsafe_allow_html=True)
    st.markdown("<div style='font-weight: 700; margin-bottom: 8px;'>🧭 أقسام المنصة (Navigation)</div>", unsafe_allow_html=True)

    # تهيئة الحالة الافتراضية للقسم النشط
    if "nav_section" not in st.session_state:
        st.session_state["nav_section"] = "🔍 Live URL Threat Scanner"

    # خيارات القائمة مع أيقونات تعبيرية واضحة
    nav_options = {
        "🔍 Live URL Threat Scanner": "🔍 الفحص الفوري للروابط",
        "📊 Threat Intelligence & Statistics Dashboard": "📊 استخبارات وإحصائيات التهديدات",
        "📱 Quishing QR & Bulk CSV Scanner": "📱 فحص QR وملفات CSV الجماعية",
        "🏛️ Academic Metrics & ML Architecture": "🏛️ المقاييس ومعمارية الذكاء الاصطناعي",
        "🎓 Project Overview & Documentation": "🎓 التوثيق الأكاديمي للمشروع"
    }

    # رسم الأزرار الفعلية للتنقل
    for key, label in nav_options.items():
        is_active = st.session_state["nav_section"] == key
        btn_type = "primary" if is_active else "secondary"
        if st.button(label, key=f"nav_btn_{key}", use_container_width=True, type=btn_type):
            st.session_state["nav_section"] = key
            st.rerun()

    nav = st.session_state["nav_section"]
# -----------------------------
# Hero Header + Centered University Branding
# -----------------------------
st.markdown(
    f"""
    <div class="hero-banner" style="flex-direction: column; text-align: center; justify-content: center; gap: 10px;">
      <div style="display: flex; align-items: center; justify-content: center; gap: 12px;">
        <span style="font-size: 2.2rem;">🏛️</span>
        <div>
          <div class="hero-title" style="justify-content: center;">Bisha CyberGuard</div>
          <div class="hero-subtitle">جامعة بيشة · كلية الحاسبات وتقنية المعلومات · قسم الأمن السيبراني</div>
        </div>
      </div>
      <div style="margin-top: 4px; font-size: 0.9rem; color: rgba(255,255,255,0.85);">
        Intelligent Phishing & Malicious URL Detection Platform
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# زر تبديل الوضع في منتصف الشاشة بشكل أنيق تحت البانر
col_center1, col_center2, col_center3 = st.columns([1, 1.5, 1])
with col_center2:
    new_theme = "light" if st.session_state["theme"] == "dark" else "dark"
    btn_label = "☀️ العودة للوضع الأكاديمي النهاري" if st.session_state["theme"] == "dark" else "🌙 التبديل إلى وضع مركز العمليات (SOC Dark)"
    if st.button(btn_label, use_container_width=True):
        apply_theme(new_theme)
        st.rerun()

st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
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
        "Safe": "#22C55E" if st.session_state["theme"] == "light" else "#7CFF6B",
        "Low": "#0284C7" if st.session_state["theme"] == "light" else "#00E5FF",
        "Medium": "#D4AF37",
        "High": "#DB2777" if st.session_state["theme"] == "light" else "#F472B6",
        "Critical Block": "#DC2626" if st.session_state["theme"] == "light" else "#FF0048",
    }
    bar_color = color_map.get(severity, "#D4AF37")
    bg_color = "rgba(0,0,0,0.04)" if st.session_state["theme"] == "light" else "rgba(255,255,255,0.06)"
    num_color = FG

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=threat_pct,
            number={"suffix": "%", "font": {"color": num_color, "size": 42}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": MUTED},
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
        margin=dict(l=15, r=15, t=25, b=10),
        height=300,
    )
    return fig


def add_history(entry: dict):
    st.session_state["session_history"].insert(0, entry)
    st.session_state["session_history"] = st.session_state["session_history"][:50]


def compute_reason_table(reasons: list):
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
    st.markdown('<div class="card-soft">', unsafe_allow_html=True)
    st.subheader("🔍 الفحص الفوري للروابط والتهديدات | Live URL Threat Scanner")
    st.caption("محرك هجين يجمع 25 خاصية مع التعلم الآلي التفسيري (Explainable AI) وفحص شهادات SSL وسجلات WHOIS.")

    # محاذاة حقل الإدخال مع زر الفحص على سطر واحد
    colA, colB = st.columns([3.2, 1])
    with colA:
        default_url_val = st.session_state.get("url_to_scan", "")
        url_input = st.text_input(
            "أدخل الرابط المراد فحصه:",
            value=default_url_val,
            placeholder="مثال: https://ub.edu.sa أو رابط يشتبه بأنه تصيد/خبيث",
        )
    with colB:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        scan_btn = st.button("🚀 ابدأ الفحص الآن", use_container_width=True)

    st.markdown("<div style='margin-top: 8px; margin-bottom: 6px; font-weight:600; font-size:0.9rem;' class='muted'>أمثلة سريعة للتجربة (Demo Cases):</div>", unsafe_allow_html=True)
    demo_col1, demo_col2, demo_col3, demo_col4 = st.columns(4)

    demo_urls = [
        "https://www.ub.edu.sa",
        "https://ub-portal-login.com",
        "http://93.184.216.34/login",
        "https://xn--pple-43d.com",
    ]
    # إصلاح تداخل الحروف العربية والإنجليزية
    demo_labels = [
        "✅ رابط سليم (جامعة بيشة)",
        "🎣 رابط تصيد (Demo)",
        "🌐 عنوان IP مباشر (Demo)",
        "🎭 خداع Punycode (Demo)",
    ]

    for i, (lbl, du) in enumerate(zip(demo_labels, demo_urls)):
        c = [demo_col1, demo_col2, demo_col3, demo_col4][i]
        if c.button(lbl, use_container_width=True):
            st.session_state["url_to_scan"] = du
            st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)

    if scan_btn or ("url_to_scan" in st.session_state and url_input):
        url_to_scan = normalize_url(url_input)
        st.session_state["url_to_scan"] = url_to_scan

        if not url_to_scan:
            st.warning("يرجى إدخال رابط صحيح.")
        else:
            with st.spinner("جاري فحص الرابط واستخراج الخصائص والتحليل بالذكاء الاصطناعي..."):
                # استدعاء دالة الفحص الأساسية لتوليد النتيجة والـ artifacts
               result = analyzer.analyze_url_with_explanations(url_to_scan)
               artifacts = result.get("artifacts", {})
               explain = result.get("explain", {})
               threat_pct = result.get("threat_pct", 0.0)
               severity = result.get("severity", "Safe")
               features = result.get("features", {})

            # استخراج البيانات الأساسية من النتيجة ومن الـ artifacts بأمان
            whois_info = artifacts.get("whois", {})
            domain_info = artifacts.get("domain_info", {})
            ssl_info = artifacts.get("ssl", {})
            st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)
            dec_col1, dec_col2 = st.columns(2)

            with dec_col1:
                st.markdown('<div class="card-soft">', unsafe_allow_html=True)
                st.markdown("### 🎯 مؤشر الخطورة (Threat Score)")
                
                display_threat_pct = 5.0 if str(severity).lower() in ["safe", "آمن"] else threat_pct
                
                st.plotly_chart(plot_threat_gauge(display_threat_pct, severity), use_container_width=True)

                st.markdown("### 🛡️ مستوى التهديد (Risk Level)")
                st.markdown(severity_badge(severity), unsafe_allow_html=True)

                st.markdown("<div class='hr'></div>", unsafe_allow_html=True)
                st.markdown("### 🌐 استخبارات النطاق وشهادة الأمان (WHOIS & SSL)")
                st.markdown('</div>', unsafe_allow_html=True)

            with dec_col2:
                st.markdown('<div class="card-soft">', unsafe_allow_html=True)
                domain = domain_info.get("domain", "") if isinstance(domain_info, dict) else ""
                reg_date = whois_info.get("registration_date")
                registrar = whois_info.get("registrar")
                whois_status = whois_info.get("status", "unknown")
                domain_age_days = whois_info.get("age_days")
                ssl_status = ssl_info.get("tls_status", "unknown")
                ssl_issuer = ssl_info.get("issuer", "")
                ssl_not_after = ssl_info.get("not_after", "")
                
                st.markdown(f"**النطاق:** `{domain}`")
                st.markdown(f"**عمر النطاق:** {domain_age_days} يوم")
                st.markdown(f"**المسجل:** {registrar}")
                st.markdown(f"**حالة شهادة SSL:** {ssl_status}")
                st.markdown('</div>', unsafe_allow_html=True)

            # التحذيرات الأمنية
            age_warning = False
            if isinstance(domain_age_days, (int, float)) and domain_age_days < 30:
                age_warning = True
            if whois_status == "unavailable":
                age_warning = True

            if age_warning:
                st.markdown('<div class="card-accent critical" style="padding:12px; border-radius:12px; margin-bottom:12px;">', unsafe_allow_html=True)
                st.markdown("**⚠️ تنبيه أمني:**")
                if whois_status == "unavailable":
                   st.markdown("- تعذر التحقق المباشر من سجلات WHOIS (تم تفعيل التحليل الاحتياطي Fallback).")
                if isinstance(domain_age_days, (int, float)) and domain_age_days < 30:
                   st.markdown(f"- عمر النطاق حديث جداً: **{int(domain_age_days)} يوم** (< 30 يوماً).")
        st.markdown("</div>", unsafe_allow_html=True)

        # استخراج الدومين بأمان
        domain = domain if 'domain' in locals() and domain else domain_info.get("domain") or whois_info.get("domain") or "N/A"
        st.markdown(f"""
        <div class="mono small" style="line-height: 1.8;">
            <div><b>Domain:</b> {domain}</div>
            <div><b>WHOIS Status:</b> {whois_status}</div>
            <div><b>Registration Date:</b> {reg_date or "N/A"}</div>
            <div><b>Age:</b> {whois_info.get('age_years', 'N/A')}</div>
            <div><b>Registrar:</b> {registrar or "N/A"}</div>
            <div><b>SSL/TLS:</b> {ssl_status}</div>
            <div><b>Issuer:</b> {ssl_issuer or "N/A"}</div>
            <div><b>Cert Not After:</b> {ssl_not_after or "N/A"}</div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown('<div class="card-soft">', unsafe_allow_html=True)
    st.markdown("### 🧠 التفسير الذكي للقرار (Explainable AI Reasons)")
    reasons = explain.get("reasons", []) if 'explain' in locals() and isinstance(explain, dict) else []
    if not reasons:
        st.info("لم يتم رصد مؤشرات خطورة عالية في القواعد التفسيرية؛ الرابط يبدو آمناً.")
    else:
        df = compute_reason_table(reasons)
        st.dataframe(df, use_container_width=True, height=240)

        st.markdown("<div class='hr'></div>", unsafe_allow_html=True)

        st.markdown("### 📌 أبرز الإشارات المؤثرة (Feature Snapshot)")
    weighted = sorted(reasons, key=lambda x: x.get("weight", 0), reverse=True)[:6]
    top_rows = []
    for r in weighted:
     key = r.get("feature_key")
     if key and features and key in features:
       top_rows.append((key, features[key], r.get("reason")))
     if not top_rows:
                    top_rows = [("Safe_Profile", "Verified", "لا توجد إشارات خبيثة مهيمنة")]
     for k, v, reason in top_rows:
                    st.markdown(f"- <span class='mono'>{k}</span>: <b>{v}</b> — {reason}", unsafe_allow_html=True)

    st.markdown("<div class='hr'></div>", unsafe_allow_html=True)
    st.markdown("### 📊 مصفوفة الخصائص الـ 25 المستخرجة (25 Features Preview)")
    safe_features = features if 'features' in locals() and isinstance(features, dict) and features else {}
    if safe_features:
        feat_df = pd.DataFrame([safe_features])
        cols = list(feat_df.columns)
        show_cols = cols[:18]
        st.dataframe(feat_df[show_cols], height=200, use_container_width=True)
    else:
        st.info("لا توجد مصفوفة خصائص مستخرجة حالياً.")

    # حفظ السجل
    if 'url_to_scan' in locals() and url_to_scan:
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "url": url_to_scan,
            "threat_pct": float(threat_pct) if 'threat_pct' in locals() else 0.0,
            "severity": severity if 'severity' in locals() else "Safe",
            "reasons": explain.get("reasons", []) if 'explain' in locals() and isinstance(explain, dict) else [],
            "features": safe_features,
        }
        add_history(entry)
        st.success("تم حفظ نتيجة الفحص ضمن سجل الجلسة بنجاح.")
    elif nav == "📊 Threat Intelligence & Statistics Dashboard":
     st.subheader("📊 لوحة استخبارات التهديدات والإحصائيات | Threat Intelligence Dashboard")
     st.caption("تحليلات الجلسة المباشرة، مؤشرات الأداء الرئيسية (KPIs)، وسجل الفحص القابل للبحث والفلترة.")

    hist = st.session_state["session_history"]
    if not hist:
        st.info("لا توجد نتائج ضمن هذه الجلسة حتى الآن. انتقل لقسم Live URL Threat Scanner وافحص رابطاً أولاً.")
    else:
        df = pd.DataFrame(hist)
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
        df["url_host"] = df["url"].apply(lambda x: analyzer.extract_domain(x).get("domain", "") if x else "")

        sev_order = ["Critical Block", "High", "Medium", "Low", "Safe"]
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
                f'<div class="card-soft"><div class="muted small">إجمالي الروابط المفحوصة</div><div style="font-size:2rem; font-weight:900;">{total}</div></div>',
                unsafe_allow_html=True,
            )
        with kpi_col2:
            st.markdown(
                f'<div class="card-soft"><div class="muted small">روابط محظورة (Blocked)</div><div style="font-size:2rem; font-weight:900;">{blocked_count}</div></div>',
                unsafe_allow_html=True,
            )
        with kpi_col3:
            st.markdown(
                f'<div class="card-soft"><div class="muted small">متوسط نسبة الخطورة</div><div style="font-size:2rem; font-weight:900;">{avg_threat:.1f}%</div></div>',
                unsafe_allow_html=True,
            )
        with kpi_col4:
            st.markdown(
                f'<div class="card-soft"><div class="muted small">تهديدات حرجة (Critical)</div><div style="font-size:2rem; font-weight:900;">{critical_count}</div></div>',
                unsafe_allow_html=True,
            )

        pie_df = pd.DataFrame({"severity": df["severity"].value_counts().index, "count": df["severity"].value_counts().values})
        pie_df["severity"] = pd.Categorical(pie_df["severity"], categories=sev_order, ordered=True)
        pie_df = pie_df.sort_values("severity")

        p1, p2 = st.columns([1.25, 1.15])
        with p1:
            st.markdown("### توزيع مستويات الخطورة (Severity Distribution)")
            fig = px.pie(
                pie_df,
                names="severity",
                values="count",
                hole=0.35,
                color="severity",
                color_discrete_map={
                    "Safe": "#22C55E",
                    "Low": "#00E5FF",
                    "Medium": "#D4AF37",
                    "High": "#F472B6",
                    "Critical Block": "#FF0048",
                },
            )
            fig.update_layout(template=plot_template, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)

        with p2:
            st.markdown("### متوسط مستوى التهديد للجلسة")
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
            st.markdown("### أكثر أسباب الحظر تكراراً")
            if len(reason_counts) == 0:
                st.info("لا توجد بيانات أسباب في سجل الجلسة.")
            else:
                fig = px.bar(
                    x=reason_counts.index,
                    y=reason_counts.values,
                    labels={"x": "السبب", "y": "التكرار"},
                    template=plot_template,
                )
                fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=360)
                fig.update_traces(marker_color=GOLD_COLOR)
                st.plotly_chart(fig, use_container_width=True)

        with c2:
            st.markdown("### علاقة عمر النطاق بنسبة الخطورة")
            if "features" in df.columns:
                ages = []
                for item in df["features"]:
                    if item and item.get("domain_age_days") is not None:
                        ages.append(float(item.get("domain_age_days")))

                if len(ages) < 2:
                    st.info("لا توجد أعمار نطاق كافية في سجل الجلسة لرسم المخطط.")
                else:
                    fig = px.scatter(
                        df,
                        x="threat_pct",
                        y=df["features"].apply(lambda x: (x or {}).get("domain_age_days", np.nan)),
                        color="severity",
                        color_discrete_map={
                            "Safe": "#22C55E",
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

        st.markdown("### 🗂️ سجل الجلسة (البحث والفلترة)")
        with st.form("history_filter_form", clear_on_submit=False):
            q = st.text_input("ابحث عن رابط أو نطاق:", value="")
            sev_filter = st.multiselect("فلترة حسب المستوى (Severity):", options=sev_order, default=sev_order)
            min_threat = st.slider("الحد الأدنى لنسبة الخطورة %:", 0, 100, 0, step=1)
            submitted = st.form_submit_button("تطبيق الفلاتر")

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
                st.warning("لا توجد نتائج مطابقة للبحث أو الفلاتر المحددة.")
            else:
                show_cols = ["timestamp", "url_host", "url", "threat_pct", "severity"]
                st.dataframe(fdf[show_cols].sort_values("timestamp", ascending=False), use_container_width=True, height=360)

elif nav == "📱 Quishing QR & Bulk CSV Scanner":
    st.subheader("📱 فحص رموز QR (Quishing) والفحص الجماعي لملفات CSV")
    st.caption("استخراج الروابط المخفية داخل صور الباركود QR وفحصها، أو رفع ملف CSV لفحص آلاف الروابط دفعة واحدة.")

    tab1, tab2 = st.tabs(["🔳 فاحص رموز QR Code", "📄 الفحص الجماعي Bulk CSV"])

    with tab1:
        st.markdown('<div class="card-soft">', unsafe_allow_html=True)
        st.markdown("### 📷 فك تشفير QR Code واستخراج الرابط لتحليله")
        qr_file = st.file_uploader("ارفع صورة تحتوي على رمز QR Code", type=["png", "jpg", "jpeg", "webp"], accept_multiple_files=False)

        if qr_file:
            img = Image.open(qr_file).convert("RGB")
            st.image(img, caption="صورة QR المرفوعة", width=280)

            decode_btn = st.button("🔍 فك الرمز وبدء الفحص الأمني", use_container_width=True)
            if decode_btn:
                try:
                    import cv2
                    from pyzbar.pyzbar import decode as zbar_decode
                except Exception:
                    st.error("تعذر تفعيل فك QR. يرجى التأكد من تثبيت مكتبات pyzbar و opencv.")
                    st.stop()

                arr = np.array(img)
                bgr = cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)
                decoded = zbar_decode(bgr)

                if not decoded:
                    st.error("لم يتم العثور على نص أو رابط داخل صورة QR.")
                else:
                    payloads = [d.data.decode("utf-8", errors="ignore") for d in decoded if d.data]
                    st.success(f"تم استخراج {len(payloads)} رابط من رمز QR بنجاح.")

                    for p in payloads:
                        url_to_scan = normalize_url(p)
                        with st.spinner("جاري تحليل الرابط المستخرج من QR ..."):
                            threat_pct, severity, explain, features, artifacts = analyzer.analyze_url_with_explanations(
                                url=url_to_scan,
                                ml_engine=ml_engine,
                            )
                        st.markdown("### نتيجة فحص رابط QR")
                        st.markdown(f"- <span class='mono'>الرابط المستخرج:</span> <b class='mono'>{url_to_scan}</b>", unsafe_allow_html=True)
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
        st.markdown("</div>", unsafe_allow_html=True)

    with tab2:
        st.markdown('<div class="card-soft">', unsafe_allow_html=True)
        st.markdown("### 📄 رفع ملف CSV للفحص الجماعي وتحميل التقرير")
        st.markdown("<div class='muted small'>يتعرف النظام تلقائياً على عمود الروابط (url, link, uri, href).</div>", unsafe_allow_html=True)

        csv_file = st.file_uploader("ارفع ملف CSV يحتوي على قائمة الروابط", type=["csv"], accept_multiple_files=False)

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

            st.info(f"تم اختيار عمود الروابط تلقائياً: **{url_col}**")

            run_btn = st.button("🚀 بدء الفحص الجماعي (Start Bulk Scan)", use_container_width=True)
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
                st.success("اكتمل الفحص الجماعي بنجاح!")

                st.dataframe(df_out, use_container_width=True, height=380)

                out_buf = io.StringIO()
                df_out.to_csv(out_buf, index=False)
                st.download_button(
                    label="📥 تحميل تقرير النتائج (Download CSV)",
                    data=out_buf.getvalue().encode("utf-8"),
                    file_name=f"bisha_cyberguard_bulk_results_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    use_container_width=True,
                )
        st.markdown("</div>", unsafe_allow_html=True)

elif nav == "🏛️ Academic Metrics & ML Architecture":
    st.subheader("🏛️ المقاييس الأكاديمية ومعمارية التعلم الآلي | Academic Metrics & ML Architecture")
    st.caption("تقييم أداء نموذج RandomForest، مصفوفة الارتباك (Confusion Matrix)، منحنى ROC-AUC، وأهمية الخصائص.")

    metrics = ml_engine.get_metrics()
    if not metrics:
        st.warning("بيانات مقاييس النموذج غير متاحة حالياً.")
    else:
        mcol1, mcol2 = st.columns(2)
        with mcol1:
            st.markdown("### 📈 مقاييس كفاءة النموذج (Performance Metrics)")
            mt = metrics.get("report", {})
            if mt:
                st.markdown(
                    f"""
                    <div class="card-soft" style="line-height: 2;">
                      <div><b>Accuracy (الدقة الكلية):</b> <span class="mono">{mt.get('accuracy', 'N/A')}</span></div>
                      <div><b>Precision (دقة التنبؤ الإيجابي):</b> <span class="mono">{mt.get('precision', 'N/A')}</span></div>
                      <div><b>Recall (الحساسية / الاستدعاء):</b> <span class="mono">{mt.get('recall', 'N/A')}</span></div>
                      <div><b>F1-Score (المتوسط التوافقي):</b> <span class="mono">{mt.get('f1', 'N/A')}</span></div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            st.markdown("### منحنى ROC-AUC")
            st.plotly_chart(metrics.get("roc_fig"), use_container_width=True)

        with mcol2:
            st.markdown("### مصفوفة الارتباك (Confusion Matrix)")
            st.plotly_chart(metrics.get("cm_fig"), use_container_width=True)

            st.markdown("### ترتيب أهمية الخصائص (Feature Importance)")
            fi_df = metrics.get("feature_importance_df", pd.DataFrame())
            if fi_df is None or fi_df.empty:
                st.info("No feature importance available.")
            else:
                fi_df = fi_df.sort_values("importance", ascending=False).head(15)
                st.dataframe(fi_df, use_container_width=True, height=260)

        st.markdown("<div class='hr'></div>", unsafe_allow_html=True)
        st.markdown("## 📐 الأساس الرياضي: إنتروبيا شانون (Shannon Entropy) ومنطق القرار")
        st.markdown(
            """
            <div class="card-soft">
              <div><b>Shannon Entropy (قياس العشوائية اللغوية في الروابط الخبيثة):</b></div>
              <div class="muted small" style="margin-top:6px;">
              تُستخدم لقياس درجة تعقيد وعشوائية الحروف داخل النطاق والرابط (حيث تميل روابط التصيد المولدة آلياً DGA إلى امتلاك إنتروبيا مرتفعة). وتُحسب رياضياً عبر المعادلة:
              </div>
              <div class="mono" style="margin:12px 0; padding:10px; background:rgba(212,175,55,0.1); border-radius:8px; text-align:center; font-weight:700;">
              H(X) = - Σ P(x_i) * log2 P(x_i)
              </div>
              <div class="muted small">
          st.markdown("حيث تمثل <b>P(x_i)</b> احتمالية تكرار الحرف أو الرمز داخل نص الرابط، ويتم دمج هذا المؤشر مع 24 خاصية أخرى داخل مصنف <b>RandomForestClassifier</b>.")
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

elif nav == "🎓 Project Overview & Documentation":
    st.subheader("🎓 التوثيق الأكاديمي ونظرة عامة على المشروع | Project Documentation")
    st.caption("الأهداف البحثية، المنهجية العلمية، ومعمارية النظام المطور في قسم الأمن السيبراني بجامعة بيشة.")

    col1, col2 = st.columns([1.2, 1])

    with col1:
        st.markdown("## 🎯 أهداف المشروع البحثية")
        st.markdown(
            """
            <div class="card-soft">
                <ul class="muted small" style="line-height: 1.9;">
                    <li><b>منظومة ذكية استباقية:</b> تحويل فحص الروابط من تحليل يدوي تقليدي إلى كشف استباقي يعتمد على التعلم الآلي الهجين.</li>
                    <li><b>رفع دقة الكشف عن هجمات التصيد (Phishing):</b> كشف محاولات التمويه البصري (Punycode / Homograph) وعناوين IP المباشرة.</li>
                    <li><b>تطبيق مفهوم الذكاء الاصطناعي القابل للتفسير (Explainable AI):</b> توضيح الأسباب التقنية والأوزان التي أدت لحظر الرابط.</li>
                    <li><b>دمج استخبارات النطاقات (WHOIS & SSL/TLS):</b> مع آلية استمرارية (Resilient Fallback) لضمان عمل المنصة في كافة الظروف.</li>
                    <li><b>حماية النطاقات الوطنية والأكاديمية السعودية من انتحال الهوية:</b> عبر خوارزميات التشابه النصي (Typosquatting).</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("## ⚙️ منهجية العمل (System Pipeline)")
        st.markdown(
            """
            <div class="card-soft">
                <ol class="muted small" style="line-height: 1.9;">
                    <li><b>استخلاص الخصائص (Feature Extraction):</b> استخراج 25 إشارة هيكلية وإحصائية ولغوية من الرابط.</li>
                    <li><b>التحقق الشبكي (Network & SSL Intelligence):</b> فحص شهادة التشفير وعمر النطاق عبر WHOIS.</li>
                    <li><b>كاشف الانتحال (Spoofing Detector):</b> قياس المسافة النصية لكشف محاولات تقليد النطاقات الرسمية.</li>
                    <li><b>التصنيف الهجين (Hybrid ML Classification):</b> تمرير المتجهات إلى نموذج RandomForest المدرب.</li>
                    <li><b>التفسير الموزون (Weighted Explainability):</b> إصدار الحكم النهائي مع جدول تفصيلي للأوزان والأسباب.</li>
                </ol>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown("## 🏛️ البطاقة التعريفية للمشروع")
        st.markdown(
            """
            <div class="card-soft" style="line-height: 2;">
                <div><b>الجامعة:</b> جامعة بيشة (University of Bisha)</div>
                <div><b>الكلية:</b> كلية الحاسبات وتقنية المعلومات</div>
                <div><b>القسم العلمي:</b> قسم الأمن السيبراني (Cybersecurity)</div>
                <div class="hr"></div>
                <div><b>إعداد الباحث:</b> م/ عبدالرحمن ماجد آل حامد</div>
                <div><b>الرقم الجامعي:</b> <span class="mono">447807111</span></div>
                <div><b>إشراف:</b> د. منير عبدالله القباطي</div>
                <div><b>العام الجامعي:</b> <span class="mono">2025 / 2026</span></div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown("## 🧩 المكونات البرمجية للنظام")
        st.markdown(
            """
            <div class="card-soft">
              <ul class="muted small" style="line-height: 1.9;">
                <li><b>Core Analyzer (`core/analyzer.py`):</b> محرك تحليل الروابط واستخراج الـ 25 خاصية وفحص WHOIS/SSL وبناء التفسيرات.</li>
                <li><b>ML Engine (`model/ml_engine.py`):</b> إدارة تدريب نموذج الغابات العشوائية (RandomForest) وحساب مقاييس الأداء الأكاديمية.</li>
                <li><b>Interactive UI (`app.py`):</b> واجهة تفاعلية ثنائية النمط (الأكاديمي النهاري / مركز العمليات الليلي SOC) مدعومة بلوحات قياس Plotly.</li>
              </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )