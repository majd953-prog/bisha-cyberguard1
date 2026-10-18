# Bisha CyberGuard: Intelligent Phishing & Malicious URL Detection Platform

**جامعة بيشة (University of Bisha)**  
**كلية الحاسبات وتقنية المعلومات (College of Computing and Information Technology)**  
**قسم الأمن السيبراني (Department of Cybersecurity)**  

## Overview
Bisha CyberGuard منصة ذكية لاكتشاف وتحليل الروابط الاحتيالية والمهددة للأنظمة باستخدام:
- **تعلم آلي هجين (Hybrid ML)** عبر استخراج **25 خاصية** من الرابط.
- **تحليل قابل للتفسير (Explainable AI)** يوضح الأسباب التي تقود لقرار الحظر/التحذير.
- **WHOIS Intelligence + SSL/TLS checks** مع **Fallback ذكي** لتجنب توقف المنصة عند انقطاع الاتصال الخارجي.
- **Saudi Domain Spoofing Detector** لاكتشاف هجمات Typosquatting وHomograph على نطاقات سعودية حساسة عبر **Levenshtein Similarity**.

## Project Navigation (5 Menus)
1. 🔍 **Live URL Threat Scanner**
   - فحص رابط واحد مع عداد Plotly Gauge + شارة مستوى الخطورة.
   - بطاقة “لماذا تم حظر هذا الرابط؟” مع جدول أسباب ترجيحية.
   - عمر النطاق + WHOIS/SSL intelligence.

2. 📊 **Threat Intelligence & Statistics Dashboard**
   - لوحات KPI
   - مخططات توزيع التهديدات والأسباب الأكثر تكراراً
   - سجل تاريخي للنتائج داخل الجلسة مع بحث وتصفية.

3. 📱 **Quishing QR & Bulk CSV Scanner**
   - فك QR واستخراج الرابط ثم تحليله
   - رفع ملف CSV لفحص دفعة واحدة وتنزيل النتائج

4. 🏛️ **Academic Metrics & ML Architecture**
   - Confusion Matrix
   - ROC-AUC curve
   - Accuracy/Precision/Recall/F1
   - Feature Importance

5. 🎓 **Project Overview & Documentation**
   - أهداف المشروع ومنهجية البحث والمعمارية

## How the ML Model Works
- يتم تدريب نموذج **RandomForestClassifier** تلقائياً عند أول تشغيل إذا لم يوجد ملف النموذج.
- يتم حفظ النموذج محلياً داخل `model/` لتسريع تشغيل Streamlit.
- التدريب هنا مُبني على بيانات توليد/وسم (heuristic-synthetic) لضمان عمل المنصة مباشرة على Streamlit Cloud بدون تعقيد جلب قواعد بيانات خارجية.

## Running Locally
### 1) Install
```bash
pip install -r requirements.txt
