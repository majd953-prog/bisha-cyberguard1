import os
import re
import math
import ssl
import socket
import unicodedata
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote

import numpy as np
import requests

try:
    import whois as whois_lib
except Exception:
    whois_lib = None


def safe_to_str(x):
    return "" if x is None else str(x)


class URLAnalyzer:
    """
    Enterprise Hybrid URL Threat Analyzer
    Compliant with OWASP Phishing Detection Guidelines, APWG Threat Indicators,
    and MITRE ATT&CK (T1566 - Phishing / Spearphishing Link).
    """

    def __init__(self):
        # 1) النطاقات الحساسة المستهدفة (وطنية وعالمية) لرصد الانتحال والتشابه
        self.saudi_targets = [
            # منصات حكومية وأكاديمية سعودية
            "ub.edu.sa", "absher.sa", "tawakkalna.gov.sa", "nafath.sa",
            "mcs.gov.sa", "sdaia.gov.sa", "zatca.gov.sa", "gosi.gov.sa",
            "moe.gov.sa", "moh.gov.sa", "hrsd.gov.sa", "najiz.sa",
            "balady.gov.sa", "sakani.sa", "ehsan.sa", "etimad.sa",
            # القطاع المالي والمصرفي
            "snb.com.sa", "alrajhibank.com.sa", "sabb.com.sa", "albilad.com",
            "alinma.com", "riyadbank.com", "anb.com.sa", "aljazirabank.com.sa",
            "stcpay.com.sa", "urpay.com.sa", "mada.com.sa",
            # خدمات لوجستية واتصالات
            "splonline.com.sa", "stc.com.sa", "mobily.com.sa", "zain.com",
            "aramex.com", "dhl.com", "fedex.com", "smsaexpress.com",
            # منصات تقنية ومالية عالمية كبرى
            "google.com", "apple.com", "microsoft.com", "paypal.com",
            "amazon.com", "netflix.com", "facebook.com", "instagram.com",
            "whatsapp.com", "telegram.org", "linkedin.com", "github.com",
            "dropbox.com", "adobe.com", "outlook.com", "office.com",
            "icloud.com", "binance.com", "visa.com", "mastercard.com",
        ]

        # 2) القائمة البيضاء الصارمة للنطاقات الجذرية الموثوقة
        self.whitelisted_domains = {
            "ub.edu.sa", "absher.sa", "tawakkalna.gov.sa", "nafath.sa",
            "mcs.gov.sa", "sdaia.gov.sa", "zatca.gov.sa", "gosi.gov.sa",
            "moe.gov.sa", "moh.gov.sa", "hrsd.gov.sa", "najiz.sa",
            "snb.com.sa", "alrajhibank.com.sa", "sabb.com.sa", "albilad.com",
            "alinma.com", "riyadbank.com", "anb.com.sa", "stcpay.com.sa",
            "splonline.com.sa", "stc.com.sa", "google.com", "apple.com",
            "microsoft.com", "paypal.com", "amazon.com", "github.com",
            "linkedin.com", "office.com", "outlook.com", "cloudflare.com",
        }

        # البادئات الرسمية للنطاقات الحكومية والأكاديمية السعودية
        self.trusted_saudi_suffixes = (".gov.sa", ".edu.sa", ".med.sa", ".mil.sa")

        # امتدادات النطاقات المركبة (Second-Level Domains) لعزل النطاق الجذري بدقة
        self.compound_tlds = {
            "com.sa", "edu.sa", "gov.sa", "net.sa", "org.sa", "med.sa", "pub.sa", "sch.sa",
            "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.jp", "co.in", "com.br", "com.eg"
        }

        # الكلمات المفتاحية للهندسة الاجتماعية والتصيد (مصنفة حسب الخطورة)
        self.suspicious_substrings = [
            "login", "signin", "sign-in", "log-in", "verify", "verification",
            "secure", "account", "bank", "banking", "payment", "support",
            "session", "update", "otp", "password", "credential", "wallet",
            "confirm", "recover", "recovery", "unlock", "suspend", "suspended",
            "authenticate", "auth", "webscr", "cmd", "invoice", "billing",
            "refund", "prize", "reward", "free", "bonus", "urgent", "kyc"
        ]

        # الامتدادات عالية الخطورة حسب تقارير APWG و Spamhaus
        self.high_risk_tlds = {
            "xyz", "top", "click", "link", "icu", "buzz", "tk", "ml", "ga",
            "cf", "gq", "work", "loan", "kim", "country", "stream", "download",
            "xin", "gdn", "racing", "jetzt", "win", "bid", "vip", "rest",
            "fit", "zip", "mov", "cam", "cfd", "sbs", "quest", "cyou"
        }

        # امتدادات الملفات التنفيذية والخبيثة
        self.dangerous_extensions = (
            ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
            ".jar", ".apk", ".msi", ".dmg", ".iso", ".hta", ".lnK"
        )

        # مختصرات الروابط الشهيرة
        self.shorteners = {
            "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "is.gd",
            "cutt.ly", "buff.ly", "adf.ly", "rb.gy", "shorturl.at",
            "tiny.cc", "bit.do", "rebrand.ly", "bl.ink", "v.gd", "qr.ae"
        }

        self.suspicious_symbols = ["@", "-", "_", "—", "~", "%", "=", "?", "&"]

        # ذاكرة تخزين مؤقت داخلية لمنع استدعاء WHOIS مرتين لنفس النطاق
        self._whois_cache = {}

    # ---------------------------------------------------------
    # 1. المدخل الرئيسي للتحليل والتفسير الهجين
    # ---------------------------------------------------------
    def analyze_url_with_explanations(self, url: str, ml_engine):
        url = (url or "").strip()
        if not url:
            raise ValueError("Empty URL")

        domain_obj = self.extract_domain(url)
        domain = domain_obj.get("domain", "")
        host = domain_obj.get("host", "")
        tld = domain_obj.get("tld", "")
        scheme = domain_obj.get("scheme", "")

        normalized_u = url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else "https://" + url
        parsed = urlparse(normalized_u)
        path = parsed.path or ""
        query = parsed.query or ""

        # استخراج الـ 25 خاصية القياسية لنموذج التعلم الآلي
        features = self.extract_25_features(
            url=url, domain=domain, host=host, tld=tld,
            scheme=scheme, path=path, query=query, ml_engine=ml_engine
        )

        # التنبؤ الاحتمالي من نموذج RandomForest (0.0 -> 100.0)
        threat_prob = float(ml_engine.predict_threat_probability(features))
        ml_pct = max(0.0, min(100.0, threat_prob * 100.0))

        # جمع استخبارات الشبكة (WHOIS + SSL/TLS)
        artifacts = self.collect_artifacts(url=url, domain=domain)

        # بناء القواعد التفسيرية وحساب الدرجة الهجينة المحكمة
        reasons, final_pct, forced_severity = self.build_reasons_and_adjustment(
            url=url,
            features=features,
            domain=domain,
            scheme=scheme,
            ml_engine=ml_engine,
            ml_pct=ml_pct,
            artifacts=artifacts,
        )

        if forced_severity == "Safe":
            severity = "Safe"
            threat_pct = round(min(final_pct, 8.0), 1)
        elif forced_severity is not None:
            severity = forced_severity
            threat_pct = round(max(final_pct, 92.0), 1)
        else:
            threat_pct = round(max(0.0, min(100.0, float(final_pct))), 1)
            severity = self.severity_from_pct(threat_pct)

        explain = {
            "threat_prob_raw": round(threat_prob, 4),
            "ml_score_pct": round(ml_pct, 1),
            "threat_pct": threat_pct,
            "severity": severity,
            "reasons": reasons,
            "scoring_methodology": "OWASP / MITRE ATT&CK Hybrid Weighted Ensemble (ML + Heuristics)",
        }
        return threat_pct, severity, explain, features, artifacts

    # ---------------------------------------------------------
    # 2. محلل النطاقات الذكي (PSL-Aware Domain Extractor)
    # ---------------------------------------------------------
    def extract_domain(self, url: str):
        u = (url or "").strip()
        if not u:
            return {"domain": "", "host": "", "tld": "", "scheme": "", "subdomain": ""}

        has_scheme = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u)
        parsed = urlparse(u if has_scheme else "https://" + u)
        scheme = (parsed.scheme or "").lower() if has_scheme else "http"

        raw_netloc = (parsed.netloc or "").lower()
        # في حال وجود رمز @ الخداعي (user:pass@realhost.com)، النطاق الفعلي هو ما بعد آخر @
        actual_host = raw_netloc.split("@")[-1]
        host = actual_host.split(":")[0].strip(".")

        # التحقق مما إذا كان الـ Host عنوان IPv4
        if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host):
            return {"domain": host, "host": host, "tld": "", "scheme": scheme, "subdomain": ""}

        parts = [p for p in host.split(".") if p]
        if len(parts) < 2:
            return {"domain": host, "host": host, "tld": "", "scheme": scheme, "subdomain": ""}

        last_two = ".".join(parts[-2:])
        if last_two in self.compound_tlds and len(parts) >= 3:
            tld = last_two
            domain = ".".join(parts[-3:])
            subdomain = ".".join(parts[:-3])
        else:
            tld = parts[-1]
            domain = ".".join(parts[-2:])
            subdomain = ".".join(parts[:-2])

        return {
            "domain": domain,
            "host": host,
            "tld": tld,
            "scheme": scheme,
            "subdomain": subdomain,
        }

    def is_trusted_domain(self, domain: str, host: str) -> bool:
        d = (domain or "").lower().strip()
        h = (host or "").lower().strip()
        if not d:
            return False
        if d in self.whitelisted_domains or h in self.whitelisted_domains:
            return True
        if d.endswith(self.trusted_saudi_suffixes) or h.endswith(self.trusted_saudi_suffixes):
            return True
        return False

    # ---------------------------------------------------------
    # 3. استخراج الـ 25 خاصية القياسية لنموذج الـ ML
    # ---------------------------------------------------------
    def extract_25_features(self, url: str, domain: str, host: str, tld: str, scheme: str, path: str, query: str, ml_engine=None):
        u = url or ""
        host = host or ""
        domain = domain or ""
        scheme = scheme or ""
        path = path or ""
        query = query or ""

        L = len(u)
        L_host = len(host)
        L_domain = len(domain)
        L_path = len(path)
        L_query = len(query)

        has_https = 1 if re.match(r"^https://", u, re.IGNORECASE) else 0
        has_http = 1 if re.match(r"^http://", u, re.IGNORECASE) else 0

        at_count = u.count("@")
        hyphen_count = u.count("-")
        underscore_count = u.count("_")
        digit_count = sum(c.isdigit() for c in u)
        alpha_count = sum(c.isalpha() for c in u)
        dot_count = u.count(".")

        ip_like = 1 if (
            re.search(r"(?:\d{1,3}\.){3}\d{1,3}", host)
            or re.search(r"0x[0-9a-fA-F]{2,}", host)
        ) else 0

        has_non_ascii = any(ord(c) > 127 for c in host)
        punycode = 1 if ("xn--" in u.lower() or has_non_ascii) else 0

        raw_netloc = urlparse(u if "://" in u else "https://" + u).netloc
        port_present = 1 if re.search(r":(?!80$|443$)\d{2,5}$", raw_netloc) else 0

        is_shortener = 1 if (domain in self.shorteners or host in self.shorteners) else 0

        lowered = unquote(u.lower())
        token_hits = sum(1 for t in self.suspicious_substrings if t in lowered)

        entropy = self.shannon_entropy(u)
        entropy_domain = self.shannon_entropy(domain) if domain else 0.0

        unique_chars = len(set(u)) if u else 0
        unique_chars_ratio = unique_chars / L if L > 0 else 0.0

        digits_ratio = digit_count / L if L > 0 else 0.0
        alpha_ratio = alpha_count / L if L > 0 else 0.0
        dots_ratio = dot_count / L if L > 0 else 0.0
        hyphen_ratio = hyphen_count / L if L > 0 else 0.0

        whois_age_days, _, _ = self.try_whois_age(domain)
        age_days = whois_age_days
        age_missing = 1 if whois_age_days is None else 0

        if self.is_trusted_domain(domain, host):
            saudi_spoof_score = 0.0
        else:
            saudi_spoof_score, _, _ = self.saudi_spoof_similarity(domain, host=host)

        features = {
            "url_length": L,
            "host_length": L_host,
            "domain_length": L_domain,
            "path_length": L_path,
            "query_length": L_query,
            "has_https": has_https,
            "has_http": has_http,
            "ip_address_like": ip_like,
            "punycode_present": punycode,
            "port_present": port_present,
            "shortener_present": is_shortener,
            "suspicious_token_hits": token_hits,
            "at_symbol_count": at_count,
            "hyphen_count": hyphen_count,
            "underscore_count": underscore_count,
            "digits_ratio": round(digits_ratio, 4),
            "alpha_ratio": round(alpha_ratio, 4),
            "dots_ratio": round(dots_ratio, 4),
            "hyphen_ratio": round(hyphen_ratio, 4),
            "url_entropy": round(entropy, 4),
            "domain_entropy": round(entropy_domain, 4),
            "unique_chars_ratio": round(unique_chars_ratio, 4),
            "domain_age_days": age_days if age_days is not None else -1,
            "domain_age_missing_flag": age_missing,
            "saudi_spoof_score": round(saudi_spoof_score, 4),
            "label_hint": "unknown",
        }

        for k, v in list(features.items()):
            if isinstance(v, bool):
                features[k] = 1 if v else 0
            elif v is None:
                features[k] = -1

        return features

    # ---------------------------------------------------------
    # 4. فحص WHOIS مع التخزين المؤقت الذكي (Cached WHOIS)
    # ---------------------------------------------------------
    def try_whois_age(self, domain: str):
        d = (domain or "").lower().strip()
        if not d or re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", d):
            return None, None, "unavailable"

        if d in self._whois_cache:
            cached = self._whois_cache[d]
            return cached["age_days"], cached["registrar"], cached["status"]

        if whois_lib is None:
            return None, None, "unavailable"

        try:
            w = whois_lib.whois(d)
            reg = getattr(w, "creation_date", None) or getattr(w, "creationdate", None)
            registrar = safe_to_str(getattr(w, "registrar", "")) or None

            reg_dt = None
            if isinstance(reg, list):
                valid_dates = [r for r in reg if isinstance(r, datetime)]
                if valid_dates:
                    reg_dt = min(
                        valid_dates,
                        key=lambda x: x.astimezone(timezone.utc) if x.tzinfo else x.replace(tzinfo=timezone.utc)
                    )
                elif reg:
                    reg_dt = reg[0]
            else:
                reg_dt = reg

            if not reg_dt:
                self._whois_cache[d] = {"age_days": None, "registrar": registrar, "status": "partial", "reg_iso": None}
                return None, registrar, "partial"

            if isinstance(reg_dt, datetime):
                reg_dt_utc = reg_dt.astimezone(timezone.utc) if reg_dt.tzinfo else reg_dt.replace(tzinfo=timezone.utc)
            else:
                try:
                    reg_dt_utc = datetime.fromisoformat(str(reg_dt)).replace(tzinfo=timezone.utc)
                except Exception:
                    self._whois_cache[d] = {"age_days": None, "registrar": registrar, "status": "partial", "reg_iso": None}
                    return None, registrar, "partial"

            age_days = max(0, int((datetime.now(timezone.utc) - reg_dt_utc).days))
            self._whois_cache[d] = {
                "age_days": age_days,
                "registrar": registrar,
                "status": "ok",
                "reg_iso": reg_dt_utc.isoformat(),
            }
            return age_days, registrar, "ok"
        except Exception:
            self._whois_cache[d] = {"age_days": None, "registrar": None, "status": "unavailable", "reg_iso": None}
            return None, None, "unavailable"

    # ---------------------------------------------------------
    # 5. جمع الأدلة الجنائية الرقمية (WHOIS + SSL Certificate)
    # ---------------------------------------------------------
    def collect_artifacts(self, url: str, domain: str):
        domain_obj = self.extract_domain(url)
        domain_name = domain_obj.get("domain", "")
        host = domain_obj.get("host", "")

        whois_info = {
            "status": "unavailable",
            "registration_date": None,
            "registrar": None,
            "age_days": None,
            "age_years": None,
        }

        if domain_name:
            age_days, registrar, status = self.try_whois_age(domain_name)
            cached = self._whois_cache.get(domain_name.lower(), {})
            whois_info.update({
                "status": status,
                "registration_date": cached.get("reg_iso"),
                "registrar": registrar,
                "age_days": age_days,
                "age_years": round(age_days / 365.25, 2) if isinstance(age_days, int) else None,
            })

        ssl_info = {
            "tls_status": "unknown",
            "issuer": None,
            "not_after": None,
            "days_to_expiry": None,
        }

        if host:
            try:
                parsed = urlparse(url if "://" in url else "https://" + url)
                port = parsed.port or 443
                server_name = host.split(":")[0]

                context = ssl.create_default_context()
                with socket.create_connection((server_name, port), timeout=4) as sock:
                    with context.wrap_socket(sock, server_hostname=server_name) as ssock:
                        cert = ssock.getpeercert()
                        who = cert.get("issuer", [])
                        if who:
                            parts = [f"{k}={v}" for item in who for k, v in item]
                            ssl_info["issuer"] = ", ".join(parts)

                        not_after = cert.get("notAfter")
                        ssl_info["not_after"] = not_after
                        ssl_info["tls_status"] = "present"

                        if not_after:
                            try:
                                exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                                ssl_info["days_to_expiry"] = (exp_dt - datetime.now(timezone.utc)).days
                            except Exception:
                                pass
            except Exception:
                ssl_info["tls_status"] = "unverified/unreachable"

        return {
            "domain": domain_obj,
            "whois": whois_info,
            "ssl": ssl_info,
        }

    # ---------------------------------------------------------
    # 6. تصنيف مستوى الخطورة القياسي (NIST / OWASP Mapping)
    # ---------------------------------------------------------
    def severity_from_pct(self, pct: float):
        if pct < 20.0:
            return "Safe"
        if pct < 40.0:
            return "Low"
        if pct < 65.0:
            return "Medium"
        if pct < 85.0:
            return "High"
        return "Critical Block"

    # ---------------------------------------------------------
    # 7. محرك القواعد التفسيرية والمعادلة الهجينة الدقيقة
    # ---------------------------------------------------------
    def build_reasons_and_adjustment(self, url: str, features: dict, domain: str, scheme: str, ml_engine=None, ml_pct: float = 0.0, artifacts: dict = None):
        reasons = []
        domain_obj = self.extract_domain(url)
        host = domain_obj.get("host", "")
        tld = domain_obj.get("tld", "")
        subdomain = domain_obj.get("subdomain", "")

        normalized_u = url if "://" in url else "https://" + url
        parsed = urlparse(normalized_u)
        path_lower = unquote((parsed.path or "").lower())
        query_lower = unquote((parsed.query or "").lower())

        # 🟢 1. فحص القائمة البيضاء الصارم (يستثنى только إذا لم يكن هناك خداع @ في الرابط)
        if self.is_trusted_domain(domain, host) and features.get("at_symbol_count", 0) == 0:
            return [], 2.0, "Safe"

        def add_reason(reason, weight, detail, feature_key=None):
            reasons.append({
                "reason": reason,
                "weight": float(weight),
                "detail": detail,
                "feature_key": feature_key,
            })

        critical_veto = False

        # 🔴 2. فحص انتحال النطاقات (Typosquatting / Homograph / Brand-in-Subdomain)
        saudi_score, target, mode = self.saudi_spoof_similarity(domain, host=host)
        if saudi_score >= 0.80:
            mode_ar = {
                "brand_in_subdomain": "إقحام اسم الجهة في النطاق الفرعي (Subdomain Spoofing)",
                "combo_squatting": "دمج اسم الجهة مع كلمات خداعية (Combo-squatting)",
                "homograph_proxy": "تمويه بصري للأحرف (Homograph Attack)",
                "typosquatting": "تلاعب إملائي بالنطاق (Typosquatting)",
            }.get(mode, mode)
            add_reason(
                f"انتحال هوية نطاق حساس ({target})",
                weight=45,
                detail=f"رصد {mode_ar} يستهدف النطاق الموثوق '{target}' بدرجة تطابق {saudi_score*100:.1f}%.",
                feature_key="saudi_spoof_score",
            )
            critical_veto = True
        elif saudi_score >= 0.70:
            add_reason(
                f"تشابه مريب مع نطاق معروف ({target})",
                weight=22,
                detail=f"النطاق يشبه '{target}' بنسبة {saudi_score*100:.1f}% ({mode}).",
                feature_key="saudi_spoof_score",
            )

        # 🔴 3. فحص Punycode / IDN Homograph
        if features.get("punycode_present", 0) == 1:
            add_reason(
                "هجوم التمويه الدولي للأحرف (IDN Punycode / Homograph)",
                weight=42,
                detail="استخدام ترميز 'xn--' أو أحرف غير لاتينية متشابهة بصرياً لخداع المستخدم.",
                feature_key="punycode_present",
            )
            critical_veto = True

        # 🔴 4. استخدام عنوان IP مباشر بدلاً من اسم نطاق
        if features.get("ip_address_like", 0) == 1:
            add_reason(
                "استضافة مباشرة عبر عنوان IP رقمي (MITRE T1566)",
                weight=34,
                detail="الروابط الشرعية تستخدم أسماء نطاقات مسجلة؛ استخدام IP مباشر مؤشر قوي على خادم تحكم أو تصيد مؤقت.",
                feature_key="ip_address_like",
            )
            if features.get("has_https", 0) == 0 or features.get("suspicious_token_hits", 0) >= 1:
                critical_veto = True

        # 🔴 5. رمز الخداع @ داخل الرابط (RFC 3986 Userinfo Obfuscation)
        if features.get("at_symbol_count", 0) >= 1:
            add_reason(
                "استخدام رمز '@' لتزييف هوية النطاق (URL Userinfo Spoofing)",
                weight=32,
                detail="المتصفح يتجاهل كل ما قبل '@' ويفتح النطاق الخبيث الذي يليه.",
                feature_key="at_symbol_count",
            )
            critical_veto = True

        # 🔴 6. ملفات تنفيذية خبيثة مباشرة في المسار
        if path_lower.endswith(self.dangerous_extensions):
            ext = "." + path_lower.split(".")[-1]
            add_reason(
                f"رصد حمولة ملف تنفيذي خطير ({ext})",
                weight=40,
                detail=f"الرابط يؤدي مباشرة إلى تنزيل ملف برمجي قابل للتنفيذ ({ext}) قد يحوي برمجية خبيثة.",
                feature_key="path_length",
            )
            critical_veto = True

        # 🟠 7. غياب التشفير HTTPS
        if features.get("has_https", 0) == 0:
            add_reason(
                "افتقار الرابط لبروتوكول التشفير الآمن (No HTTPS)",
                weight=16,
                detail=f"الاتصال يتم عبر بروتوكول غير مشفر ({scheme or 'http'}) مما يعرض البيانات للتنصت.",
                feature_key="has_https",
            )

        # 🟠 8. التحقق من شهادة SSL عند استخدام HTTPS
        if artifacts and isinstance(artifacts.get("ssl"), dict):
            tls_status = artifacts["ssl"].get("tls_status")
            days_exp = artifacts["ssl"].get("days_to_expiry")
            if features.get("has_https", 0) == 1 and tls_status == "unverified/unreachable":
                add_reason(
                    "فشل التحقق من موثوقية شهادة SSL/TLS",
                    weight=15,
                    detail="رغم كتابة https:// إلا أن الخادم لا يقدم شهادة SSL صالحة وموثقة.",
                    feature_key="has_https",
                )
            elif isinstance(days_exp, int) and days_exp < 0:
                add_reason(
                    "شهادة الأمان SSL منتهية الصلاحية",
                    weight=20,
                    detail="الشهادة الرقمية للنطاق منتهية الصلاحية.",
                    feature_key="has_https",
                )

        # 🟠 9. خدمات اختصار الروابط (URL Shorteners)
        if features.get("shortener_present", 0) == 1:
            add_reason(
                "إخفاء الوجهة النهائية عبر مُختصر روابط (URL Shortener)",
                weight=20,
                detail="تُستغل خدمات اختصار الروابط لتجاوز فلاتر البريد الإلكتروني وإخفاء نطاق التصيد الفعلي.",
                feature_key="shortener_present",
            )

        # 🟠 10. امتدادات النطاقات عالية الخطورة (High-Risk TLD)
        if tld in self.high_risk_tlds:
            add_reason(
                f"امتداد نطاق عالي الخطورة (.{tld})",
                weight=18,
                detail=f"الامتداد '.{tld}' مدرج ضمن أكثر النطاقات استغلالاً في حملات التصيد العشوائية حسب تقارير APWG.",
                feature_key="domain_length",
            )

        # 🟠 11. تعدد النطاقات الفرعية المفرط (Subdomain Chaining)
        sub_count = len([p for p in subdomain.split(".") if p]) if subdomain else 0
        if sub_count >= 3:
            add_reason(
                "تعميق مريب للنطاقات الفرعية (Deep Subdomain Chaining)",
                weight=16,
                detail=f"يحتوي الرابط على {sub_count} مستويات فرعية لإخفاء النطاق الأصلي على شاشات الهواتف.",
                feature_key="dots_ratio",
            )

        # 🟠 12. منفذ شبكي غير قياسي (Non-standard Port)
        if features.get("port_present", 0) == 1:
            add_reason(
                "الاتصال عبر منفذ شبكي غير قياسي (Non-Standard Port)",
                weight=18,
                detail="استخدام منفذ غير 80/443 يشير غالباً إلى خادم ويب مؤقت أو مخترق.",
                feature_key="port_present",
            )

        # 🟠 13. الكلمات المفتاحية للتصيد والهندسة الاجتماعية
        token_hits = features.get("suspicious_token_hits", 0)
        if token_hits >= 1:
            w = min(28, 10 + token_hits * 6)
            add_reason(
                "مؤشرات هندسة اجتماعية وكلمات استدراج",
                weight=w,
                detail=f"تم رصد {token_hits} من الكلمات المفتاحية المرتبطة بصفحات سرقة بيانات الاعتماد.",
                feature_key="suspicious_token_hits",
            )

        # 🟠 14. إعادة التوجيه المفتوحة (Open Redirect Pattern)
        if re.search(r"(?:redirect|url|next|return|goto|dest|continue)=https?%3a|https?://", query_lower):
            add_reason(
                "ثغرة إعادة توجيه خارجية (Open Redirect Parameter)",
                weight=22,
                detail="الرابط يمرر عنوان ويب خارجي داخل المعاملات لتحويل الضحية بعد النقر.",
                feature_key="query_length",
            )

        # 🟡 15. العشوائية الإحصائية العالية (Shannon Entropy / DGA)
        entropy = features.get("url_entropy", 0.0)
        dom_entropy = features.get("domain_entropy", 0.0)
        if entropy >= 4.2 or dom_entropy >= 3.7:
            add_reason(
                "ارتفاع العشوائية الإحصائية للأحرف (High Shannon Entropy)",
                weight=14,
                detail=f"إنتروبيا الرابط ({entropy:.2f}) والنطاق ({dom_entropy:.2f}) تشير إلى توليد خوارزمي عشوائي.",
                feature_key="url_entropy",
            )

        # 🟡 16. الإفراط في الشرطات (-) أو طول الرابط
        hyphen_count = features.get("hyphen_count", 0)
        if hyphen_count >= 3:
            add_reason(
                "كثافة غير طبيعية للشرطات الفاصلة (-)",
                weight=12 if hyphen_count < 6 else 18,
                detail=f"وجود {hyphen_count} شرطات في الرابط وهو نمط شائع في النطاقات المزيفة.",
                feature_key="hyphen_count",
            )

        L = features.get("url_length", 0)
        if L >= 120:
            add_reason(
                "طول مفرط للرابط لإخفاء المعاملات",
                weight=10 if L < 200 else 16,
                detail=f"طول الرابط ({L} حرفاً) يتجاوز المعدل الطبيعي للروابط المعيارية.",
                feature_key="url_length",
            )

        # 🔴/🟠 17. تحليل عمر النطاق عبر WHOIS
        age_days = features.get("domain_age_days", -1)
        age_missing = features.get("domain_age_missing_flag", 0)
        if age_missing == 1:
            add_reason(
                "حجب أو عدم توفر سجلات ملكية النطاق (WHOIS Unverified)",
                weight=10,
                detail="تعذر التحقق من تاريخ تسجيل النطاق، وتم تفعيل التقييم الاستدلالي البديل (Fallback).",
                feature_key="domain_age_missing_flag",
            )
        elif isinstance(age_days, (int, float)) and 0 <= age_days < 30:
            add_reason(
                "نطاق مسجل حديثاً جداً (Newly Registered Domain - NRD)",
                weight=26,
                detail=f"عمر النطاق {int(age_days)} يوم فقط (< 30 يوماً)، وهي سمة رئيسية لحملات التصيد الخاطفة.",
                feature_key="domain_age_days",
            )
        elif isinstance(age_days, (int, float)) and 30 <= age_days < 90:
            add_reason(
                "نطاق حديث العهد نسبياً",
                weight=12,
                detail=f"عمر النطاق {int(age_days)} يوماً (< 90 يوماً).",
                feature_key="domain_age_days",
            )

        # ---------------------------------------------------------
        # المعادلة الرياضية الموزونة لحساب النسبة النهائية (Hybrid Scoring)
        # ---------------------------------------------------------
        total_w = sum(r.get("weight", 0.0) for r in reasons)

        # تحويل مجموع أوزان القواعد إلى مقياس معياري (0 - 100) عبر دالة تشبع غير خطية
        # تضمن الدقة وعدم القفز العشوائي: وزن 25 ≈ 46%، وزن 50 ≈ 72%، وزن 80 ≈ 89%
        if total_w == 0:
            heuristic_pct = 4.0
        else:
            heuristic_pct = 100.0 * (1.0 - math.exp(-total_w / 38.0))

        # إذا كان النطاق قديماً وموثقاً (> 365 يوماً) ويملك HTTPS ولا توجد عليه إنذارات حرجة، نخفض احتمالية الإنذار الكاذب
        trust_discount = 0.0
        if (
            not critical_veto
            and isinstance(age_days, (int, float))
            and age_days >= 365
            and features.get("has_https", 0) == 1
            and total_w <= 15
        ):
            trust_discount = 18.0

        # دمج قرار نموذج التعلم الآلي (ML) مع محرك القواعد السيبراني (Heuristics)
        if total_w == 0:
            # عندما لا يرصد المحرك أي مخالفة قواعدية، نكبح جماح الـ ML لمنع الـ False Positives
            combined_pct = min(18.0, 0.25 * ml_pct + 4.0)
        else:
            combined_pct = (0.35 * ml_pct) + (0.65 * heuristic_pct)
            # إذا كانت القواعد صريحة وقوية، لا نسمح لنموذج الـ ML بخفض النتيجة دون حد الأمان
            combined_pct = max(combined_pct, heuristic_pct * 0.88)

        combined_pct = max(2.0, min(100.0, combined_pct - trust_discount))

        if critical_veto:
            final_pct = max(92.0, min(99.4, combined_pct, 90.0 + min(9.4, total_w * 0.08)))
            return reasons, final_pct, "Critical Block"

        return reasons, combined_pct, None

    # ---------------------------------------------------------
    # 8. حساب الإنتروبيا الإحصائية (Shannon Entropy)
    # ---------------------------------------------------------
    def shannon_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        s = str(s)
        L = len(s)
        if L == 0:
            return 0.0
        counts = {}
        for c in s:
            counts[c] = counts.get(c, 0) + 1
        ent = 0.0
        for k in counts.values():
            p = k / L
            if p > 0:
                ent -= p * math.log(p, 2)
        return float(ent)

    # ---------------------------------------------------------
    # 9. كاشف الانتحال والتشابه المتقدم (Multi-Layer Spoofing Engine)
    # ---------------------------------------------------------
    def _strip_tld(self, dom: str) -> str:
        parts = [p for p in dom.lower().split(".") if p]
        if len(parts) >= 3 and ".".join(parts[-2:]) in self.compound_tlds:
            return parts[-3]
        if len(parts) >= 2:
            return parts[-2]
        return dom.lower()

    def saudi_spoof_similarity(self, domain: str, host: str = ""):
        d = (domain or "").lower().strip()
        h = (host or d).lower().strip()
        if not d or self.is_trusted_domain(d, h):
            return 0.0, None, None

        d_label = self._strip_tld(d)
        sub_part = h[:-len(d)].strip(".") if h.endswith(d) and len(h) > len(d) else ""

        best_score = 0.0
        best_target = None
        best_mode = None

        for target in self.saudi_targets:
            t = target.lower().strip()
            if d == t or h == t:
                continue

            t_label = self._strip_tld(t)

            # 1) فحص وجود اسم العلامة المحمية صراحةً داخل النطاق الفرعي (Brand-in-Subdomain)
            # مثل: absher.sa.login-verify.com أو alrajhibank.secure-update.xyz
            if len(t_label) >= 4 and (t_label in sub_part.split(".") or t_label in sub_part.replace("-", ".")):
                return 0.95, target, "brand_in_subdomain"

            # 2) فحص دمج العلامة المحمية مع كلمات إضافية في النطاق نفسه (Combo-squatting)
            # مثل: ub-portal-login.com أو absher-verify.net أو alrajhibank-online.com
            if len(t_label) >= 4 and t_label in d_label and d_label != t_label:
                return 0.91, target, "combo_squatting"
            if t_label == "ub" and re.match(r"^ub[-_](?:edu|portal|login|verify|student|sso)", d_label):
                return 0.92, target, "combo_squatting"

            # 3) فحص التمويه البصري للأحرف (Homograph Normalization) على اسم النطاق بدون الامتداد
            homo_d = self.normalize_homograph(d_label)
            homo_t = self.normalize_homograph(t_label)
            if homo_d == homo_t and d_label != t_label:
                return 0.94, target, "homograph_proxy"

            # 4) مقارنة التشابه الإملائي (Levenshtein + Jaro-Winkler) على الجذر الأساسي للنطاق
            lev_label = self.levenshtein_distance(d_label, t_label)
            max_lbl = max(len(d_label), len(t_label), 1)
            lbl_sim = 1.0 - (lev_label / max_lbl)

            # إذا كان الاختلاف حرفاً واحداً فقط في علامة لا يقل طولها عن 5 أحرف (مثل g0ogle أو hogle أو abshar)
            if len(t_label) >= 5 and lev_label == 1 and abs(len(d_label) - len(t_label)) <= 1:
                lbl_sim = max(lbl_sim, 0.86)

            homo_lev = self.levenshtein_distance(homo_d, homo_t)
            homo_sim = 1.0 - (homo_lev / max(len(homo_d), len(homo_t), 1))

            # مقارنة النطاق الكامل أيضاً
            full_lev = self.levenshtein_distance(d, t)
            full_sim = 1.0 - (full_lev / max(len(d), len(t), 1))

            cand_sim = max(lbl_sim, full_sim)
            if cand_sim > best_score:
                best_score = cand_sim
                best_target = target
                best_mode = "typosquatting"

            if homo_sim > best_score:
                best_score = homo_sim
                best_target = target
                best_mode = "homograph_proxy"

        return float(best_score), best_target, best_mode

    # ---------------------------------------------------------
    # 10. مسافة التعديل (Levenshtein Distance)
    # ---------------------------------------------------------
    def levenshtein_distance(self, a: str, b: str) -> int:
        a = a or ""
        b = b or ""
        if a == b:
            return 0
        if not a:
            return len(b)
        if not b:
            return len(a)
        if len(a) < len(b):
            a, b = b, a
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, start=1):
            cur = [i]
            for j, cb in enumerate(b, start=1):
                ins = cur[j - 1] + 1
                delete = prev[j] + 1
                sub = prev[j - 1] + (0 if ca == cb else 1)
                cur.append(min(ins, delete, sub))
            prev = cur
        return prev[-1]

    # ---------------------------------------------------------
    # 11. تطبيع الحروف المتشابهة بصرياً (Unicode & Leet Homographs)
    # ---------------------------------------------------------
    def normalize_homograph(self, s: str) -> str:
        s = (s or "").lower()
        # تفكيك التشكيل والرموز المركبة قياسياً
        s = unicodedata.normalize("NFKD", s)
        # استبدال المقاطع المتشابهة بصرياً
        multi_subs = {
            "rn": "m",
            "vv": "w",
            "cl": "d",
            "00": "o",
        }
        for k, v in multi_subs.items():
            s = s.replace(k, v)

        # استبدال الأرقام والحروف السيريلية/اليونانية المشابهة للحروف اللاتينية
        char_subs = {
            "0": "o", "1": "l", "I": "l", "|": "l", "!": "i",
            "3": "e", "4": "a", "@": "a", "5": "s", "$": "s",
            "6": "g", "8": "b", "9": "g",
            # Cyrillic / Greek confusables
            "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
            "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
            "ԁ": "d", "ɡ": "g", "ν": "v", "α": "a", "ο": "o",
        }
        return "".join(char_subs.get(ch, ch) for ch in s)