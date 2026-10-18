import os
import re
import math
import ssl
import socket
import hashlib
from datetime import datetime, timezone

import numpy as np
import requests

try:
    import whois as whois_lib
except Exception:
    whois_lib = None

from urllib.parse import urlparse


def safe_to_str(x):
    return "" if x is None else str(x)


class URLAnalyzer:
    def __init__(self):
        # Saudi sensitive domains (base set)
        self.saudi_targets = [
            "ub.edu.sa",
            "absher.sa",
            "tawakkalna.gov.sa",
            "nafath.sa",
            "mcs.gov.sa",
            "sdaia.gov.sa",
            # Example banks (generic placeholders)
            "snb.com.sa",
            "alrajhibank.com.sa",
            "sabb.com.sa",
            "albilad.com",
        ]

        # Common phishing char patterns
        self.suspicious_substrings = [
            "login",
            "signin",
            "verify",
            "verification",
            "secure",
            "account",
            "bank",
            "payment",
            "support",
            "session",
            "update",
            "otp",
            "password",
            "credential",
        ]

        self.suspicious_symbols = ["@", "-", "_", "—", "~", "%", "=", "?", "&"]

    # -----------------------------
    # Public entry
    # -----------------------------
    def analyze_url_with_explanations(self, url: str, ml_engine):
        url = (url or "").strip()
        if not url:
            raise ValueError("Empty URL")

        domain_obj = self.extract_domain(url)
        domain = domain_obj.get("domain", "")
        host = domain_obj.get("host", "")
        tld = domain_obj.get("tld", "")
        scheme = domain_obj.get("scheme", "")

        parsed = urlparse(url)
        path = parsed.path or ""
        query = parsed.query or ""
        full_text = (url or "")

        features = self.extract_25_features(url=url, domain=domain, host=host, tld=tld, scheme=scheme, path=path, query=query, ml_engine=ml_engine)

        # ML prediction
        threat_prob = ml_engine.predict_threat_probability(features)
        threat_pct = float(threat_prob) * 100.0

        # Explainable rules
        reasons, adjusted_pct, forced_severity = self.build_reasons_and_adjustment(
            url=url,
            features=features,
            domain=domain,
            scheme=scheme,
            ml_engine=ml_engine,
        )

        if forced_severity is not None:
            severity = forced_severity
            threat_pct = max(threat_pct, 92.0)  # ensure "Critical" feel
            adjusted_pct = threat_pct
        else:
            threat_pct = max(0.0, min(100.0, float(adjusted_pct)))
            severity = self.severity_from_pct(threat_pct)

        artifacts = self.collect_artifacts(url=url, domain=domain)

        explain = {
            "threat_prob_raw": float(threat_prob),
            "threat_pct": threat_pct,
            "severity": severity,
            "reasons": reasons,
        }
        return threat_pct, severity, explain, features, artifacts

    # -----------------------------
    # Extract domain/scheme
    # -----------------------------
    def extract_domain(self, url: str):
        u = (url or "").strip()
        if not u:
            return {"domain": "", "host": "", "tld": "", "scheme": ""}

        parsed = urlparse(u if re.match(r"^https?://", u, re.IGNORECASE) else "https://" + u)
        scheme = parsed.scheme or ""
        host = (parsed.netloc or "").lower()

        # remove port
        host = host.split(":")[0] if host else ""

        # Try to derive domain+TLD
        parts = [p for p in host.split(".") if p]
        tld = parts[-1] if len(parts) >= 2 else ""
        domain = host

        # Normalize Saudi: keep last 3 parts if possible (e.g., ub.edu.sa)
        if len(parts) >= 3:
            # If endswith .sa, take last 3 parts
            if parts[-1] == "sa":
                domain = ".".join(parts[-3:])
            else:
                domain = host

        return {"domain": domain, "host": host, "tld": tld, "scheme": scheme}

    # -----------------------------
    # 25 Features
    # -----------------------------
    def extract_25_features(self, url: str, domain: str, host: str, tld: str, scheme: str, path: str, query: str, ml_engine=None):
        # 1-25: engineered signals
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

        # suspicious chars count
        at_count = u.count("@")
        hyphen_count = u.count("-")
        underscore_count = u.count("_")
        digit_count = sum(c.isdigit() for c in u)
        alpha_count = sum(c.isalpha() for c in u)
        slash_count = u.count("/")
        dot_count = u.count(".")
        question_count = u.count("?")
        percent_count = u.count("%")
        equal_count = u.count("=")

        # IP detection
        ip_like = 1 if re.search(r"(?:\d{1,3}\.){3}\d{1,3}", host) else 0

        # punycode detection
        punycode = 1 if "xn--" in u.lower() or re.search(r"\bxn--", host.lower()) else 0

        # Port detection (e.g., :8080)
        port_present = 1 if re.search(r":\d{2,5}", host) else 0

        # URL shorteners (common in phishing)
        shorteners = [
            "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "is.gd", "cutt.ly", "buff.ly", "adf.ly"
        ]
        is_shortener = 1 if any(s in host for s in shorteners) else 0

        # Path / query suspicious tokens
        lowered = u.lower()
        token_hits = 0
        for t in self.suspicious_substrings:
            if t in lowered:
                token_hits += 1

        # Shannon entropy
        entropy = self.shannon_entropy(u)
        entropy_domain = self.shannon_entropy(domain) if domain else 0.0

        # Character diversity
        unique_chars = len(set(u)) if u else 0
        unique_chars_ratio = unique_chars / L if L > 0 else 0

        # Ratio features
        digits_ratio = digit_count / L if L > 0 else 0
        alpha_ratio = alpha_count / L if L > 0 else 0
        dots_ratio = dot_count / L if L > 0 else 0
        hyphen_ratio = hyphen_count / L if L > 0 else 0

        # Keyword/Pattern flags
        has_symbol_spoof = 1 if any(sym in u for sym in ["@", "-", "_"]) else 0
        has_at_and_dash = 1 if ("@" in u and "-" in u) else 0

        # Suspicious length
        long_url = 1 if L > 120 else 0
        very_long_url = 1 if L > 200 else 0
        short_url = 1 if 10 < L < 35 else 0  # suspicious sometimes

        # Domain age proxy (if available through WHOIS in artifacts, but here fallback-ready proxy from text)
        # We add placeholder-like feature computed from patterns: new domain likely contains punycode or shortener
        # Real WHOIS is handled later in artifacts and also included via features through fallback.
        # We'll attempt WHOIS age here but never hard-fail.
        whois_age_days, whois_registrar, whois_status = self.try_whois_age(domain)

        age_days = whois_age_days
        age_missing = 1 if whois_age_days is None else 0

        # TLS/SSL feature proxy using scheme + port 443 patterns
        # Real TLS status also collected in artifacts; features include scheme & host presence
        tls_possible = 1 if scheme in ["https", ""] else 0

        # Similarity-based Saudi spoofing score (typosquatting/homograph)
        saudi_spoof_score, saudi_target, saudi_mode = self.saudi_spoof_similarity(domain)
        saudi_spoof_flag = 1 if saudi_spoof_score >= 0.80 else 0

        # Scheme mismatch: https missing
        no_https = 1 if has_https == 0 else 0

        # Query complexity
        query_len = L_query
        query_entropy = self.shannon_entropy(query) if query else 0.0
        many_params = 1 if query.count("&") >= 2 else 0
        has_credential_params = 1 if any(k in lowered for k in ["password", "pass", "session", "token", "otp", "code"]) else 0

        # Final 25 features (fixed keys)
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
            "digits_ratio": digits_ratio,
            "alpha_ratio": alpha_ratio,
            "dots_ratio": dots_ratio,
            "hyphen_ratio": hyphen_ratio,
            "url_entropy": entropy,
            "domain_entropy": entropy_domain,
            "unique_chars_ratio": unique_chars_ratio,
            "domain_age_days": age_days if age_days is not None else -1,
            "domain_age_missing_flag": age_missing,
            "saudi_spoof_score": saudi_spoof_score,
        }

        # Add a couple extras inside features dict (still counts as part of extraction logic; ML engine will pick exact list)
        # Provide hint for model training
        features["label_hint"] = "unknown"

        # Ensure all numeric
        for k, v in list(features.items()):
            if isinstance(v, bool):
                features[k] = 1 if v else 0
            if v is None:
                features[k] = -1

        return features

    # -----------------------------
    # WHOIS age with fallback
    # -----------------------------
    def try_whois_age(self, domain: str):
        # Return (age_days_or_none, registrar_or_str, status)
        if not domain:
            return None, None, "unavailable"

        # If library missing, fallback
        if whois_lib is None:
            return None, None, "unavailable"

        try:
            # whois_lib may block; set timeouts by using requests-like? library doesn't always support.
            w = whois_lib.whois(domain)

            # registration_date can be list or datetime
            reg = w.creation_date or w.creationdate if hasattr(w, "creationdate") else None
            registrar = safe_to_str(getattr(w, "registrar", "")) if hasattr(w, "registrar") else None

            if isinstance(reg, list):
                # take earliest
                reg_dt = reg[0]
                for r in reg:
                    if r and (getattr(r, "year", 0) < getattr(reg_dt, "year", 0)):
                        reg_dt = r
            else:
                reg_dt = reg

            if not reg_dt:
                return None, registrar, "partial"

            if isinstance(reg_dt, datetime):
                reg_dt_utc = reg_dt.astimezone(timezone.utc) if reg_dt.tzinfo else reg_dt.replace(tzinfo=timezone.utc)
            else:
                # attempt parse
                try:
                    reg_dt_utc = datetime.fromisoformat(str(reg_dt)).replace(tzinfo=timezone.utc)
                except Exception:
                    return None, registrar, "partial"

            now = datetime.now(timezone.utc)
            age_days = (now - reg_dt_utc).days
            if age_days < 0:
                age_days = 0

            return age_days, registrar, "ok"
        except Exception:
            return None, None, "unavailable"

    # -----------------------------
    # Collect artifacts: whois + ssl with fallback
    # -----------------------------
    def collect_artifacts(self, url: str, domain: str):
        domain_obj = self.extract_domain(url)
        domain_name = domain_obj.get("domain", "")

        whois_info = {
            "status": "unavailable",
            "registration_date": None,
            "registrar": None,
            "age_days": None,
            "age_years": None,
        }
        ssl_info = {
            "tls_status": "unknown",
            "issuer": None,
            "not_after": None,
        }

        # WHOIS
        if whois_lib is not None and domain_name:
            try:
                w = whois_lib.whois(domain_name)
                reg = w.creation_date or w.creationdate if hasattr(w, "creationdate") else None
                registrar = safe_to_str(getattr(w, "registrar", "")) if hasattr(w, "registrar") else None

                reg_dt = None
                if isinstance(reg, list):
                    # choose min valid
                    valid = [r for r in reg if isinstance(r, datetime)]
                    if valid:
                        reg_dt = min(valid, key=lambda x: x)
                elif isinstance(reg, datetime):
                    reg_dt = reg

                if reg_dt is None and reg:
                    try:
                        reg_dt = datetime.fromisoformat(str(reg)).replace(tzinfo=timezone.utc)
                    except Exception:
                        reg_dt = None

                if reg_dt:
                    if reg_dt.tzinfo:
                        reg_dt_utc = reg_dt.astimezone(timezone.utc)
                    else:
                        reg_dt_utc = reg_dt.replace(tzinfo=timezone.utc)

                    age_days = (datetime.now(timezone.utc) - reg_dt_utc).days
                    age_days = max(0, int(age_days))

                    whois_info.update({
                        "status": "ok",
                        "registration_date": reg_dt_utc.isoformat(),
                        "registrar": registrar,
                        "age_days": age_days,
                        "age_years": round(age_days / 365.25, 2),
                    })
                else:
                    whois_info.update({"status": "partial"})
            except Exception:
                whois_info.update({"status": "unavailable"})

        # SSL/TLS certificate check (best effort)
        # We'll attempt only if host exists and scheme can be inferred.
        host = domain_obj.get("host", "")
        scheme = domain_obj.get("scheme", "")
        port = 443
        if host:
            try:
                # decide port
                parsed = urlparse(url)
                if parsed.port:
                    port = parsed.port

                server_name = host.split(":")[0]

                context = ssl.create_default_context()
                with socket.create_connection((server_name, port), timeout=6) as sock:
                    with context.wrap_socket(sock, server_hostname=server_name) as ssock:
                        cert = ssock.getpeercert()
                        who = cert.get("issuer", [])
                        issuer = None
                        if who:
                            # issuer as list tuples
                            parts = []
                            for item in who:
                                for k, v in item:
                                    parts.append(f"{k}={v}")
                            issuer = ", ".join(parts)

                        not_after = cert.get("notAfter")
                        ssl_info["tls_status"] = "present"
                        ssl_info["issuer"] = issuer
                        ssl_info["not_after"] = not_after
            except Exception:
                ssl_info["tls_status"] = "unverified/unreachable"

        artifacts = {
            "domain": domain_obj,
            "whois": whois_info,
            "ssl": ssl_info,
        }
        return artifacts

    # -----------------------------
    # Severity mapping
    # -----------------------------
    def severity_from_pct(self, pct: float):
        if pct < 20:
            return "Safe"
        if pct < 40:
            return "Low"
        if pct < 65:
            return "Medium"
        if pct < 85:
            return "High"
        return "Critical Block"

    # -----------------------------
    # Build reasons + adjust severity
    # -----------------------------
    def build_reasons_and_adjustment(self, url: str, features: dict, domain: str, scheme: str, ml_engine=None):
        reasons = []

        def add_reason(reason, weight, detail, feature_key=None):
            reasons.append({
                "reason": reason,
                "weight": float(weight),
                "detail": detail,
                "feature_key": feature_key
            })

        # Rule 1: HTTPS missing
        if features.get("has_https", 0) == 0:
            add_reason(
                "عدم استخدام HTTPS (قد يشير لصفحة غير آمنة/تصيد)",
                weight=14,
                detail=f"الرابط لا يبدأ بـ https:// (scheme={scheme or 'unknown'}).",
                feature_key="has_https"
            )

        # Rule 2: shortener
        if features.get("shortener_present", 0) == 1:
            add_reason(
                "استخدام مُختصر رابط (URL Shortener)",
                weight=16,
                detail="تُستخدم مُختصرات الروابط كثيراً في إخفاء الوجهة الحقيقية.",
                feature_key="shortener_present"
            )

        # Rule 3: IP direct
        if features.get("ip_address_like", 0) == 1:
            add_reason(
                "استخدام عنوان IP بدل اسم نطاق",
                weight=18,
                detail="توجيه المستخدم عبر IP مباشرةً يقلل موثوقية الهوية ويُستخدم في الهجمات.",
                feature_key="ip_address_like"
            )

        # Rule 4: punycode
        if features.get("punycode_present", 0) == 1:
            add_reason(
                "وجود Punycode (Homograph تمويه لغوي)",
                weight=22,
                detail="Punycode غالباً يعني استخدام أحرف تبدو مشابهة للاسم الحقيقي (Homograph).",
                feature_key="punycode_present"
            )

        # Rule 5: entropy high
        entropy = features.get("url_entropy", 0.0)
        if entropy >= 4.0:
            add_reason(
                "ارتفاع عشوائية المحتوى (Shannon Entropy)",
                weight=14,
                detail=f"قيمة Shannon Entropy للـ URL ≈ {entropy:.3f} (تعقيد/عشوائية عالية).",
                feature_key="url_entropy"
            )

        # Rule 6: suspicious tokens
        token_hits = features.get("suspicious_token_hits", 0)
        if token_hits >= 2:
            add_reason(
                "كلمات/مسارات تصيدية ضمن الرابط",
                weight=12 + 3 * min(token_hits, 4),
                detail=f"تم رصد مؤشرات كلمات تصيد متعددة (hits={token_hits}).",
                feature_key="suspicious_token_hits"
            )

        # Rule 7: special characters
        at_count = features.get("at_symbol_count", 0)
        hyphen_count = features.get("hyphen_count", 0)
        if at_count >= 1:
            add_reason(
                "رمز @ في الرابط",
                weight=12,
                detail="وجود '@' قد يستخدم لخداع المستخدم حول جزء النطاق الحقيقي.",
                feature_key="at_symbol_count"
            )
        if hyphen_count >= 10:
            add_reason(
                "أعداد كبيرة من '-' (تمويه نصي/typosquatting)",
                weight=10,
                detail=f"عدد '-' مرتفع (count={hyphen_count}).",
                feature_key="hyphen_count"
            )

        # Rule 8: length
        L = features.get("url_length", 0)
        if L >= 200:
            add_reason(
                "طول زائد للرابط",
                weight=14,
                detail=f"طول الرابط {L} حرف → غالباً يستخدم لإخفاء نوايا خبيثة أو صيغ تصيد طويلة.",
                feature_key="url_length"
            )
        elif L >= 120:
            add_reason(
                "طول مرتفع للرابط",
                weight=10,
                detail=f"طول الرابط {L} حرف → إشارة متزايدة للتهديد.",
                feature_key="url_length"
            )

        # Rule 9: domain age if missing or very new
        age_days = features.get("domain_age_days", None)
        age_missing = features.get("domain_age_missing_flag", 0)
        if age_missing == 1:
            add_reason(
                "تعذر التحقق من عمر النطاق (WHOIS fallback)",
                weight=10,
                detail="لم تتوفر سجلات WHOIS بشكل كامل، لذلك يعتمد القرار على إشارات أخرى.",
                feature_key="domain_age_missing_flag"
            )
        else:
            if isinstance(age_days, (int, float)) and age_days >= 0 and age_days < 30:
                add_reason(
                    "عمر نطاق حديث جداً",
                    weight=20,
                    detail=f"النطاق عمرة ≈ {int(age_days)} يوم (< 30) → شائع في التصيد.",
                    feature_key="domain_age_days"
                )

        # Rule 10: Saudi spoofing critical raise
        saudi_score = features.get("saudi_spoof_score", 0.0)
        if saudi_score is not None:
            # Compute similarity again to get target/mode via internal method
            saudi_score2, target, mode = self.saudi_spoof_similarity(domain)
            if saudi_score2 >= 0.80:
                reasons.insert(
                    0,
                    {
                        "reason": "انتحال/تشابه نطاق سعودي حساس (Typosquatting/Homograph)",
                        "weight": 35,
                        "detail": f"تطابق/تشابه مرتفع مع: {target or 'target'} (mode={mode}). Score={saudi_score2:.3f}",
                        "feature_key": "saudi_spoof_score",
                    }
                )
                # forced critical
                return reasons, max(92.0, saudi_score2 * 100.0), "Critical Block"

        # Weight-based adjustment
        total_w = sum(r.get("weight", 0) for r in reasons) if reasons else 0
        # Map weight to additional threat increment
        # base: classifier already gave probability; we enhance by reason-weight scaled.
        adj = min(16.0, total_w * 0.25) if total_w else 0.0

        # compute adjusted percentage by rule-based adjustment around threshold
        # If strong reasons present, we push up.
        base_adj_pct = 0.0
        if reasons:
            base_adj_pct = adj
        # We'll return adjusted_pct as "pseudo" additional; app will map severity based on final adjusted
        adjusted_pct = (0.0 + base_adj_pct) + 0.0  # app uses severity_from_pct on final adjusted_pct elsewhere
        # But we need actual threat_pct from app; so return adjusted_pct as:
        # We'll use a stable mapping: if total_w is large, move to critical range.
        if total_w == 0:
            adjusted_pct = 10.0
        else:
            # Convert total_w into a [0,100] threat contribution
            adjusted_pct = min(100.0, 10.0 + total_w * 1.2)

        return reasons, adjusted_pct, None

    # -----------------------------
    # Entropy
    # -----------------------------
    def shannon_entropy(self, s: str):
        if not s:
            return 0.0
        s = str(s)
        if len(s) == 0:
            return 0.0

        counts = {}
        for c in s:
            counts[c] = counts.get(c, 0) + 1

        ent = 0.0
        L = len(s)
        for c, k in counts.items():
            p = k / L
            if p > 0:
                ent -= p * math.log(p, 2)
        return float(ent)

    # -----------------------------
    # Saudi spoofing similarity detector
    # -----------------------------
    def saudi_spoof_similarity(self, domain: str):
        d = (domain or "").lower().strip()
        if not d:
            return 0.0, None, None

        best_score = 0.0
        best_target = None
        best_mode = None

        for target in self.saudi_targets:
            t = target.lower().strip()

            # Typosquatting: Levenshtein similarity (normalized)
            lev = self.levenshtein_distance(d, t)
            max_len = max(len(d), len(t), 1)
            lev_sim = 1.0 - (lev / max_len)

            # Homograph proxy: compare normalized with common substitutions
            homo_d = self.normalize_homograph(d)
            homo_t = self.normalize_homograph(t)
            lev2 = self.levenshtein_distance(homo_d, homo_t)
            max_len2 = max(len(homo_d), len(homo_t), 1)
            homo_sim = 1.0 - (lev2 / max_len2)

            if lev_sim > best_score:
                best_score = lev_sim
                best_target = target
                best_mode = "typosquatting"

            if homo_sim > best_score:
                best_score = homo_sim
                best_target = target
                best_mode = "homograph_proxy"

        return float(best_score), best_target, best_mode

    # -----------------------------
    # Levenshtein distance
    # -----------------------------
    def levenshtein_distance(self, a: str, b: str):
        a = a or ""
        b = b or ""
        if a == b:
            return 0
        if len(a) == 0:
            return len(b)
        if len(b) == 0:
            return len(a)

        # DP with O(min(n,m)) memory
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

    # -----------------------------
    # Homograph normalization proxy
    # -----------------------------
    def normalize_homograph(self, s: str):
        # Normalize common Latin homoglyph-like substitutions (proxy, not full Unicode spoofing)
        # This is intentionally simple to keep compatibility on Streamlit Cloud.
        s = s.lower()
        subs = {
            "0": "o",
            "1": "l",
            "3": "e",
            "5": "s",
            "8": "b",
            "@": "a",
        }
        for k, v in subs.items():
            s = s.replace(k, v)
        return s
