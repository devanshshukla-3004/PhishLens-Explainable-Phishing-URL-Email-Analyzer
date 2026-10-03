"""Explainable, offline phishing indicator analysis. Never fetches submitted URLs."""
from __future__ import annotations

import re
from urllib.parse import urlsplit, unquote

URL_RULES = [
    ("IP_ADDRESS_HOST", "The hostname is an IP address rather than a conventional domain.", 20),
    ("AT_SYMBOL", "The URL contains '@', which can obscure the destination before it.", 20),
    ("PUNYCODE_HOST", "The hostname contains an IDN punycode label (xn--); verify the displayed domain carefully.", 15),
    ("EXCESSIVE_SUBDOMAINS", "The hostname has many labels; check which domain is actually registered.", 10),
    ("URL_SHORTENER", "The URL uses a known shortening domain, hiding the final destination.", 15),
    ("SUSPICIOUS_KEYWORD", "The URL contains a credential, payment, or account-related keyword.", 10),
    ("NONSTANDARD_PORT", "The URL specifies a non-standard web port.", 10),
    ("HTTP_NOT_HTTPS", "The URL uses HTTP rather than HTTPS; content may not be encrypted in transit.", 5),
]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "ow.ly", "rb.gy", "shorturl.at"}
KEYWORDS = {"login", "verify", "password", "signin", "account", "wallet", "payment", "secure", "update", "banking", "credential"}
URGENCY = ("immediately", "urgent", "within 24 hours", "act now", "final warning", "account suspended", "verify your account", "limited time")
CREDENTIALS = ("password", "one-time password", "otp", "verification code", "credit card", "bank details", "social security")


def _valid_url(raw: str):
    raw = raw.strip()
    if not raw:
        raise ValueError("URL is empty")
    if any(ch.isspace() for ch in raw):
        raise ValueError("URL must not contain unescaped whitespace")
    candidate = raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) else "https://" + raw
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a valid HTTP(S) URL or hostname")
    return parsed


def analyze_url(raw: str) -> dict:
    parsed = _valid_url(raw)
    host = (parsed.hostname or "").lower().rstrip(".")
    score, findings = 0, []

    def add(code, explanation, points):
        nonlocal score
        score += points
        findings.append({"code": code, "explanation": explanation, "points": points})

    try:
        import ipaddress
        ipaddress.ip_address(host)
        add(*URL_RULES[0])
    except ValueError:
        pass
    if "@" in parsed.netloc or "@" in parsed.path:
        add(*URL_RULES[1])
    if any(label.startswith("xn--") for label in host.split(".")):
        add(*URL_RULES[2])
    if len(host.split(".")) >= 5:
        add(*URL_RULES[3])
    if host in SHORTENERS:
        add(*URL_RULES[4])
    decoded = unquote((parsed.path + " " + parsed.query).lower())
    if any(word in decoded for word in KEYWORDS):
        add(*URL_RULES[5])
    try:
        port = parsed.port
    except ValueError:
        add("INVALID_PORT", "The URL contains an invalid port value.", 10)
    else:
        if port is not None and not ((parsed.scheme.lower() == "http" and port == 80) or (parsed.scheme.lower() == "https" and port == 443)):
            add(*URL_RULES[6])
    if parsed.scheme.lower() == "http":
        add(*URL_RULES[7])
    score = min(score, 100)
    level = "low" if score < 20 else "moderate" if score < 45 else "high"
    return {
        "input": raw,
        "normalized_url": parsed.geturl(),
        "hostname": host,
        "risk_score": score,
        "risk_level": level,
        "findings": findings,
        "disclaimer": "Heuristic indicators only; this is not a definitive verdict and does not visit the URL.",
    }


def analyze_email(text: str) -> dict:
    if not text.strip():
        raise ValueError("Email text is empty")
    lower = text.lower()
    findings = []
    for phrase in URGENCY:
        if phrase in lower:
            findings.append({
                "code": "URGENCY_LANGUAGE",
                "matched_text": phrase,
                "explanation": "Urgency or pressure can be used to rush a recipient into unsafe action.",
                "points": 12,
            })
    for phrase in CREDENTIALS:
        if phrase in lower:
            findings.append({
                "code": "SENSITIVE_INFORMATION_REQUEST",
                "matched_text": phrase,
                "explanation": "The message references credentials or sensitive financial/account information; verify through an independent channel.",
                "points": 18,
            })
    if re.search(r"\b(click|tap|open)\s+(the\s+)?(link|button|attachment)\b", lower):
        findings.append({
            "code": "ACTION_LINK_PROMPT",
            "matched_text": "link/button/attachment prompt",
            "explanation": "The message asks the recipient to follow a link, button, or attachment; inspect the destination independently.",
            "points": 8,
        })
    if re.search(r"\b(dear customer|dear user|valued customer)\b", lower):
        findings.append({
            "code": "GENERIC_GREETING",
            "matched_text": "generic greeting",
            "explanation": "A generic greeting can be a weak indicator when combined with other signals.",
            "points": 4,
        })
    score = min(sum(f["points"] for f in findings), 100)
    level = "low" if score < 20 else "moderate" if score < 45 else "high"
    return {
        "risk_score": score,
        "risk_level": level,
        "findings": findings,
        "disclaimer": "Text-only heuristic analysis; findings require human review and may include false positives.",
    }
