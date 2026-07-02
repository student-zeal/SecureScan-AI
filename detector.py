"""
Sensitive Data Detection Engine
Uses regex patterns to find PII, credentials, and confidential info in text.
"""

import re

# ---- Regex patterns for each sensitive data type ----
PATTERNS = {
    "Aadhaar Number": r"\b\d{4}\s?\d{4}\s?\d{4}\b",
    "PAN Number": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
    "Email Address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "Phone Number": r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b",
    "Credit Card Number": r"\b(?:\d[ -]*?){13,16}\b",
    "IFSC Code": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
    "Bank Account Number": r"(?i)(?:account\s*(?:no|number)?|a/c)\s*[:=]?\s*(\d{9,18})\b",
    "API Key / Secret": r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*[\'\"]?([A-Za-z0-9_\-]{16,})[\'\"]?",
    "Password": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*[\'\"]?(\S{4,})[\'\"]?",
    "Employee ID": r"(?i)\b((?:EMP|EID|ID)[-_]?\d{3,8})\b",
    "IP Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}

# Friendly singular and plural names for reasons
FRIENDLY_NAMES = {
    "Aadhaar Number": ("Aadhaar Number", "Aadhaar Numbers"),
    "PAN Number": ("PAN Number", "PAN Numbers"),
    "Credit Card Number": ("Credit Card", "Credit Cards"),
    "Bank Account Number": ("Bank Account Details", "Bank Account Details"),
    "IFSC Code": ("IFSC Code", "IFSC Codes"),
    "API Key / Secret": ("API Key", "API Keys"),
    "Password": ("Password", "Passwords"),
    "Email Address": ("Email Address", "Email Addresses"),
    "Phone Number": ("Phone Number", "Phone Numbers"),
    "Employee ID": ("Employee ID", "Employee IDs"),
    "IP Address": ("IP Address", "IP Addresses"),
}


def detect_sensitive_data(text: str) -> dict:
    """
    Scans text and returns a dict of {category: [matches]}
    """
    findings = {}
    for label, pattern in PATTERNS.items():
        matches = re.findall(pattern, text)
        cleaned = []
        seen = set()
        for m in matches:
            val = m if isinstance(m, str) else m[0]
            val = val.strip()
            if val not in seen and val:
                seen.add(val)
                cleaned.append(val)
        if cleaned:
            findings[label] = cleaned
    return findings


def calculate_risk(findings: dict) -> dict:
    """
    Calculates a risk score and level based on findings, with category caps.
    High importance: Passwords, API Keys, Credit Cards, Aadhaar, PAN, Bank Details
    Lower importance: Email, Phone Number, IP Address, Employee ID
    """
    score = 0
    reasons = []

    # Risk weight per category
    weights = {
        "Aadhaar Number": 10,
        "PAN Number": 8,
        "Credit Card Number": 10,
        "Bank Account Number": 9,
        "IFSC Code": 6,
        "API Key / Secret": 10,
        "Password": 10,
        "Email Address": 2,
        "Phone Number": 3,
        "Employee ID": 2,
        "IP Address": 2,
    }

    for label, items in findings.items():
        count = len(items)
        if count == 0:
            continue

        weight = weights.get(label, 2)
        # Cap the count contribution per category to max 3 items
        effective_count = min(count, 3)
        category_score = weight * effective_count
        score += category_score

        # Get grammar-perfect labels for risk reasons
        names = FRIENDLY_NAMES.get(label, (label, label + "s"))
        name_str = names[0] if count == 1 else names[1]
        reasons.append(f"• {count} {name_str}")

    # Risk level thresholding based on capped score
    if score == 0:
        level = "Low Risk"
    elif score <= 5:
        level = "Low Risk"
    elif score <= 15:
        level = "Medium Risk"
    else:
        level = "High Risk"

    return {"score": score, "level": level, "reasons": reasons}


def mask_value(value: str, category: str) -> str:
    """Masks sensitive values according to specific compliance rules."""
    val = value.strip()
    if not val:
        return ""

    if category == "Email Address":
        if "@" in val:
            parts = val.split("@", 1)
            username = parts[0]
            domain = parts[1]
            if len(username) <= 2:
                masked_user = "*" * len(username)
            else:
                masked_user = username[:2] + "*" * (len(username) - 2)
            return f"{masked_user}@{domain}"
        return val[:2] + "*" * (len(val) - 2)

    elif category == "Phone Number":
        if len(val) <= 4:
            return "*" * len(val)
        return val[:2] + "*" * (len(val) - 4) + val[-2:]

    elif category == "PAN Number":
        if len(val) <= 6:
            return "*" * len(val)
        return val[:5] + "*" * (len(val) - 6) + val[-1:]

    elif category == "Aadhaar Number":
        if len(val) <= 8:
            return "*" * len(val)
        return val[:4] + "*" * (len(val) - 8) + val[-4:]

    elif category == "Credit Card Number":
        digits_only = re.sub(r"\D", "", val)
        if len(digits_only) >= 8:
            masked_digits = digits_only[:4] + "*" * (len(digits_only) - 8) + digits_only[-4:]
            return masked_digits
        return val[:4] + "*" * (len(val) - 4)

    elif category == "Password":
        return "Password Detected"

    elif category == "API Key / Secret":
        # sk-********abcd (first 3, last 7 - 3 = 4)
        if len(val) <= 7:
            return "*" * len(val)
        return val[:3] + "*" * (len(val) - 7) + val[-4:]

    else:
        # Default: keep first 2 and last 2
        if len(val) <= 4:
            return "*" * len(val)
        return val[:2] + "*" * (len(val) - 4) + val[-2:]


def redact_text(text: str, findings: dict) -> str:
    """Returns a redacted version of the document text."""
    redacted = text
    for label, items in findings.items():
        for item in items:
            redacted = redacted.replace(item, mask_value(item, label))
    return redacted