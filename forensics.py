"""
forensics.py — ELA analysis + OCR text extraction + heuristic fraud rules
"""
import io
import re
import base64
import numpy as np
from PIL import Image, ImageChops, ImageEnhance, ImageFilter
import cv2
from pathlib import Path


# ─────────────────────────────────────────────
# ELA — Error Level Analysis
# ─────────────────────────────────────────────

def compute_ela(image: Image.Image, quality: int = 90) -> tuple[float, str]:
    """
    Compute ELA score. Higher score = more potential manipulation.
    Returns (score 0-100, base64 ELA image)
    """
    try:
        # Save as JPEG with specific quality then reload
        buf = io.BytesIO()
        image_rgb = image.convert("RGB")
        image_rgb.save(buf, format="JPEG", quality=quality)
        buf.seek(0)
        reloaded = Image.open(buf).convert("RGB")

        # Compute difference
        diff = ImageChops.difference(image_rgb, reloaded)

        # Amplify differences
        extrema = diff.getextrema()
        max_diff = max([ex[1] for ex in extrema]) or 1
        scale = 255.0 / max_diff
        ela_img = diff.point(lambda px: px * scale)

        # Compute anomaly score (0-100)
        ela_array = np.array(ela_img).astype(float)
        mean_ela = ela_array.mean()
        std_ela = ela_array.std()
        # Normalize to 0-100
        score = min(100.0, (mean_ela + std_ela * 2) / 2.55)

        # Encode ELA image as base64
        ela_buf = io.BytesIO()
        ela_img.save(ela_buf, format="PNG")
        ela_b64 = base64.b64encode(ela_buf.getvalue()).decode()

        return round(score, 2), ela_b64
    except Exception as e:
        return 0.0, ""


# ─────────────────────────────────────────────
# OCR — Extract text from screenshot
# ─────────────────────────────────────────────

def extract_text(image: Image.Image) -> str:
    """Extract text using pytesseract. Falls back gracefully if unavailable."""
    try:
        import pytesseract
        # Enhance for OCR
        enhanced = image.convert("L")
        enhanced = ImageEnhance.Contrast(enhanced).enhance(2.0)
        text = pytesseract.image_to_string(enhanced, config="--psm 6")
        return text.strip()
    except Exception:
        return ""


# ─────────────────────────────────────────────
# Heuristic Fraud Rules
# ─────────────────────────────────────────────

FRAUD_RULES = [
    {
        "id": "fake_watermark",
        "name": "FAKE Watermark Detected",
        "description": "Image contains a 'FAKE!' stamp or watermark — a clear indicator of a fabricated screenshot.",
        "severity": "CRITICAL",
        "weight": 95
    },
    {
        "id": "rewards_screen",
        "name": "Rewards/Cashback Screen (Not Payment)",
        "description": "This appears to be a Google Pay rewards or cashback notification, NOT an actual payment. Scammers show this to trick merchants.",
        "severity": "CRITICAL",
        "weight": 90
    },
    {
        "id": "no_debit_account",
        "name": "Missing 'Debited From' Account",
        "description": "Genuine payment receipts show the sender's bank account. This screenshot is missing that field — a key fraud indicator.",
        "severity": "HIGH",
        "weight": 75
    },
    {
        "id": "suspicious_utr",
        "name": "Suspicious UTR/Transaction ID",
        "description": "The UTR number contains spaces, sequential digits, or irregular patterns not matching genuine bank-generated UTRs.",
        "severity": "HIGH",
        "weight": 70
    },
    {
        "id": "sound_scam",
        "name": "Possible PhonePe Sound Box Scam",
        "description": "Transaction shows ₹1 sent to a payment gateway — typical of the 'sound box' trick where a tiny amount triggers a sound to fake a larger payment.",
        "severity": "HIGH",
        "weight": 80
    },
    {
        "id": "mandate_request",
        "name": "Debit Authorization Request (Not Payment)",
        "description": "This is a MANDATE/debit authorization request, not a completed payment. Money has NOT been transferred yet.",
        "severity": "CRITICAL",
        "weight": 88
    },
    {
        "id": "ela_manipulation",
        "name": "Image Manipulation Detected (ELA)",
        "description": "Error Level Analysis reveals digital manipulation or editing artifacts in this screenshot.",
        "severity": "MEDIUM",
        "weight": 55
    },
    {
        "id": "amount_too_small",
        "name": "Unusually Small Amount (₹1 or less)",
        "description": "Payment of ₹1 to a merchant gateway is suspicious — classic PhonePe sound box trick amount.",
        "severity": "MEDIUM",
        "weight": 60
    },
]


def run_heuristic_analysis(text: str, image: Image.Image) -> tuple[list[dict], dict]:
    """
    Run all heuristic rules on extracted text.
    Returns (triggered_rules, transaction_details)
    """
    text_lower = text.lower()
    triggered = []
    details = {}

    # ── Extract transaction details ──────────────────────
    # Amount
    amount_match = re.search(r'[₹rs\.]\s*([\d,]+\.?\d*)', text, re.IGNORECASE)
    if amount_match:
        amount_str = amount_match.group(1).replace(",", "")
        try:
            details["amount"] = float(amount_str)
        except:
            pass

    # UPI ID
    upi_match = re.search(r'[\w\.\-]+@[\w]+', text)
    if upi_match:
        details["upi_id"] = upi_match.group()

    # Transaction ID / UTR
    txn_match = re.search(
        r'(?:transaction id|txn id|upi txn id|utr|order id)[:\s#]*([A-Z0-9\s]{8,30})',
        text, re.IGNORECASE
    )
    if txn_match:
        details["transaction_id"] = txn_match.group(1).strip()

    # Status
    if re.search(r'payment successful|transaction successful|paid successfully|completed', text_lower):
        details["status"] = "Successful"
    elif re.search(r'pending|processing', text_lower):
        details["status"] = "Pending"
    elif re.search(r'failed|declined', text_lower):
        details["status"] = "Failed"

    # ── Rule checks ──────────────────────────────────────

    # FAKE watermark
    if re.search(r'\bfake[!\.]?\b', text_lower):
        triggered.append("fake_watermark")

    # Rewards screen
    if re.search(r'reward|cashback|scratch card|you won|bonus|gift|prize', text_lower):
        triggered.append("rewards_screen")
    if re.search(r'from google pay rewards|google pay reward', text_lower):
        triggered.append("rewards_screen")
    if re.search(r'rewarded for doing your first|first card transaction', text_lower):
        triggered.append("rewards_screen")

    # Sound scam (₹1)
    if details.get("amount") is not None and details["amount"] <= 1.0:
        triggered.append("sound_scam")
        triggered.append("amount_too_small")

    # Mandate / debit request (not payment)
    if re.search(r'mandate|debit authorization|auto pay|authorize|approve payment', text_lower):
        triggered.append("mandate_request")

    # Missing debit account — check for "debited from" or "from" field
    # Real transactions often use "Sent from", "Credited to", "Received from", "Paid to", or "UPI Lite"
    has_debit_from = bool(re.search(
        r'debited from|from\s+\w+|debit.*account|bank account|state bank|axis bank|hdfc|icici|kotak|credited to|sent from|received from|paid to|upi lite',
        text_lower
    ))
    if not has_debit_from and len(text) > 50:
        triggered.append("no_debit_account")

    # Suspicious UTR
    if txn_match:
        utr = details.get("transaction_id", "")
        # OCR might occasionally add a single space, so only flag if multiple spaces or obvious fake patterns
        if utr.count(" ") > 1:  
            triggered.append("suspicious_utr")
        elif re.search(r'(012345|123456|234567|345678|456789|567890|999999|000000)', utr):
            triggered.append("suspicious_utr")

    # Deduplicate
    triggered = list(dict.fromkeys(triggered))
    rule_map = {r["id"]: r for r in FRAUD_RULES}
    triggered_rules = [rule_map[rid] for rid in triggered if rid in rule_map]

    return triggered_rules, details


def compute_risk_score(triggered_rules: list[dict], ela_score: float, gemini_verdict: str = None) -> int:
    """
    Compute final risk score (0-100).
    """
    if not triggered_rules and ela_score < 20:
        base = int(ela_score * 0.3)
    else:
        weights = [r["weight"] for r in triggered_rules]
        if weights:
            # Weighted combination — take max and add partial contributions
            max_w = max(weights)
            extra = sum(w for w in weights if w != max_w) * 0.2
            base = min(100, int(max_w + extra))
        else:
            base = 0

    # Boost from ELA
    ela_boost = int(ela_score * 0.15) if ela_score > 30 else 0

    # Gemini override
    if gemini_verdict == "FRAUD":
        base = max(base, 75)
    elif gemini_verdict == "GENUINE":
        base = min(base, 40)

    return min(100, base + ela_boost)
