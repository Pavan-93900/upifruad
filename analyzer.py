"""
analyzer.py — Core analysis orchestrator: combines Gemini AI + forensic engines
"""
import base64
import io
from PIL import Image
from forensics import compute_ela, extract_text, run_heuristic_analysis, compute_risk_score
from gemini_client import analyze_with_gemini


async def analyze_screenshot(image_bytes: bytes, filename: str) -> dict:
    """
    Full analysis pipeline for a UPI payment screenshot.
    Returns complete analysis result with verdict, risk score, and evidence.
    """
    # Open image
    try:
        image = Image.open(io.BytesIO(image_bytes))
    except Exception:
        return {"error": "Invalid image file. Please upload a valid PNG, JPG, or WEBP screenshot."}

    # ── 1. ELA Analysis ───────────────────────────────────
    ela_score, ela_b64 = compute_ela(image)

    # ── 2. OCR Text Extraction ────────────────────────────
    extracted_text = extract_text(image)

    # ── 3. Heuristic Rule Analysis ────────────────────────
    triggered_rules, transaction_details = run_heuristic_analysis(extracted_text, image)

    # Add ELA rule if manipulation detected
    if ela_score > 35:
        ela_rule = {
            "id": "ela_manipulation",
            "name": "Image Manipulation Detected (ELA)",
            "description": f"Error Level Analysis score: {ela_score:.1f}/100. High ELA indicates potential digital editing or manipulation of this screenshot.",
            "severity": "MEDIUM",
            "weight": 55
        }
        triggered_rules.append(ela_rule)

    # ── 4. Gemini Vision AI Analysis ─────────────────────
    gemini_result = await analyze_with_gemini(image)
    gemini_verdict = gemini_result.get("verdict", "UNKNOWN")
    gemini_confidence = gemini_result.get("confidence", 50)
    gemini_fraud_type = gemini_result.get("fraud_type", "none")
    gemini_summary = gemini_result.get("summary", "")
    gemini_info = gemini_result.get("extracted_info", {})

    # If Gemini detects a specific fraud type, add corresponding rule
    if gemini_fraud_type and gemini_fraud_type != "none":
        fraud_type_map = {
            "rewards_scam": {
                "id": "rewards_screen",
                "name": "AI: Rewards/Cashback Screen Detected",
                "description": "Gemini AI confirmed this is a rewards notification, not an actual payment receipt.",
                "severity": "CRITICAL",
                "weight": 92
            },
            "sound_box_scam": {
                "id": "sound_scam",
                "name": "AI: PhonePe Sound Box Scam",
                "description": "Gemini AI detected the ₹1 sound box trick — a tiny amount to trigger a beep without real payment.",
                "severity": "HIGH",
                "weight": 85
            },
            "fake_watermark": {
                "id": "fake_watermark",
                "name": "AI: FAKE Watermark Confirmed",
                "description": "Gemini AI confirmed a FAKE stamp/watermark is present on this screenshot.",
                "severity": "CRITICAL",
                "weight": 98
            },
            "manipulated_screenshot": {
                "id": "ela_manipulation",
                "name": "AI: Manipulated Screenshot",
                "description": "Gemini AI detected signs of digital manipulation or editing in this screenshot.",
                "severity": "HIGH",
                "weight": 80
            },
            "mandate_request": {
                "id": "mandate_request",
                "name": "AI: Debit Authorization Request",
                "description": "Gemini AI confirmed this is a mandate/debit authorization, NOT a completed payment.",
                "severity": "CRITICAL",
                "weight": 92
            }
        }
        if gemini_fraud_type in fraud_type_map:
            ai_rule = fraud_type_map[gemini_fraud_type]
            # Add only if not already present
            existing_ids = {r["id"] for r in triggered_rules}
            if ai_rule["id"] not in existing_ids:
                triggered_rules.append(ai_rule)

    # ── 5. Compute Final Risk Score ───────────────────────
    risk_score = compute_risk_score(triggered_rules, ela_score, gemini_verdict)

    # ── 6. Final Verdict ──────────────────────────────────
    if risk_score >= 60 or gemini_verdict == "FRAUD":
        final_verdict = "FRAUD"
    elif risk_score >= 40:
        final_verdict = "SUSPICIOUS"
    else:
        final_verdict = "GENUINE"

    # Override: if Gemini says GENUINE with high confidence and no critical rules
    critical_rules = [r for r in triggered_rules if r.get("severity") == "CRITICAL"]
    if gemini_verdict == "GENUINE" and gemini_confidence >= 80 and not critical_rules:
        final_verdict = "GENUINE"
        risk_score = min(risk_score, 30)

    # Confidence percentage
    if final_verdict == "FRAUD":
        confidence = min(100, max(60, risk_score))
    elif final_verdict == "GENUINE":
        confidence = min(100, max(60, 100 - risk_score))
    else:
        confidence = 50

    # Merge transaction details with Gemini info
    if gemini_info.get("amount") and "amount" not in transaction_details:
        try:
            amt_str = gemini_info["amount"].replace("₹", "").replace(",", "").strip()
            transaction_details["amount"] = float(amt_str)
        except:
            pass
    if gemini_info.get("upi_id"):
        transaction_details["upi_id"] = gemini_info["upi_id"]
    if gemini_info.get("transaction_id"):
        transaction_details["transaction_id"] = gemini_info["transaction_id"]
    if gemini_info.get("recipient"):
        transaction_details["recipient"] = gemini_info["recipient"]
    if gemini_info.get("app"):
        transaction_details["app"] = gemini_info["app"]
    if gemini_info.get("status"):
        transaction_details["status"] = gemini_info["status"]

    # Encode image thumbnail
    thumb_buf = io.BytesIO()
    thumb = image.copy()
    thumb.thumbnail((400, 600))
    thumb.save(thumb_buf, format="JPEG", quality=80)
    thumb_b64 = base64.b64encode(thumb_buf.getvalue()).decode()

    return {
        "filename": filename,
        "verdict": final_verdict,
        "confidence": confidence,
        "risk_score": risk_score,
        "fraud_reasons": triggered_rules,
        "transaction_details": transaction_details,
        "gemini_summary": gemini_summary,
        "gemini_verdict": gemini_verdict,
        "ela_score": ela_score,
        "ela_image": ela_b64,
        "extracted_text": extracted_text[:500] if extracted_text else "",
        "thumbnail": thumb_b64
    }
