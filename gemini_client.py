"""
gemini_client.py — Google Gemini Vision AI integration for UPI fraud analysis
"""
import os
import base64
import re
from io import BytesIO
from PIL import Image
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

FRAUD_ANALYSIS_PROMPT = """You are an expert UPI payment fraud detection AI trained to analyze Indian digital payment screenshots.

Analyze this screenshot and determine if it's a GENUINE payment or FRAUD/FAKE.

Known fraud patterns you must detect:
1. **FAKE watermark/stamp** — "FAKE!" text or stamp overlaid on screenshot
2. **Google Pay Rewards Scam** — Shows a "rewards/cashback received" screen instead of actual payment (e.g., "From Google Pay rewards", "Rewarded for doing your first card transaction")
3. **PhonePe Sound Box Scam** — Payment of ₹1 to a payment gateway (e.g., zomatoonlineorder.rzp@rxairtel) to trigger a beep sound without real payment
4. **Missing Debit Account** — Genuine payment receipts always show which account was debited. Missing this = suspicious
5. **Manipulated Screenshot** — Edited amounts, fake transaction IDs, inconsistent fonts
6. **Mandate Request Scam** — Shows a debit authorization/mandate request disguised as a payment confirmation

Genuine payment indicators:
- Shows "Payment successful" or "Transaction successful" clearly
- Has sender's full name and bank account details
- Has valid UPI transaction ID and UTR number
- Amount matches a realistic purchase amount
- Consistent app branding (PhonePe, Google Pay, Paytm, Navi UPI)

Respond in this EXACT JSON format:
{
  "verdict": "GENUINE" or "FRAUD",
  "confidence": 0-100,
  "fraud_type": "none" or one of ["fake_watermark", "rewards_scam", "sound_box_scam", "missing_debit_account", "manipulated_screenshot", "mandate_request"],
  "summary": "2-3 sentence explanation of why this is genuine or fraudulent",
  "extracted_info": {
    "app": "PhonePe/Google Pay/Paytm/Navi/Other",
    "amount": "amount as string or null",
    "recipient": "recipient name or null",
    "upi_id": "UPI ID or null",
    "transaction_id": "transaction ID or null",
    "status": "Successful/Pending/Failed/Unknown"
  }
}

Return ONLY valid JSON, no markdown or extra text."""


async def analyze_with_gemini(image: Image.Image) -> dict:
    """
    Send image to Gemini Vision API for fraud analysis.
    Returns structured analysis result.
    """
    if not GEMINI_API_KEY or GEMINI_API_KEY == "your_gemini_api_key_here":
        return _fallback_result()

    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel("gemini-1.5-flash")

        # Convert image to bytes
        buf = BytesIO()
        image_rgb = image.convert("RGB")
        image_rgb.save(buf, format="JPEG", quality=95)
        image_bytes = buf.getvalue()

        # Create parts
        import google.generativeai.types as types

        response = model.generate_content([
            FRAUD_ANALYSIS_PROMPT,
            {
                "mime_type": "image/jpeg",
                "data": base64.b64encode(image_bytes).decode()
            }
        ])

        # Parse JSON response
        text = response.text.strip()
        # Remove markdown code blocks if present
        text = re.sub(r'^```json\s*', '', text)
        text = re.sub(r'^```\s*', '', text)
        text = re.sub(r'\s*```$', '', text)

        import json
        result = json.loads(text)
        return result

    except Exception as e:
        print(f"[Gemini] Error: {e}")
        return _fallback_result()


def _fallback_result() -> dict:
    """Return a neutral result when Gemini is unavailable."""
    return {
        "verdict": "UNKNOWN",
        "confidence": 50,
        "fraud_type": "none",
        "summary": "Gemini Vision AI analysis unavailable. Please configure your API key for AI-powered analysis. Forensic analysis results are shown below.",
        "extracted_info": {
            "app": "Unknown",
            "amount": None,
            "recipient": None,
            "upi_id": None,
            "transaction_id": None,
            "status": "Unknown"
        }
    }
