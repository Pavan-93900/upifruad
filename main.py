"""
main.py — FastAPI application entry point for UPI Fraud Detection System
"""
import os
import io
import base64
from pathlib import Path
from fastapi import FastAPI, File, UploadFile, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from contextlib import asynccontextmanager

from database import init_db, save_scan, get_all_scans, get_scan_by_id, get_stats
from analyzer import analyze_screenshot

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
ALLOWED_TYPES = {"image/jpeg", "image/jpg", "image/png", "image/webp", "image/gif"}
MAX_SIZE_MB = 15


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    print("UPI Fraud Detection System started")
    print(f"Frontend directory: {FRONTEND_DIR}")
    yield
    print("Shutting down...")


app = FastAPI(
    title="UPI Fraud Detection API",
    description="AI-powered UPI payment screenshot fraud detection using Gemini Vision + forensic analysis",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend static files
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return HTMLResponse(content=index_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>UPI Fraud Detection API</h1><p>Frontend not found.</p>")


@app.post("/api/analyze")
async def analyze_upi_screenshot(file: UploadFile = File(...)):
    """Analyze a UPI payment screenshot for fraud indicators."""

    # Validate file type
    if file.content_type not in ALLOWED_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {file.content_type}. Please upload PNG, JPG, or WEBP."
        )

    # Read and validate size
    contents = await file.read()
    size_mb = len(contents) / (1024 * 1024)
    if size_mb > MAX_SIZE_MB:
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({size_mb:.1f}MB). Maximum allowed: {MAX_SIZE_MB}MB"
        )

    # Run analysis
    result = await analyze_screenshot(contents, file.filename)

    if "error" in result:
        raise HTTPException(status_code=422, detail=result["error"])

    # Save to audit log (store thumbnail only, not full image)
    scan_id = await save_scan(
        filename=file.filename,
        verdict=result["verdict"],
        confidence=result["confidence"],
        risk_score=result["risk_score"],
        fraud_reasons=result["fraud_reasons"],
        transaction_details=result["transaction_details"],
        gemini_summary=result["gemini_summary"],
        ela_score=result["ela_score"],
        image_data=result.get("thumbnail")
    )

    result["scan_id"] = scan_id
    return JSONResponse(content=result)


@app.post("/api/analyze-batch")
async def analyze_batch(files: list[UploadFile] = File(...)):
    """Analyze multiple UPI screenshots at once (max 10)."""
    if len(files) > 10:
        raise HTTPException(status_code=400, detail="Maximum 10 files per batch.")

    results = []
    for file in files:
        if file.content_type not in ALLOWED_TYPES:
            results.append({"filename": file.filename, "error": "Unsupported file type"})
            continue

        contents = await file.read()
        result = await analyze_screenshot(contents, file.filename)

        if "error" not in result:
            scan_id = await save_scan(
                filename=file.filename,
                verdict=result["verdict"],
                confidence=result["confidence"],
                risk_score=result["risk_score"],
                fraud_reasons=result["fraud_reasons"],
                transaction_details=result["transaction_details"],
                gemini_summary=result["gemini_summary"],
                ela_score=result["ela_score"],
                image_data=result.get("thumbnail")
            )
            result["scan_id"] = scan_id

        results.append(result)

    return JSONResponse(content={"batch_results": results, "total": len(results)})


@app.get("/api/history")
async def get_history(limit: int = 50):
    """Get scan history from audit log."""
    scans = await get_all_scans(limit=limit)
    return JSONResponse(content={"scans": scans, "total": len(scans)})


@app.get("/api/history/{scan_id}")
async def get_scan_detail(scan_id: int):
    """Get detailed result for a specific scan."""
    scan = await get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse(content=scan)


@app.get("/api/stats")
async def get_statistics():
    """Get dashboard statistics."""
    stats = await get_stats()
    return JSONResponse(content=stats)


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    from gemini_client import GEMINI_API_KEY
    return {
        "status": "running",
        "gemini_configured": bool(GEMINI_API_KEY and GEMINI_API_KEY != "your_gemini_api_key_here"),
        "version": "2.0.0"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
