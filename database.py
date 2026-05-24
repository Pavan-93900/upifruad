"""
database.py — SQLite audit log for UPI fraud scan history
"""
import aiosqlite
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "fraud_audit.db"


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                scan_time TEXT NOT NULL,
                verdict TEXT NOT NULL,
                confidence REAL NOT NULL,
                risk_score INTEGER NOT NULL,
                fraud_reasons TEXT,
                transaction_details TEXT,
                gemini_summary TEXT,
                ela_score REAL,
                image_data TEXT
            )
        """)
        await db.commit()


async def save_scan(
    filename: str,
    verdict: str,
    confidence: float,
    risk_score: int,
    fraud_reasons: list,
    transaction_details: dict,
    gemini_summary: str,
    ela_score: float,
    image_data: str = None
) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("""
            INSERT INTO scan_history
            (filename, scan_time, verdict, confidence, risk_score, fraud_reasons,
             transaction_details, gemini_summary, ela_score, image_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            filename,
            datetime.now().isoformat(),
            verdict,
            confidence,
            risk_score,
            json.dumps(fraud_reasons),
            json.dumps(transaction_details),
            gemini_summary,
            ela_score,
            image_data
        ))
        await db.commit()
        return cursor.lastrowid


async def get_all_scans(limit: int = 50) -> list:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT id, filename, scan_time, verdict, confidence, risk_score,
                   fraud_reasons, transaction_details, gemini_summary, ela_score
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = await cursor.fetchall()
        result = []
        for row in rows:
            r = dict(row)
            r["fraud_reasons"] = json.loads(r["fraud_reasons"] or "[]")
            r["transaction_details"] = json.loads(r["transaction_details"] or "{}")
            result.append(r)
        return result


async def get_scan_by_id(scan_id: int) -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM scan_history WHERE id = ?", (scan_id,)
        )
        row = await cursor.fetchone()
        if row:
            r = dict(row)
            r["fraud_reasons"] = json.loads(r["fraud_reasons"] or "[]")
            r["transaction_details"] = json.loads(r["transaction_details"] or "{}")
            return r
        return None


async def get_stats() -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT COUNT(*) FROM scan_history")
        total = (await cursor.fetchone())[0]

        cursor = await db.execute(
            "SELECT COUNT(*) FROM scan_history WHERE verdict = 'FRAUD'"
        )
        fraud_count = (await cursor.fetchone())[0]

        cursor = await db.execute(
            "SELECT COUNT(*) FROM scan_history WHERE verdict = 'GENUINE'"
        )
        genuine_count = (await cursor.fetchone())[0]

        cursor = await db.execute(
            "SELECT AVG(risk_score) FROM scan_history"
        )
        avg_risk = (await cursor.fetchone())[0] or 0

        return {
            "total_scans": total,
            "fraud_detected": fraud_count,
            "genuine_detected": genuine_count,
            "avg_risk_score": round(avg_risk, 1),
            "fraud_rate": round((fraud_count / total * 100) if total > 0 else 0, 1)
        }
