from fastapi import FastAPI, HTTPException, Depends, Request, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from typing import List, Optional
import uuid
import json
import asyncio
import os

# DB Imports
from sqlalchemy import create_engine, Column, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# App Imports
from app.models import AuditRequest, AuditResult, AuditSummary, AuditMetrics, ServiceInfo, Finding, SuspiciousIP
from app.audit_runner import run_audit_task
# --- FIX: IMPORTAR EL GENERADOR HTML ---
from app.utils import generate_html_report

# --- Database Setup (SQLite) ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./audit.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class AuditLog(Base):
    __tablename__ = "auditlog"
    id = Column(String, primary_key=True, index=True)
    timestamp = Column(String)
    server = Column(String)
    status = Column(String)
    result_json = Column(Text)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- App Setup ---
# app = FastAPI() # Replaced with APIRouter
router = APIRouter()

# Middleware handled in main.py
# app.add_middleware(...) 

# --- Endpoints ---

@router.post("/audit", response_model=AuditResult) # Removed /api prefix
async def start_audit(request: AuditRequest, db: Session = Depends(get_db)):
    loop = asyncio.get_event_loop()
    
    # Run audit in thread pool to avoid blocking
    try:
        result = await loop.run_in_executor(None, run_audit_task, request)
    except Exception as e:
        # Fallback error handling if runner explodes
        error_msg = str(e)
        if "PassphraseRequired" in error_msg:
             return JSONResponse(
                status_code=401,
                content={
                    "status": "error",
                    "code": "PASSPHRASE_REQUIRED",
                    "message": "Key is encrypted. Please provide passphrase."
                }
            )
        if "sudo: a terminal is required" in error_msg or "sudo: a password is required" in error_msg:
             return JSONResponse(
                status_code=401,
                content={
                    "status": "error",
                    "code": "SUDO_PASSWORD_REQUIRED",
                    "message": "Sudo requires password. Please provide SSH password."
                }
            )
        raise HTTPException(status_code=500, detail=error_msg)

    # Check result status for controlled errors
    if result.status == "failed":
        # Check specific findings or description for Passphrase
        error_desc = result.findings[0].description if result.findings else ""
        if "PassphraseRequired" in error_desc:
             return JSONResponse(
                status_code=401,
                content={
                    "status": "error",
                    "code": "PASSPHRASE_REQUIRED",
                    "message": "Key is encrypted. Please provide passphrase."
                }
            )
        if "sudo: a terminal is required" in error_desc or "sudo: a password is required" in error_desc:
             return JSONResponse(
                status_code=401,
                content={
                    "status": "error",
                    "code": "SUDO_PASSWORD_REQUIRED",
                    "message": "Sudo requires password. Please provide SSH password."
                }
            )

    # Save to DB
    db_audit = AuditLog(
        id=result.id,
        timestamp=result.timestamp,
        server=result.server,
        status=result.status,
        result_json=result.json()
    )
    db.add(db_audit)
    db.commit()
    
    return result

@router.get("/history", response_model=List[AuditResult]) # Removed /api prefix
def get_history(db: Session = Depends(get_db)):
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(10).all()
    results = []
    for log in logs:
        try:
            data = json.loads(log.result_json)
            # Reconstruct objects to match response model
            results.append(AuditResult(**data))
        except:
            continue
    return results

@router.get("/audit/{audit_id}/export") # Removed /api prefix
def export_audit_report(audit_id: str, format: str = "json", db: Session = Depends(get_db)):
    log = db.query(AuditLog).filter(AuditLog.id == audit_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Audit not found")
    
    try:
        audit_data = json.loads(log.result_json)
    except:
        raise HTTPException(status_code=500, detail="Corrupt audit data")

    if format == 'json':
        return Response(
            content=log.result_json, 
            media_type="application/json", 
            headers={"Content-Disposition": f"attachment; filename=audit-{audit_id}.json"}
        )
    
    if format == 'csv':
        # Simple CSV generation
        rows = ["Section,Key,Value"]
        
        # Summary
        summ = audit_data.get('summary', {})
        for k, v in summ.items(): rows.append(f"Summary,{k},{v}")
        
        # Metrics
        met = audit_data.get('metrics', {})
        for k, v in met.items(): rows.append(f"Metrics,{k},{v}")
        
        rows.append(",,") # Spacer
        
        # Services
        for s in audit_data.get('services', []):
            rows.append(f"Service,{s.get('name')},{s.get('status')} | {s.get('version')}")
            
        # Findings
        for f in audit_data.get('findings', []):
            rows.append(f"Finding,{f.get('severity')},{f.get('description')}")

        csv_content = "\n".join(rows)
        return Response(
            content=csv_content, 
            media_type="text/csv", 
            headers={"Content-Disposition": f"attachment; filename=audit-report-{audit_id}.csv"}
        )

    if format == 'html':
        # --- FIX: USE PROFESSIONAL GENERATOR ---
        # 1. Reconstruct the full AuditResult object from the DB JSON
        # This ensures the generator receives the correct data structure
        try:
            audit_result_obj = AuditResult(**audit_data)
            
            # 2. Call the generator
            html_content = generate_html_report(audit_result_obj)
            
            return Response(
                content=html_content, 
                media_type="text/html", 
                headers={"Content-Disposition": f"attachment; filename=audit-report-{audit_id}.html"}
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to generate HTML: {str(e)}")

    raise HTTPException(status_code=400, detail="Invalid format")
