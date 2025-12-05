from fastapi import APIRouter, HTTPException, Depends
from sqlmodel import Session, select
from app.models import AuditRequest, AuditResult, AuditLog
from app.audit_runner import run_audit_task
from app.database import get_session
import asyncio
import json

router = APIRouter()

@router.post("/audit", response_model=AuditResult)
async def start_audit(request: AuditRequest, session: Session = Depends(get_session)):
    """
    Starts a security audit synchronously (waits for result).
    Executes the blocking SSH task in a separate thread to avoid blocking the event loop.
    """
    try:
        # Run blocking task in executor
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, run_audit_task, request)
        
        # Save to DB
        db_log = AuditLog(
            id=result.id,
            timestamp=result.timestamp,
            server=result.server,
            status=result.status,
            result_json=result.json()
        )
        session.add(db_log)
        session.commit()
        session.refresh(db_log)
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/audit/{audit_id}", response_model=AuditResult)
async def get_audit(audit_id: str, session: Session = Depends(get_session)):
    """
    Retrieves a past audit result from the database.
    """
    audit_log = session.get(AuditLog, audit_id)
    if not audit_log:
        raise HTTPException(status_code=404, detail="Audit not found")
    
    # Reconstruct AuditResult from stored JSON
    return AuditResult.parse_raw(audit_log.result_json)

@router.get("/audits")
async def list_audits(session: Session = Depends(get_session)):
    """
    Lists recent audits.
    """
    statement = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(20)
    results = session.exec(statement).all()
    return results
