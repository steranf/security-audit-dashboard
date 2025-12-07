from typing import Optional, List, Dict, Any
from sqlmodel import Field, SQLModel, JSON
from pydantic import BaseModel, validator
import re
from datetime import datetime

# --- Request Models (Pydantic) ---

class AuditOptions(BaseModel):
    fast: bool = False
    silent: bool = False

class AuditRequest(BaseModel):
    server: str
    user: str
    port: int = 22
    mode: str = "json"
    lines: int = 100
    services: str = ""
    passphrase: Optional[str] = None
    password: Optional[str] = None
    options: Optional[AuditOptions] = None

    @validator('server')
    def validate_server(cls, v):
        # Strict Regex for IP or Hostname
        regex = r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^localhost$"
        if not re.match(regex, v):
            raise ValueError('Invalid server format. Must be a valid IP or Hostname.')
        return v

    @validator('port')
    def validate_port(cls, v):
        if not 1 <= v <= 65535:
            raise ValueError('Port must be between 1 and 65535.')
        return v

# --- Response/DB Models (SQLModel) ---

class AuditLog(SQLModel, table=True):
    id: Optional[str] = Field(default=None, primary_key=True)
    timestamp: str
    server: str
    status: str
    # We store the full nested result as a JSON blob for simplicity in SQLite
    # In a larger Postgres app, we might normalize this.
    result_json: str = Field(default="{}") 

# --- Frontend Response Structure ---

class AuditSummary(BaseModel):
    critical: int
    warning: int
    info: int

class AuditMetrics(BaseModel):
    cpu: str
    ram: str
    disk: str
    connections: Optional[int] = 0

class ServiceInfo(BaseModel):
    name: str
    status: str
    version: str

class Finding(BaseModel):
    severity: str
    description: str
    recommendation: Optional[str] = None

class SuspiciousIP(BaseModel):
    ip: str
    country: str
    reason: str

class AuditResult(BaseModel):
    id: str
    status: str
    server: str
    timestamp: str
    summary: AuditSummary
    metrics: AuditMetrics
    services: List[ServiceInfo]
    findings: List[Finding]
    logs: List[str]
    ips: List[SuspiciousIP]
    raw_output: Optional[str] = None # For debugging or text mode
