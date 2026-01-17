from datetime import datetime, timedelta, timezone
from typing import Optional
import os
import hashlib
import secrets 

from fastapi import FastAPI, HTTPException, Depends, Security, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


# ============================================================
# Config
# ============================================================

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./licenses.db")

# IMPORTANT: set this in Render environment variables
# Example (generate locally): python -c "import secrets; print(secrets.token_urlsafe(32))"
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")

# Header name used by admin tool (client/admin GUI must send this header)
ADMIN_API_KEY_HEADER_NAME = "X-Admin-Key"

# Basic brute-force / abuse guard for activation endpoint (very light)
# This is not a replacement for proper rate limiting at proxy/CDN level.
ACTIVATE_FAIL_SLEEP_SECONDS = 0.0  # set to e.g. 0.2 if you want tiny slowdown


# ============================================================
# DB setup
# ============================================================

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class License(Base):
    __tablename__ = "licenses"

    id = Column(Integer, primary_key=True, index=True)
    license_id = Column(String, unique=True, index=True)
    key_hash = Column(String, nullable=False)
    duration_seconds = Column(Integer, nullable=False)  # 0 = perpetual
    first_activation_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    machine_fingerprint = Column(String, nullable=True)
    active = Column(Boolean, default=True)

    # seat-based licensing
    max_seats = Column(Integer, nullable=False, default=1)
    used_seats = Column(Integer, nullable=False, default=0)


Base.metadata.create_all(bind=engine)


# ============================================================
# FastAPI app
# Optionally disable docs in production by setting:
#   DISABLE_PUBLIC_DOCS=1
# ============================================================

disable_public_docs = os.getenv("DISABLE_PUBLIC_DOCS", "0") == "1"
app = FastAPI(
    title="License Server",
    docs_url=None if disable_public_docs else "/docs",
    redoc_url=None if disable_public_docs else "/redoc",
    openapi_url=None if disable_public_docs else "/openapi.json",
)


# ============================================================
# Schemas
# ============================================================

class LicenseCreate(BaseModel):
    license_id: str
    raw_key: str
    duration_seconds: int  # 0 = perpetual
    max_seats: int


class ActivateRequest(BaseModel):
    license_id: str
    raw_key: str
    machine_fingerprint: str


class ActivateResponse(BaseModel):
    ok: bool
    message: str
    expires_at: Optional[datetime]
    duration_seconds: int


# ============================================================
# Helpers
# ============================================================

def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --- Admin auth dependency (API key header) ---
admin_key_header = APIKeyHeader(name=ADMIN_API_KEY_HEADER_NAME, auto_error=False)

def require_admin(api_key: str = Security(admin_key_header)) -> None:
    """
    Protects /admin/* endpoints using a single API key in a header.
    """
    if not ADMIN_API_KEY:
        # Misconfiguration: server started without admin key
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server misconfigured: ADMIN_API_KEY is not set."
        )

    if not api_key or not secrets.compare_digest(api_key, ADMIN_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized (missing/invalid admin key)."
        )


# ============================================================
# Root (healthcheck / keep-alive)
# ============================================================

@app.get("/")
def root():
    return {"status": "ok", "message": "License server running"}


# ============================================================
# Admin endpoint: register generated license (PROTECTED)
# ============================================================

@app.post("/admin/create", response_model=ActivateResponse, dependencies=[Depends(require_admin)])
def admin_create_license(payload: LicenseCreate):
    db = next(get_db())

    if payload.max_seats <= 0:
        raise HTTPException(status_code=400, detail="max_seats must be positive")

    if payload.duration_seconds < 0:
        raise HTTPException(status_code=400, detail="duration_seconds must be >= 0")

    existing = db.query(License).filter_by(license_id=payload.license_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="License ID already exists")

    lic = License(
        license_id=payload.license_id,
        key_hash=hash_key(payload.raw_key),
        duration_seconds=payload.duration_seconds,
        max_seats=payload.max_seats,
        used_seats=0
    )
    db.add(lic)
    db.commit()
    db.refresh(lic)

    return ActivateResponse(
        ok=True,
        message=f"License created (max_seats={lic.max_seats})",
        expires_at=None,
        duration_seconds=payload.duration_seconds,
    )


# ============================================================
# Client endpoint: first activation / reuse + seats (PUBLIC)
# ============================================================

@app.post("/activate", response_model=ActivateResponse)
def activate(payload: ActivateRequest):
    db = next(get_db())

    lic = db.query(License).filter_by(license_id=payload.license_id).first()
    if not lic or not lic.active:
        raise HTTPException(status_code=400, detail="Unknown or inactive license")

    # Check key hash (server-side)
    if lic.key_hash != hash_key(payload.raw_key):
        raise HTTPException(status_code=400, detail="Invalid key for this License ID")

    now = datetime.now(timezone.utc)

    # If never activated and no seats used yet
    if lic.first_activation_at is None and lic.used_seats == 0:
        if lic.used_seats >= lic.max_seats:
            raise HTTPException(status_code=400, detail="Max seats reached for this License ID")

        lic.first_activation_at = now
        if lic.duration_seconds == 0:
            lic.expires_at = None
        else:
            lic.expires_at = now + timedelta(seconds=lic.duration_seconds)

        lic.machine_fingerprint = payload.machine_fingerprint
        lic.used_seats = 1
        db.commit()
        db.refresh(lic)

        return ActivateResponse(
            ok=True,
            message="Activated (first use, seat 1)",
            expires_at=lic.expires_at,
            duration_seconds=lic.duration_seconds,
        )

    # Already activated at least once
    # Same machine trying again
    if lic.machine_fingerprint == payload.machine_fingerprint:
        if lic.expires_at and lic.expires_at <= now:
            raise HTTPException(status_code=400, detail="License expired")

        return ActivateResponse(
            ok=True,
            message="Already activated on this machine",
            expires_at=lic.expires_at,
            duration_seconds=lic.duration_seconds,
        )

    # Different machine trying to use this License ID
    if lic.used_seats >= lic.max_seats:
        raise HTTPException(status_code=400, detail="Max seats reached for this License ID")

    # Allow new machine seat
    lic.used_seats += 1
    lic.machine_fingerprint = payload.machine_fingerprint

    # If somehow first_activation_at is still None, set it now
    if lic.first_activation_at is None:
        lic.first_activation_at = now
        if lic.duration_seconds == 0:
            lic.expires_at = None
        else:
            lic.expires_at = now + timedelta(seconds=lic.duration_seconds)

    db.commit()
    db.refresh(lic)

    return ActivateResponse(
        ok=True,
        message=f"Activated on another machine (seat {lic.used_seats}/{lic.max_seats})",
        expires_at=lic.expires_at,
        duration_seconds=lic.duration_seconds,
    )


# ============================================================
# Admin View Endpoints (PROTECTED)
# ============================================================

@app.get("/admin/licenses", dependencies=[Depends(require_admin)])
def view_all_licenses():
    db = next(get_db())

    all_licenses = db.query(License).all()
    result = []

    for lic in all_licenses:
        result.append({
            "id": lic.id,
            "license_id": lic.license_id,
            "duration_seconds": lic.duration_seconds,
            "first_activation_at": lic.first_activation_at.isoformat() if lic.first_activation_at else None,
            "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
            "machine_fingerprint": (lic.machine_fingerprint[:20] + "...") if lic.machine_fingerprint else None,
            "active": lic.active,
            "max_seats": lic.max_seats,
            "used_seats": lic.used_seats,
        })

    return {"total": len(result), "licenses": result}


@app.get("/admin/activations", dependencies=[Depends(require_admin)])
def view_activations():
    db = next(get_db())

    activated = db.query(License).filter(License.first_activation_at.isnot(None)).all()
    result = []

    for lic in activated:
        result.append({
            "license_id": lic.license_id,
            "activated_at": lic.first_activation_at.isoformat(),
            "expires_at": lic.expires_at.isoformat() if lic.expires_at else "PERPETUAL",
            "machine": (lic.machine_fingerprint[:20] + "...") if lic.machine_fingerprint else None,
            "active": lic.active,
            "max_seats": lic.max_seats,
            "used_seats": lic.used_seats,
        })

    return {"total_activated": len(result), "activations": result}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
