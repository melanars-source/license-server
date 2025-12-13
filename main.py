from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Boolean
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import hashlib

# ---------- DB setup ----------
DATABASE_URL = "sqlite:///./licenses.db"

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
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

# ---------- FastAPI app ----------
app = FastAPI(title="License Server")

# ---------- Schemas ----------

class LicenseCreate(BaseModel):
    license_id: str
    raw_key: str
    duration_seconds: int  # 0 = perpetual
    max_seats: int         # NEW


class ActivateRequest(BaseModel):
    license_id: str
    raw_key: str
    machine_fingerprint: str


class ActivateResponse(BaseModel):
    ok: bool
    message: str
    expires_at: Optional[datetime]
    duration_seconds: int


# ---------- Helpers ----------

def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------- Root (healthcheck / keep-alive) ----------

@app.get("/")
def root():
    """
    Simple healthcheck endpoint for cron-job.org or uptime pings.
    """
    return {"status": "ok", "message": "License server running"}


# ---------- Admin endpoint: register generated license ----------

@app.post("/admin/create", response_model=ActivateResponse)
def admin_create_license(payload: LicenseCreate):
    db = next(get_db())

    if payload.max_seats <= 0:
        raise HTTPException(status_code=400, detail="max_seats must be positive")

    existing = db.query(License).filter_by(license_id=payload.license_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="License ID already exists")

    key_hash = hash_key(payload.raw_key)

    lic = License(
        license_id=payload.license_id,
        key_hash=key_hash,
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


# ---------- Client endpoint: first activation / reuse + seats ----------

@app.post("/activate", response_model=ActivateResponse)
def activate(payload: ActivateRequest):
    db = next(get_db())

    lic = db.query(License).filter_by(license_id=payload.license_id).first()
    if not lic or not lic.active:
        raise HTTPException(status_code=400, detail="Unknown or inactive license")

    # Check key
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


# ---------- Admin View Endpoints ----------

@app.get("/admin/licenses")
def view_all_licenses():
    """View all licenses in database"""
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
            "machine_fingerprint": lic.machine_fingerprint[:20] + "..." if lic.machine_fingerprint else None,
            "active": lic.active,
            "max_seats": lic.max_seats,
            "used_seats": lic.used_seats,
        })

    return {
        "total": len(result),
        "licenses": result
    }


@app.get("/admin/activations")
def view_activations():
    """View only activated licenses"""
    db = next(get_db())

    activated = db.query(License).filter(License.first_activation_at.isnot(None)).all()

    result = []
    for lic in activated:
        result.append({
            "license_id": lic.license_id,
            "activated_at": lic.first_activation_at.isoformat(),
            "expires_at": lic.expires_at.isoformat() if lic.expires_at else "PERPETUAL",
            "machine": lic.machine_fingerprint[:20] + "..." if lic.machine_fingerprint else None,
            "active": lic.active,
            "max_seats": lic.max_seats,
            "used_seats": lic.used_seats,
        })

    return {
        "total_activated": len(result),
        "activations": result
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
