from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Boolean,
    ForeignKey, UniqueConstraint
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
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

    # Legacy (keep for compatibility / last seen machine)
    machine_fingerprint = Column(String, nullable=True)

    active = Column(Boolean, default=True)

    # seat-based licensing
    max_seats = Column(Integer, nullable=False, default=1)
    used_seats = Column(Integer, nullable=False, default=0)


class Activation(Base):
    """
    Tracks each machine activation per license (seat-based).
    """
    __tablename__ = "activations"

    id = Column(Integer, primary_key=True, index=True)
    license_db_id = Column(Integer, ForeignKey("licenses.id"), index=True, nullable=False)
    machine_fingerprint = Column(String, nullable=False)
    activated_at = Column(DateTime, nullable=False)

    __table_args__ = (
        UniqueConstraint("license_db_id", "machine_fingerprint", name="uq_license_machine"),
    )


Base.metadata.create_all(bind=engine)

# ---------- FastAPI app ----------
app = FastAPI(title="License Server")

# ---------- Schemas ----------

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
    max_seats: Optional[int] = None
    used_seats: Optional[int] = None


# ---------- Helpers ----------

def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def license_to_dict(db: Session, lic: License) -> Dict[str, Any]:
    used = db.query(Activation).filter_by(license_db_id=lic.id).count()

    return {
        "id": lic.id,
        "license_id": lic.license_id,
        "duration_seconds": lic.duration_seconds,
        "first_activation_at": lic.first_activation_at.isoformat() if lic.first_activation_at else None,
        "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
        "last_machine": (lic.machine_fingerprint[:20] + "...") if lic.machine_fingerprint else None,
        "active": lic.active,
        "max_seats": lic.max_seats,
        "used_seats": used,
    }


# ---------- Root (healthcheck / keep-alive) ----------

@app.get("/")
def root():
    """
    Simple healthcheck endpoint for cron-job.org or uptime pings.
    """
    return {"status": "ok", "message": "License server running"}


# ---------- Admin endpoint: register generated license ----------

@app.post("/admin/create", response_model=ActivateResponse)
def admin_create_license(payload: LicenseCreate, db: Session = Depends(get_db)):
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
        duration_seconds=int(payload.duration_seconds),
        max_seats=int(payload.max_seats),
        used_seats=0,
        active=True
    )
    db.add(lic)
    db.commit()
    db.refresh(lic)

    return ActivateResponse(
        ok=True,
        message=f"License created (max_seats={lic.max_seats})",
        expires_at=None,
        duration_seconds=lic.duration_seconds,
        max_seats=lic.max_seats,
        used_seats=0
    )


# ---------- Client endpoint: first activation / reuse + seats ----------

@app.post("/activate", response_model=ActivateResponse)
def activate(payload: ActivateRequest, db: Session = Depends(get_db)):
    lic = db.query(License).filter_by(license_id=payload.license_id).first()
    if not lic or not lic.active:
        raise HTTPException(status_code=400, detail="Unknown or inactive license")

    # Check key
    if lic.key_hash != hash_key(payload.raw_key):
        raise HTTPException(status_code=400, detail="Invalid key for this License ID")

    now = utc_now()

    # Expiry check (if already has expires_at)
    if lic.expires_at is not None and lic.expires_at <= now:
        raise HTTPException(status_code=400, detail="License expired")

    # If already activated on this machine (seat already consumed)
    existing_act = db.query(Activation).filter_by(
        license_db_id=lic.id,
        machine_fingerprint=payload.machine_fingerprint
    ).first()

    if existing_act:
        return ActivateResponse(
            ok=True,
            message="Already activated on this machine",
            expires_at=lic.expires_at,
            duration_seconds=lic.duration_seconds,
            max_seats=lic.max_seats,
            used_seats=db.query(Activation).filter_by(license_db_id=lic.id).count()
        )

    # Seat count
    used_seats = db.query(Activation).filter_by(license_db_id=lic.id).count()
    if used_seats >= lic.max_seats:
        raise HTTPException(status_code=400, detail="Max seats reached for this License ID")

    # First activation sets the expiry window
    if lic.first_activation_at is None:
        lic.first_activation_at = now
        if lic.duration_seconds == 0:
            lic.expires_at = None
        else:
            lic.expires_at = now + timedelta(seconds=int(lic.duration_seconds))

    # Create activation record (consume seat)
    act = Activation(
        license_db_id=lic.id,
        machine_fingerprint=payload.machine_fingerprint,
        activated_at=now
    )
    db.add(act)

    # Keep last machine in licenses table (optional / legacy)
    lic.machine_fingerprint = payload.machine_fingerprint

    # Update cached used_seats
    lic.used_seats = used_seats + 1

    db.commit()
    db.refresh(lic)

    return ActivateResponse(
        ok=True,
        message=f"Activated (seat {lic.used_seats}/{lic.max_seats})",
        expires_at=lic.expires_at,
        duration_seconds=lic.duration_seconds,
        max_seats=lic.max_seats,
        used_seats=lic.used_seats
    )


# ---------- Admin JSON endpoints (for syncing) ----------

@app.get("/admin/license-ids", response_model=List[str])
def admin_license_ids(db: Session = Depends(get_db)):
    """
    Lightweight endpoint for admin tool syncing.
    Returns: ["LICENSEID1", "LICENSEID2", ...]
    """
    rows = db.query(License.license_id).order_by(License.license_id.asc()).all()
    return [r[0] for r in rows if r and r[0]]


@app.get("/admin/license-exists/{license_id}")
def admin_license_exists(license_id: str, db: Session = Depends(get_db)):
    """
    Simple existence check for avoiding duplicates.
    """
    exists = db.query(License).filter_by(license_id=license_id).first() is not None
    return {"license_id": license_id, "exists": exists}


@app.get("/admin/licenses")
def view_all_licenses(db: Session = Depends(get_db)):
    """View all licenses in database (JSON)"""
    all_licenses = db.query(License).order_by(License.id.desc()).all()
    result = [license_to_dict(db, lic) for lic in all_licenses]
    return {"total": len(result), "licenses": result}


@app.get("/admin/activations")
def view_activations(db: Session = Depends(get_db)):
    """
    View all activation records (per seat).
    """
    acts = db.query(Activation).order_by(Activation.id.desc()).all()
    result = []
    for a in acts:
        result.append({
            "id": a.id,
            "license_db_id": a.license_db_id,
            "machine": (a.machine_fingerprint[:20] + "...") if a.machine_fingerprint else None,
            "activated_at": a.activated_at.isoformat() if a.activated_at else None
        })
    return {"total": len(result), "activations": result}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
