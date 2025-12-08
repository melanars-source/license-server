from datetime import datetime, timedelta
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


Base.metadata.create_all(bind=engine)

# ---------- FastAPI app ----------
app = FastAPI(title="License Server")

# ---------- Schemas ----------

class LicenseCreate(BaseModel):
    license_id: str
    raw_key: str
    duration_seconds: int  # 0 = perpetual


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
    # Simple hash; you can upgrade to HMAC/argon2 later
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------- Admin endpoint: register generated license ----------

@app.post("/admin/create", response_model=ActivateResponse)
def admin_create_license(payload: LicenseCreate):
    from fastapi import Depends
    db = next(get_db())

    existing = db.query(License).filter_by(license_id=payload.license_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="License ID already exists")

    key_hash = hash_key(payload.raw_key)

    lic = License(
        license_id=payload.license_id,
        key_hash=key_hash,
        duration_seconds=payload.duration_seconds,
    )
    db.add(lic)
    db.commit()
    db.refresh(lic)

    return ActivateResponse(
        ok=True,
        message="License created",
        expires_at=None,
        duration_seconds=payload.duration_seconds,
    )


# ---------- Client endpoint: first activation / reuse check ----------

@app.post("/activate", response_model=ActivateResponse)
def activate(payload: ActivateRequest):
    from fastapi import Depends
    db = next(get_db())

    lic = db.query(License).filter_by(license_id=payload.license_id).first()
    if not lic or not lic.active:
        raise HTTPException(status_code=400, detail="Unknown or inactive license")

    # Check key
    if lic.key_hash != hash_key(payload.raw_key):
        raise HTTPException(status_code=400, detail="Invalid key for this License ID")

    now = datetime.utcnow()

    # First activation
    if lic.first_activation_at is None:
        lic.first_activation_at = now
        if lic.duration_seconds == 0:
            lic.expires_at = None
        else:
            lic.expires_at = now + timedelta(seconds=lic.duration_seconds)
        lic.machine_fingerprint = payload.machine_fingerprint
        db.commit()
        db.refresh(lic)
        return ActivateResponse(
            ok=True,
            message="Activated (first use)",
            expires_at=lic.expires_at,
            duration_seconds=lic.duration_seconds,
        )

    # Already activated: enforce same machine + not expired
    if lic.machine_fingerprint != payload.machine_fingerprint:
        raise HTTPException(status_code=400, detail="License already bound to another machine")

    if lic.expires_at and lic.expires_at <= now:
        raise HTTPException(status_code=400, detail="License expired")

    return ActivateResponse(
        ok=True,
        message="Already activated on this machine",
        expires_at=lic.expires_at,
        duration_seconds=lic.duration_seconds,
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)




