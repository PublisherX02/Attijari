"""database.py — PostgreSQL models and connection management via SQLAlchemy.

Tables:
  - emails:     processed email records with full analysis data
  - blocklist:  blocked indicators (email, domain, IP, hash)
  - whitelist:  whitelisted indicators (override blocklist)
  - audit_log:  analyst actions and system events
  - reports:    generated admin reports

All tables use timezone-aware timestamps.  Connection is pooled (pool_size=5).
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Optional

from dotenv import load_dotenv
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker
import logging
from logging.handlers import RotatingFileHandler
import json

load_dotenv()

# Setup secure audit logger (ISO 27001 Log Segregation)
AUDIT_LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "audit_secure.log")
os.makedirs(os.path.dirname(AUDIT_LOG_FILE), exist_ok=True)
audit_logger = logging.getLogger("iso27001_audit")
audit_logger.setLevel(logging.INFO)
# Max 10MB per file, keep 10 backups
if not audit_logger.handlers:
    handler = RotatingFileHandler(AUDIT_LOG_FILE, maxBytes=10*1024*1024, backupCount=10)
    handler.setFormatter(logging.Formatter('{"ts": "%(asctime)s", "event": %(message)s}'))
    audit_logger.addHandler(handler)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/attijari_db",
)

# ---------------------------------------------------------------------------
# Engine & session factory
# ---------------------------------------------------------------------------
engine = create_engine(
    DATABASE_URL,
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,  # auto-reconnect stale connections
    echo=False,
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

Base = declarative_base()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class Email(Base):
    """Processed email record — one row per unique idempotency key."""

    __tablename__ = "emails"

    id = Column(Integer, primary_key=True, autoincrement=True)
    idempotency_key = Column(String(128), unique=True, nullable=False, index=True)
    message_id = Column(String(512), nullable=True)
    raw_sha256 = Column(String(64), nullable=False)
    sender = Column(String(512), nullable=True)
    sender_domain = Column(String(255), nullable=True)
    subject = Column(Text, nullable=True)
    attachment_count = Column(Integer, default=0)
    status = Column(
        String(20),
        nullable=False,
        default="recu",
        index=True,
    )  # pending, recu, accepted, escalated, quarantined, released
    rules_result = Column(JSONB, nullable=True)
    enrichment_result = Column(JSONB, nullable=True)
    llm_result = Column(JSONB, nullable=True)
    llm_reasoning = Column(Text, nullable=True)
    parse_errors = Column(JSONB, nullable=True)
    email_date = Column(DateTime(timezone=True), nullable=True)  # original Date header from the email
    analyst_action = Column(String(50), nullable=True)
    analyst_notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    audit_entries = relationship("AuditLog", back_populates="email", cascade="all, delete-orphan")


class Blocklist(Base):
    """Blocked indicators — email addresses, domains, IPs, file hashes."""

    __tablename__ = "blocklist"

    id = Column(Integer, primary_key=True, autoincrement=True)
    indicator_type = Column(
        String(20), nullable=False,
    )  # email, domain, ip, hash
    value = Column(String(512), nullable=False)
    source = Column(String(20), nullable=False, default="auto")  # manual, auto, cascade
    confirmed_by = Column(String(255), nullable=True)
    active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("indicator_type", "value", name="uq_blocklist_type_value"),
        Index("ix_blocklist_active_type", "active", "indicator_type"),
    )


class Whitelist(Base):
    """Whitelisted indicators — always override blocklist (CLAUDE.md rule)."""

    __tablename__ = "whitelist"

    id = Column(Integer, primary_key=True, autoincrement=True)
    indicator_type = Column(String(20), nullable=False)  # email, domain, ip
    value = Column(String(512), nullable=False)
    reason = Column(Text, nullable=True)
    created_by = Column(String(255), nullable=True)
    active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        UniqueConstraint("indicator_type", "value", name="uq_whitelist_type_value"),
    )


class AuditLog(Base):
    """Audit trail — every analyst action and significant system event."""

    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=True)
    action = Column(String(50), nullable=False)  # release, quarantine, override, blocklist_add, etc.
    actor = Column(String(255), nullable=True)  # analyst name or 'system'
    details = Column(JSONB, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)

    email = relationship("Email", back_populates="audit_entries")


class AnalystFeedback(Base):
    """Analyst feedback on verdicts — used to train the pipeline over time.

    When an analyst releases an escalated email (false positive) or quarantines
    an accepted one (false negative), they provide reasoning. This feedback
    drives whitelist/blocklist updates and is available for future LLM prompt
    enrichment.
    """

    __tablename__ = "analyst_feedback"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False)
    action = Column(String(20), nullable=False)  # release, quarantine
    pipeline_verdict = Column(String(20), nullable=True)  # what the pipeline said
    analyst_verdict = Column(String(20), nullable=True)  # what the analyst decided
    reasoning = Column(Text, nullable=False)  # why the analyst disagrees
    domain = Column(String(255), nullable=True)  # domain affected
    indicator_type = Column(String(20), nullable=True)  # whitelist or blocklist
    indicator_value = Column(String(512), nullable=True)  # value added to list
    created_at = Column(DateTime(timezone=True), default=utcnow)

    email = relationship("Email")


class Report(Base):
    """Generated admin reports stored for dashboard access."""

    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    report_type = Column(String(20), nullable=False)  # daily, hourly, weekly
    period_start = Column(DateTime(timezone=True), nullable=False)
    period_end = Column(DateTime(timezone=True), nullable=False)
    data = Column(JSONB, nullable=False)
    delivered_via = Column(JSONB, nullable=True)  # ["smtp", "slack", "dashboard"]
    created_at = Column(DateTime(timezone=True), default=utcnow)


class User(Base):
    """System users for the Dashboard (ISO 27001 Access Control)."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    totp_secret = Column(String(64), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


# ---------------------------------------------------------------------------
# Database initialization
# ---------------------------------------------------------------------------

def init_db():
    """Create all tables if they don't exist. Safe to call multiple times."""
    Base.metadata.create_all(bind=engine)
    print("[DB] All tables created / verified.")
    
    # Initialize default admin if no users exist
    try:
        db = SessionLocal()
        import bcrypt
        import pyotp
        if db.query(User).count() == 0:
            default_pass = os.getenv("DASHBOARD_PASS", "admin").encode("utf-8")
            hashed = bcrypt.hashpw(default_pass, bcrypt.gensalt()).decode("utf-8")
            # Generate a consistent TOTP secret for the first run, or a random one
            totp_secret = pyotp.random_base32()
            admin = User(username=os.getenv("DASHBOARD_USER", "admin"), password_hash=hashed, totp_secret=totp_secret)
            db.add(admin)
            db.commit()
            print(f"\n=======================================================")
            print(f"[ISO 27001] ADMIN CREATED. MFA REQUIRED!")
            print(f"Username: {admin.username}")
            print(f"Password: (see DASHBOARD_PASS in .env)")
            print(f"TOTP Secret: {totp_secret}")
            print(f"Set this up in Google Authenticator!")
            print(f"=======================================================\n")
    except Exception as e:
        print(f"[DB] Error initializing admin: {e}")
    finally:
        db.close()


def get_db() -> Session:
    """Get a database session. Use in a with-statement or try/finally."""
    db = SessionLocal()
    try:
        return db
    except Exception:
        db.close()
        raise


# ---------------------------------------------------------------------------
# Helper functions used across the codebase
# ---------------------------------------------------------------------------

def get_cached_email(db: Session, idempotency_key: str) -> Optional[Email]:
    """Check if an email has already been processed (idempotency)."""
    return db.query(Email).filter(Email.idempotency_key == idempotency_key).first()


def save_email(db: Session, data: dict) -> Email:
    """Insert or update an email record from pipeline output."""
    existing = get_cached_email(db, data["idempotency_key"])
    if existing:
        # Update existing record
        for key, val in data.items():
            if key != "idempotency_key" and hasattr(existing, key):
                setattr(existing, key, val)
        existing.updated_at = utcnow()
        db.commit()
        db.refresh(existing)
        return existing

    email = Email(
        idempotency_key=data["idempotency_key"],
        message_id=data.get("message_id"),
        raw_sha256=data.get("raw_sha256", ""),
        sender=data.get("sender"),
        sender_domain=data.get("sender_domain"),
        subject=data.get("subject"),
        attachment_count=data.get("attachment_count", 0),
        status=data.get("status", "recu"),
        email_date=data.get("email_date"),
        rules_result=data.get("rules_result"),
        enrichment_result=data.get("enrichment_result"),
        llm_result=data.get("llm_result"),
        llm_reasoning=data.get("llm_reasoning"),
        parse_errors=data.get("parse_errors"),
    )
    db.add(email)
    db.commit()
    db.refresh(email)
    return email


def add_audit_entry(db: Session, action: str, actor: str = "system",
                    email_id: Optional[int] = None, details: Optional[dict] = None):
    """Record an action in the audit log and secure file."""
    # DB Log
    entry = AuditLog(
        email_id=email_id,
        action=action,
        actor=actor,
        details=details,
    )
    db.add(entry)
    db.commit()
    
    # Secure File Log (ISO 27001 Log Segregation)
    log_event = {
        "action": action,
        "actor": actor,
        "email_id": email_id,
        "details": details
    }
    audit_logger.info(json.dumps(log_event))


def is_blocked(db: Session, indicator_type: str, value: str) -> bool:
    """Check if an indicator is in the active blocklist."""
    val = value.strip().lower()
    return db.query(Blocklist).filter(
        Blocklist.indicator_type == indicator_type,
        Blocklist.value == val,
        Blocklist.active == True,
    ).first() is not None


def is_whitelisted(db: Session, indicator_type: str, value: str) -> bool:
    """Check if an indicator is in the active whitelist. Whitelist always wins."""
    val = value.strip().lower()
    return db.query(Whitelist).filter(
        Whitelist.indicator_type == indicator_type,
        Whitelist.value == val,
        Whitelist.active == True,
    ).first() is not None


def add_blocklist_entry(db: Session, indicator_type: str, value: str,
                        source: str = "auto", confirmed_by: Optional[str] = None) -> bool:
    """Add an indicator to the blocklist. Returns True if newly added."""
    val = value.strip().lower()
    if not val:
        return False

    # Whitelist always wins
    if is_whitelisted(db, indicator_type, val):
        print(f"[BLOCKLIST] Skipped {indicator_type}:{val} — whitelisted")
        return False

    existing = db.query(Blocklist).filter(
        Blocklist.indicator_type == indicator_type,
        Blocklist.value == val,
    ).first()

    if existing:
        if not existing.active:
            existing.active = True
            db.commit()
            return True
        return False

    entry = Blocklist(
        indicator_type=indicator_type,
        value=val,
        source=source,
        confirmed_by=confirmed_by,
    )
    db.add(entry)
    db.commit()
    return True


def save_feedback(db: Session, email_id: int, action: str, reasoning: str,
                   pipeline_verdict: str = None, domain: str = None,
                   indicator_type: str = None, indicator_value: str = None) -> AnalystFeedback:
    """Save analyst feedback for pipeline learning."""
    fb = AnalystFeedback(
        email_id=email_id,
        action=action,
        pipeline_verdict=pipeline_verdict,
        analyst_verdict=action,
        reasoning=reasoning,
        domain=domain,
        indicator_type=indicator_type,
        indicator_value=indicator_value,
    )
    db.add(fb)
    db.commit()
    db.refresh(fb)
    return fb


def get_feedback_for_domain(db: Session, domain: str) -> list[AnalystFeedback]:
    """Get all analyst feedback for a specific domain (for LLM context)."""
    return db.query(AnalystFeedback).filter(
        AnalystFeedback.domain == domain.strip().lower()
    ).order_by(AnalystFeedback.created_at.desc()).all()


def get_all_blocked(db: Session, indicator_type: Optional[str] = None) -> list[Blocklist]:
    """Get all active blocklist entries, optionally filtered by type."""
    q = db.query(Blocklist).filter(Blocklist.active == True)
    if indicator_type:
        q = q.filter(Blocklist.indicator_type == indicator_type)
    return q.all()


def get_blocked_set(db: Session, indicator_type: str) -> set[str]:
    """Get a set of all active blocked values for a given type (for fast lookups)."""
    rows = db.query(Blocklist.value).filter(
        Blocklist.indicator_type == indicator_type,
        Blocklist.active == True,
    ).all()
    return {r[0] for r in rows}
