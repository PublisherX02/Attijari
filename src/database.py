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
from datetime import datetime, timedelta, timezone
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

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is not set. "
        "The application refuses to start without a database connection string. "
        "Set it in your .env file (e.g. DATABASE_URL=postgresql://user:pass@host:5432/dbname)."
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
    # NULL means the entry never expires. Set via ttl_days in add_blocklist_entry().
    # A background cleanup job could periodically DELETE expired rows, but the
    # 60-second cache refresh in rules._refresh_blocklist_cache() already filters
    # them out, so no job is required for correctness.
    expires_at = Column(DateTime(timezone=True), nullable=True)
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


class Alert(Base):
    """Security alert — raised by pipeline events, visible in the dashboard."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    level = Column(String(20), nullable=False)       # info, warning, critical
    title = Column(String(255), nullable=False)
    details = Column(JSONB, nullable=True)
    source = Column(String(100), nullable=False, default="system")
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)
    acknowledged = Column(Boolean, default=False)


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
    """System users for the Dashboard (ISO 27001 Access Control).

    Roles:
      - admin:   full access, can manage users and assign permissions
      - analyst: configurable permissions (view, release, quarantine, etc.)
      - viewer:  read-only access to emails and reports
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    totp_secret = Column(String(64), nullable=True)
    is_active = Column(Boolean, default=True)
    role = Column(String(20), nullable=False, default="viewer")  # admin, analyst, viewer
    permissions = Column(JSONB, nullable=False, default=dict)  # granular permission flags
    created_by = Column(String(255), nullable=True)
    last_login = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class PendingDetonation(Base):
    """Queue of attachments awaiting behavioral analysis in the CAPE sandbox.

    The pipeline enqueues a row when static analysis was inconclusive AND the
    LLM was unsure, then moves on without blocking. A separate drained
    detonation worker processes the queue one sample at a time.
    """

    __tablename__ = "pending_detonation"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=True)
    idempotency_key = Column(String(128), nullable=True, index=True)
    sha256 = Column(String(64), nullable=False)
    filename = Column(String(512), nullable=True)
    stored_path = Column(Text, nullable=False)
    reason = Column(String(255), nullable=True)   # why it was queued
    status = Column(String(20), nullable=False, default="queued")  # queued, running, done, error
    result = Column(JSONB, nullable=True)         # parsed CAPE result
    attempts = Column(Integer, default=0)
    created_by = Column(String(255), nullable=True)   # operator username (manual uploads)
    priority = Column(Boolean, nullable=False, default=False)  # manual rows jump the queue
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("ix_pending_detonation_status", "status"),
    )


# ---------------------------------------------------------------------------
# RBAC — Permission definitions
# ---------------------------------------------------------------------------

# Every granular permission the system supports.
# Admin role implicitly has ALL permissions.
# Analyst/viewer roles get a subset assigned by the admin.
ALL_PERMISSIONS = {
    "emails.view": True,         # view email list and details
    "emails.release": True,      # release emails
    "emails.quarantine": True,   # quarantine emails
    "emails.override": True,     # override pipeline verdicts
    "emails.revert": True,       # revert analyst actions
    "emails.bulk": True,         # bulk release/quarantine
    "emails.scan": True,         # trigger manual IMAP scan
    "blocklist.view": True,      # view blocklist
    "blocklist.manage": True,    # add/remove blocklist entries
    "whitelist.view": True,      # view whitelist
    "whitelist.manage": True,    # add/remove whitelist entries
    "audit.view": True,          # view audit log and action history
    "reports.view": True,        # view reports
    "health.view": True,         # view system health
    "alerts.view": True,         # view security alerts
    "alerts.acknowledge": True,  # acknowledge alerts
    "export.csv": True,          # export email data as CSV
    "users.manage": True,        # create/edit/delete users (admin only)
    "detonation.manual": True,   # upload + detonate an arbitrary file in the sandbox
}

VIEWER_PERMISSIONS = {
    "emails.view": True,
    "blocklist.view": True,
    "whitelist.view": True,
    "reports.view": True,
    "health.view": True,
    "alerts.view": True,
    "audit.view": True,
}

ANALYST_PERMISSIONS = {
    **VIEWER_PERMISSIONS,
    "emails.release": True,
    "emails.quarantine": True,
    "emails.override": True,
    "emails.revert": True,
    "emails.bulk": True,
    "emails.scan": True,
    "blocklist.manage": True,
    "whitelist.manage": True,
    "alerts.acknowledge": True,
    "export.csv": True,
}

ROLE_DEFAULTS = {
    "admin": ALL_PERMISSIONS,
    "analyst": ANALYST_PERMISSIONS,
    "viewer": VIEWER_PERMISSIONS,
}


def user_has_permission(user: "User", permission: str) -> bool:
    """Check if a user has a specific permission."""
    if user.role == "admin":
        return True  # admin bypasses all checks
    return bool(user.permissions.get(permission, False))


def _migrate_users_rbac():
    """One-time migration: add role+permissions columns to pre-RBAC users table."""
    from sqlalchemy import inspect, text as sa_text
    try:
        inspector = inspect(engine)
        existing_cols = {c["name"] for c in inspector.get_columns("users")}

        # Add missing columns via ALTER TABLE
        new_cols = {
            "role": "VARCHAR(20) NOT NULL DEFAULT 'viewer'",
            "permissions": "JSONB NOT NULL DEFAULT '{}'::jsonb",
            "created_by": "VARCHAR(255)",
            "last_login": "TIMESTAMP WITH TIME ZONE",
        }
        first_migration = "role" not in existing_cols
        with engine.begin() as conn:
            for col_name, col_def in new_cols.items():
                if col_name not in existing_cols:
                    conn.execute(sa_text(f'ALTER TABLE users ADD COLUMN "{col_name}" {col_def}'))
                    print(f"[DB] Added column users.{col_name}")

        # Only promote pre-RBAC users on first migration (when role column was just added).
        # On subsequent startups, never touch existing roles — they were set intentionally.
        if first_migration:
            db = SessionLocal()
            try:
                users = db.query(User).all()
                for u in users:
                    u.role = "admin"  # pre-RBAC users were de facto admins
                    u.permissions = ALL_PERMISSIONS.copy()
                db.commit()
                print("[DB] Migrated existing users to RBAC schema (first run).")
            finally:
                db.close()
    except Exception as e:
        print(f"[DB] RBAC migration note: {e}")


def _migrate_pending_detonation_manual():
    """One-time: add manual-detonation columns to an existing pending_detonation table."""
    from sqlalchemy import inspect, text as sa_text
    try:
        inspector = inspect(engine)
        if "pending_detonation" not in inspector.get_table_names():
            return  # create_all will make it with the columns already
        existing = {c["name"] for c in inspector.get_columns("pending_detonation")}
        new_cols = {
            "created_by": "VARCHAR(255)",
            "priority": "BOOLEAN NOT NULL DEFAULT FALSE",
        }
        with engine.begin() as conn:
            for name, ddl in new_cols.items():
                if name not in existing:
                    conn.execute(sa_text(f'ALTER TABLE pending_detonation ADD COLUMN "{name}" {ddl}'))
                    print(f"[DB] Added column pending_detonation.{name}")
    except Exception as e:
        print(f"[DB] pending_detonation manual migration skipped: {e}")


# ---------------------------------------------------------------------------
# Database initialization
# ---------------------------------------------------------------------------

def init_db():
    """Create all tables if they don't exist. Safe to call multiple times."""
    Base.metadata.create_all(bind=engine)
    print("[DB] All tables created / verified.")

    # Migrate existing users: add role/permissions columns if missing
    _migrate_users_rbac()
    _migrate_pending_detonation_manual()

    # Initialize default admin if no users exist
    try:
        db = SessionLocal()
        import bcrypt
        import pyotp
        import secrets
        if db.query(User).count() == 0:
            env_pass = os.getenv("DASHBOARD_PASS")
            if env_pass:
                password = env_pass
            else:
                password = secrets.token_urlsafe(16)
            hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            totp_secret = pyotp.random_base32()
            admin = User(
                username=os.getenv("DASHBOARD_USER", "admin"),
                password_hash=hashed,
                totp_secret=totp_secret,
                role="admin",
                permissions=ALL_PERMISSIONS.copy(),
            )
            db.add(admin)
            db.commit()
            # Write credentials to a secure local file — NEVER print to console/logs
            totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(
                name=admin.username, issuer_name="ImaniIA SOC"
            )
            creds_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "admin_credentials.txt")
            os.makedirs(os.path.dirname(creds_file), exist_ok=True)
            with open(creds_file, "w") as f:
                f.write(f"Username: {admin.username}\n")
                if not env_pass:
                    f.write(f"Password: {password}\n")
                else:
                    f.write(f"Password: (set via DASHBOARD_PASS env var)\n")
                f.write(f"TOTP URI (import into Google Authenticator):\n{totp_uri}\n")
            # Restrict file permissions (best-effort on Windows)
            try:
                os.chmod(creds_file, 0o600)
            except OSError:
                pass
            print(f"\n=======================================================")
            print(f"[ISO 27001] ADMIN CREATED. MFA REQUIRED!")
            print(f"Username: {admin.username}")
            print(f"Credentials written to: {creds_file}")
            print(f"READ AND DELETE THIS FILE IMMEDIATELY AFTER SETUP.")
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
                        source: str = "auto", confirmed_by: Optional[str] = None,
                        ttl_days: Optional[int] = None) -> bool:
    """Add an indicator to the blocklist. Returns True if newly added.

    Args:
        ttl_days: If provided, the entry expires after this many days.
                  NULL (default) means the entry never expires.
                  Auto-cascade entries should use ttl_days=90.
    """
    val = value.strip().lower()
    if not val:
        return False

    # Whitelist always wins
    if is_whitelisted(db, indicator_type, val):
        print(f"[BLOCKLIST] Skipped {indicator_type}:{val} — whitelisted")
        return False

    expires_at = utcnow() + timedelta(days=ttl_days) if ttl_days is not None else None

    existing = db.query(Blocklist).filter(
        Blocklist.indicator_type == indicator_type,
        Blocklist.value == val,
    ).first()

    if existing:
        if not existing.active:
            existing.active = True
            existing.expires_at = expires_at
            db.commit()
            return True
        return False

    entry = Blocklist(
        indicator_type=indicator_type,
        value=val,
        source=source,
        confirmed_by=confirmed_by,
        expires_at=expires_at,
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


# ---------------------------------------------------------------------------
# Detonation queue helpers
# ---------------------------------------------------------------------------

def enqueue_detonation(db: Session, sha256: str, stored_path: str,
                       filename: Optional[str] = None, email_id: Optional[int] = None,
                       idempotency_key: Optional[str] = None,
                       reason: Optional[str] = None,
                       created_by: Optional[str] = None,
                       priority: bool = False,
                       status: str = "queued") -> Optional["PendingDetonation"]:
    """Queue an attachment for detonation. De-dupes on (sha256) while queued/running."""
    existing = db.query(PendingDetonation).filter(
        PendingDetonation.sha256 == sha256,
        PendingDetonation.status.in_(["queued", "running"]),
    ).first()
    if existing:
        return existing
    row = PendingDetonation(
        email_id=email_id,
        idempotency_key=idempotency_key,
        sha256=sha256,
        filename=filename,
        stored_path=stored_path,
        reason=reason,
        status=status,
        created_by=created_by,
        priority=priority,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def get_queued_detonations(db: Session, limit: int = 5) -> list["PendingDetonation"]:
    """Oldest queued samples first."""
    return (
        db.query(PendingDetonation)
        .filter(PendingDetonation.status == "queued")
        .order_by(PendingDetonation.priority.desc(), PendingDetonation.created_at.asc())
        .limit(limit)
        .all()
    )


def count_queued_detonations(db: Session) -> int:
    return db.query(PendingDetonation).filter(PendingDetonation.status == "queued").count()


def list_manual_detonations(db: Session, limit: int = 100) -> list["PendingDetonation"]:
    """Manual (non-email) detonations, newest first, for the manual-detonation page."""
    return (
        db.query(PendingDetonation)
        .filter(PendingDetonation.email_id.is_(None))
        .order_by(PendingDetonation.created_at.desc())
        .limit(limit)
        .all()
    )


def promote_deferred_detonations(db: Session) -> int:
    """Flip Branch-B 'deferred' rows to 'ready' once the email backlog is clear.
    Called at the end of a pipeline tick. Returns the number promoted."""
    rows = db.query(PendingDetonation).filter(PendingDetonation.status == "deferred").all()
    for r in rows:
        r.status = "ready"
    if rows:
        db.commit()
    return len(rows)


def get_pending_detonation(db: Session, pending_id: int) -> Optional["PendingDetonation"]:
    return db.query(PendingDetonation).filter(PendingDetonation.id == pending_id).first()
