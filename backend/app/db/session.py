"""Database session with per-transaction tenant binding for Row-Level Security.

`SET LOCAL app.tenant_id` makes the active tenant available to RLS policies for
the lifetime of the transaction, so the database itself enforces isolation.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.tenancy import get_current_tenant

_engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)


@contextmanager
def tenant_session() -> Iterator[Session]:
    """Yield a session bound to the current tenant for RLS enforcement."""
    tenant = get_current_tenant()
    session = SessionLocal()
    try:
        # Parameterized; tenant already validated by validate_tenant_id().
        session.execute(
            text("SELECT set_config('app.tenant_id', :tid, true)"), {"tid": tenant}
        )
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
