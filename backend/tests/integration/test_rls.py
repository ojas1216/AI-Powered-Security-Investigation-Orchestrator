"""Integration test: Postgres Row-Level Security tenant isolation.

Skipped unless AEGIS_PG_OWNER_DSN (superuser/owner) and AEGIS_PG_APP_DSN
(non-superuser app role) point at a real, migrated Postgres. The CI security job
provisions these; locally you can reproduce with:

    docker run -d --name pg -e POSTGRES_USER=aegis -e POSTGRES_PASSWORD=aegis \
        -e POSTGRES_DB=aegis -p 5544:5432 postgres:16-alpine
    AEGIS_DATABASE_URL=postgresql+psycopg://aegis:aegis@localhost:5544/aegis \
        python -c "from alembic.config import main; main(['upgrade','head'])"
    psql ... -c "CREATE ROLE aegis_app LOGIN PASSWORD 'aegis_app' NOSUPERUSER;
                 GRANT USAGE ON SCHEMA public TO aegis_app;
                 GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO aegis_app;"
    AEGIS_PG_OWNER_DSN=postgresql://aegis:aegis@localhost:5544/aegis \
    AEGIS_PG_APP_DSN=postgresql://aegis_app:aegis_app@localhost:5544/aegis \
        pytest tests/integration/test_rls.py
"""
from __future__ import annotations

import os
import uuid

import pytest

APP_DSN = os.environ.get("AEGIS_PG_APP_DSN")

pytestmark = pytest.mark.skipif(
    not APP_DSN, reason="set AEGIS_PG_APP_DSN to run RLS integration test"
)


def test_rls_hides_other_tenant_rows():
    """Raw, unfiltered SELECT as the app role must only see the current tenant.

    Because there is NO WHERE clause, the only thing that can hide a row is the
    RLS policy keyed on app.tenant_id — this isolates RLS from any app-side filter.
    """
    import psycopg

    inv_id = str(uuid.uuid4())
    alert_id = str(uuid.uuid4())
    with psycopg.connect(APP_DSN, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("select rolsuper from pg_roles where rolname = current_user")
        assert cur.fetchone()[0] is False, "app role must NOT be a superuser (would bypass RLS)"

        # Insert one alert+investigation as tenant 'acme'.
        cur.execute("select set_config('app.tenant_id', 'acme', false)")
        cur.execute(
            "insert into alerts (id, tenant_id, source, source_alert_id, title, severity) "
            "values (%s,'acme','generic','X','t','low')",
            (alert_id,),
        )
        cur.execute(
            "insert into investigations (id, tenant_id, alert_id, status, overall_verdict) "
            "values (%s,'acme',%s,'complete','malicious')",
            (inv_id, alert_id),
        )

        # As 'globex', the unfiltered count must exclude the acme row.
        cur.execute("select set_config('app.tenant_id', 'globex', false)")
        cur.execute("select count(*) from investigations where id = %s", (inv_id,))
        assert cur.fetchone()[0] == 0, "RLS leaked an acme row to globex"

        # As 'acme', the row is visible.
        cur.execute("select set_config('app.tenant_id', 'acme', false)")
        cur.execute("select count(*) from investigations where id = %s", (inv_id,))
        assert cur.fetchone()[0] == 1
