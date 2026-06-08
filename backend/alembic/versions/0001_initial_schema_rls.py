"""Initial schema with Postgres Row-Level Security for multi-tenant isolation.

Every tenant-scoped table gets an RLS policy keyed on the per-transaction GUC
`app.tenant_id` (set by app.db.session.tenant_session). FORCE ROW LEVEL SECURITY
ensures even the table owner is subject to the policy.

Revision ID: 0001
Revises:
Create Date: 2026-06-08
"""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

_TENANT_TABLES = ["alerts", "investigations", "iocs", "audit_log"]


def _create_common(table: str, extra: list[sa.Column]) -> None:
    op.create_table(
        table,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        *extra,
    )


def upgrade() -> None:
    _create_common("alerts", [
        sa.Column("source", sa.String(32)),
        sa.Column("source_alert_id", sa.String(256), index=True),
        sa.Column("title", sa.String(512)),
        sa.Column("severity", sa.String(16)),
        sa.Column("payload", sa.JSON()),
    ])
    _create_common("investigations", [
        sa.Column("alert_id", sa.String(36), sa.ForeignKey("alerts.id")),
        sa.Column("status", sa.String(16), index=True),
        sa.Column("overall_verdict", sa.String(16)),
        sa.Column("risk_score", sa.Float()),
        sa.Column("package", sa.JSON()),
    ])
    _create_common("iocs", [
        sa.Column("investigation_id", sa.String(36),
                  sa.ForeignKey("investigations.id"), index=True),
        sa.Column("type", sa.String(24), index=True),
        sa.Column("value", sa.String(2048), index=True),
        sa.Column("verdict", sa.String(16)),
        sa.Column("confidence", sa.Float()),
    ])
    _create_common("audit_log", [
        sa.Column("actor", sa.String(256)),
        sa.Column("action", sa.String(128), index=True),
        sa.Column("target", sa.String(256)),
        sa.Column("result", sa.String(32)),
        sa.Column("detail", sa.Text()),
    ])

    # Enable + force RLS and create the tenant isolation policy on each table.
    for table in _TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING (tenant_id = current_setting('app.tenant_id', true)) "
            f"WITH CHECK (tenant_id = current_setting('app.tenant_id', true))"
        )


def downgrade() -> None:
    for table in reversed(_TENANT_TABLES):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.drop_table(table)
