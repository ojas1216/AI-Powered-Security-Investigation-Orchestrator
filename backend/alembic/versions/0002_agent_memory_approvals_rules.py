"""Agent long-term memory, approval workflow, and tenant detection rules.

All three tables are tenant-scoped and protected by the same RLS policy pattern
as the initial schema (per-transaction `app.tenant_id` GUC, FORCE RLS).

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-13
"""
import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

_TENANT_TABLES = ["case_memory", "approvals", "detection_rules"]


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
    _create_common("case_memory", [
        sa.Column("investigation_id", sa.String(36), index=True),
        sa.Column("title", sa.String(512)),
        sa.Column("verdict", sa.String(16)),
        sa.Column("risk_score", sa.Float()),
        sa.Column("ioc_keys", sa.JSON()),
        sa.Column("technique_ids", sa.JSON()),
    ])
    _create_common("approvals", [
        sa.Column("investigation_id", sa.String(36), index=True),
        sa.Column("status", sa.String(16), index=True),
        sa.Column("request", sa.JSON()),
    ])
    _create_common("detection_rules", [
        sa.Column("rule_id", sa.String(64), index=True),
        sa.Column("rule", sa.JSON()),
    ])
    op.create_unique_constraint(
        "uq_detection_rules_tenant_rule", "detection_rules", ["tenant_id", "rule_id"]
    )

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
