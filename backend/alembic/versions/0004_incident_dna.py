"""Incident DNA fingerprint store (tenant-scoped, RLS).

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-16
"""
import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "incident_dna",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("investigation_id", sa.String(36), index=True),
        sa.Column("title", sa.String(512), server_default=""),
        sa.Column("dna", sa.JSON()),
    )
    op.execute("ALTER TABLE incident_dna ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE incident_dna FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON incident_dna "
        "USING (tenant_id = current_setting('app.tenant_id', true)) "
        "WITH CHECK (tenant_id = current_setting('app.tenant_id', true))")


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON incident_dna")
    op.drop_table("incident_dna")
