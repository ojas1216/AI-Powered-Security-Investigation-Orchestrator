"""Native/Google user accounts.

The users table is deliberately NOT under an RLS policy: sign-in must look up
an account before the caller has any tenant context. Every other access path
filters by tenant_id explicitly.

Revision ID: 0003
Revises: 0002
Create Date: 2026-07-13
"""
import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(64), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("email", sa.String(320), nullable=False, unique=True, index=True),
        sa.Column("display_name", sa.String(256), server_default=""),
        sa.Column("roles", sa.JSON()),
        sa.Column("provider", sa.String(16), server_default="password"),
        sa.Column("password_hash", sa.String(256), server_default=""),
    )


def downgrade() -> None:
    op.drop_table("users")
