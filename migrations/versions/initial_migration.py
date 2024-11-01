"""Initial migration

Revision ID: initial_migration
Revises: 
Create Date: 2024-11-01

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'initial_migration'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('analysis_results',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('repository_name', sa.String(length=255), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('results', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_analysis_results_repository_name'), 'analysis_results', ['repository_name'], unique=False)

def downgrade():
    op.drop_index(op.f('ix_analysis_results_repository_name'), table_name='analysis_results')
    op.drop_table('analysis_results')