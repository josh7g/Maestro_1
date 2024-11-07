"""Add user_id column

Revision ID: add_user_id_column
Revises: initial_migration
Create Date: 2024-11-07

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_user_id_column'
down_revision = 'initial_migration'  # Points to your previous migration
branch_labels = None
depends_on = None

def upgrade():
    # Add user_id column
    op.add_column('analysis_results',
        sa.Column('user_id', sa.String(length=255), nullable=True)
    )
    # Create index for user_id
    op.create_index(op.f('ix_analysis_results_user_id'), 'analysis_results', ['user_id'], unique=False)

def downgrade():
    # Remove index and column
    op.drop_index(op.f('ix_analysis_results_user_id'), table_name='analysis_results')
    op.drop_column('analysis_results', 'user_id')