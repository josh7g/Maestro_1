from alembic import context
from flask import current_app

config = context.config

target_metadata = current_app.extensions['migrate'].db.metadata

def run_migrations_online():
    """Run migrations in 'online' mode."""
    url = current_app.config.get('SQLALCHEMY_DATABASE_URI')
    context.configure(
        url=url, target_metadata=target_metadata, literal_binds=True
    )

    with context.begin_transaction():
        context.run_migrations()