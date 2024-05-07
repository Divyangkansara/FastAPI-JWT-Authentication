from alembic import op
import sqlalchemy as sa

# Define the upgrade function
def upgrade():
    op.add_column('users', sa.Column('hashed_password', sa.String, nullable=False))

# Define the downgrade function (if needed)
def downgrade():
    op.drop_column('users', 'hashed_password')
