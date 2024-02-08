"""empty message

Revision ID: f77b23eeee22
Revises: 3277e0ef1496
Create Date: 2024-02-08 09:07:11.683010

"""
from alembic import op
import sqlalchemy as sa
import sarna


# revision identifiers, used by Alembic.
revision = 'f77b23eeee22'
down_revision = '3277e0ef1496'
branch_labels = None
depends_on = None


def upgrade():
# Create impact columns for finding + translation
    op.add_column('finding', sa.Column('impact', sa.String(), nullable=True))
    op.add_column('finding_template_translation', sa.Column('impact', sa.String(), nullable=True))


def downgrade():
# ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('finding_template_translation', 'impact')
    op.drop_column('finding', 'impact')
    # ### end Alembic commands ###