"""Nullable fields

Revision ID: 68a62bb9bff4
Revises: 44c6c91dd3c4
Create Date: 2020-09-29 16:50:52.247676

"""
from alembic import op
import sqlalchemy as sa
import sarna


# revision identifiers, used by Alembic.
revision = '68a62bb9bff4'
down_revision = '44c6c91dd3c4'
branch_labels = None
depends_on = None


def upgrade():
# ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('assessment', 'platform',
               existing_type=sa.VARCHAR(length=64),
               nullable=True)
    op.alter_column('finding', 'business_risk',
               existing_type=sa.INTEGER(),
               nullable=True)
    op.alter_column('finding', 'dissemination',
               existing_type=sa.INTEGER(),
               nullable=True)
    op.alter_column('finding', 'exploitability',
               existing_type=sa.INTEGER(),
               nullable=True)
    op.alter_column('finding', 'solution_complexity',
               existing_type=sa.INTEGER(),
               nullable=True)
    op.alter_column('finding', 'tech_risk',
               existing_type=sa.INTEGER(),
               nullable=True)
    op.alter_column('finding_template', 'business_risk',
               existing_type=sa.INTEGER(),
               nullable=True)
    op.alter_column('finding_template', 'dissemination',
               existing_type=sa.INTEGER(),
               nullable=True)
    op.alter_column('finding_template', 'exploitability',
               existing_type=sa.INTEGER(),
               nullable=True)
    op.alter_column('finding_template', 'solution_complexity',
               existing_type=sa.INTEGER(),
               nullable=True)
    op.alter_column('finding_template', 'tech_risk',
               existing_type=sa.INTEGER(),
               nullable=True)
    # ### end Alembic commands ###


def downgrade():
# ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('finding_template', 'tech_risk',
               existing_type=sa.INTEGER(),
               nullable=False)
    op.alter_column('finding_template', 'solution_complexity',
               existing_type=sa.INTEGER(),
               nullable=False)
    op.alter_column('finding_template', 'exploitability',
               existing_type=sa.INTEGER(),
               nullable=False)
    op.alter_column('finding_template', 'dissemination',
               existing_type=sa.INTEGER(),
               nullable=False)
    op.alter_column('finding_template', 'business_risk',
               existing_type=sa.INTEGER(),
               nullable=False)
    op.alter_column('finding', 'tech_risk',
               existing_type=sa.INTEGER(),
               nullable=False)
    op.alter_column('finding', 'solution_complexity',
               existing_type=sa.INTEGER(),
               nullable=False)
    op.alter_column('finding', 'exploitability',
               existing_type=sa.INTEGER(),
               nullable=False)
    op.alter_column('finding', 'dissemination',
               existing_type=sa.INTEGER(),
               nullable=False)
    op.alter_column('finding', 'business_risk',
               existing_type=sa.INTEGER(),
               nullable=False)
    op.alter_column('assessment', 'platform',
               existing_type=sa.VARCHAR(length=64),
               nullable=False)
    # ### end Alembic commands ###
