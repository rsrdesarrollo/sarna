import getpass

import click
from flask.cli import AppGroup
from sqlalchemy.exc import IntegrityError
from terminaltables import AsciiTable

from sarna.model import db
from sarna.model.enums import UserType, AuthSource
from sarna.model.user import User

user_cli = AppGroup('user', help='User management')


def init_app(app):
    app.cli.add_command(user_cli)


@user_cli.command('list', help='list all users')
def list_users():
    table = AsciiTable(
        [('username', 'role', 'source', 'creation', 'lastLogin', 'hasOtp')] + [
            (
                user.username,
                user.user_type.name,
                user.source,
                user.creation_date,
                user.last_access,
                user.otp_enabled
            )
            for user in User.query.all()
        ],
        title='List of users'
    )
    click.echo(table.table)


@user_cli.command('add', help='add a new user')
@click.option('-r', '--role', type=click.Choice(a.name for a in UserType), default=UserType.auditor.name)
@click.argument('username')
def add_user(username, role):
    pswd = getpass.getpass('Password: ')
    pswd2 = getpass.getpass('Repeat password: ')

    if pswd == pswd2:
        user = User(username=username, user_type=UserType[role])
        user.set_database_passwd(pswd)
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            click.echo('User {} already exist'.format(username), err=True)
            db.session.rollback()
    else:
        click.echo('Password confirmation mismatch.', err=True)


@user_cli.command('del', help='delete a existing user')
@click.argument('username')
def del_user(username):
    user = User.query.filter_by(username=username)
    user.delete()
    db.session.commit()


@user_cli.command('mod', help='modify a existing user')
@click.option('-r', '--role', type=click.Choice(a.name for a in UserType))
@click.option('-p', '--change-passwd', default=False, is_flag=True)
@click.argument('username')
def mod_user(username, role, change_passwd):
    user = User.query.filter_by(username=username).first()
    if not user:
        click.echo("ERROR: User {} not found.".format(username), err=True)

    if role:
        user.user_type = UserType[role]

    if change_passwd and user.source == AuthSource.database:
        pswd = getpass.getpass('Password: ')
        pswd2 = getpass.getpass('Repeat password: ')

        if pswd == pswd2:
            user.set_database_passwd(pswd)
        else:
            click.echo('Password confirmation mismatch.', err=True)
            db.session.rollback()

    db.session.commit()
