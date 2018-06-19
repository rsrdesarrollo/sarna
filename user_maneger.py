import argparse
import getpass
import sys

from sqlalchemy.exc import IntegrityError
from terminaltables import AsciiTable

from sarna.core import app
from sarna.model import db, User

parser = argparse.ArgumentParser()
parser.add_argument('command', help="command", choices=('add', 'list', 'del', 'mod', 'help'))
parser.add_argument('args', nargs=argparse.REMAINDER)

ops = parser.parse_args()


def error(msg, code=1):
    print(msg, file=sys.stderr)
    sys.exit(code)


with app.app_context():
    if ops.command == 'list':
        # noinspection PyTypeChecker
        table = AsciiTable(
            [('username', 'isAdmin', 'creation', 'lastLogin', 'hasOtp')] + [
                (
                    user.username,
                    user.is_admin,
                    user.creation_date,
                    user.last_access,
                    user.otp_enabled
                )
                for user in User.query.all()
            ],
            title='List of users'
        )

        print(table.table)

    elif ops.command == 'del':
        parser = argparse.ArgumentParser(prog='user_manager.py del')
        parser.add_argument('username', help='username')
        ops = parser.parse_args(ops.args)

        User.query.filter_by(username=ops.username).delete()
        db.session.commit()

    elif ops.command == 'add':
        parser = argparse.ArgumentParser(prog='user_manager.py add')
        parser.add_argument('-s', '--is-admin', action='store_true', help='is administrator')
        parser.add_argument('username')
        ops = parser.parse_args(ops.args)

        pswd = getpass.getpass('Password: ')
        pswd2 = getpass.getpass('Repeat password: ')

        if pswd == pswd2:
            user = User(username=ops.username, is_admin=ops.is_admin)
            user.set_passwd(pswd)
            db.session.add(user)
            try:
                db.session.commit()
            except IntegrityError:
                error('User {} already exist'.format(ops.username))
        else:
            error('Password confirmation mismatch.')

    elif ops.command == 'mod':
        parser = argparse.ArgumentParser(prog='user_manager.py mod')
        parser.add_argument('-s', '--is-admin', action='store_true', help='is administrator')
        parser.add_argument('-p', '--change-passwd', action='store_true', help='Change password')
        parser.add_argument('username')
        ops = parser.parse_args(ops.args)

        user = User.query.filter_by(username=ops.username).first()
        if not user:
            error("ERROR: User {} not found.".format(ops.username))

        if ops.change_passwd:
            pswd = getpass.getpass('Password: ')
            pswd2 = getpass.getpass('Repeat password: ')

            if pswd == pswd2:
                user.set_passwd(pswd)
            else:
                error('Password confirmation mismatch.')

        user.is_admin = ops.is_admin

        db.session.commit()
    else:
        parser.error('form more help with a command use <command> help.')
