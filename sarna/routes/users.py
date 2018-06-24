import os

from flask import Blueprint, render_template, request, flash
from sqlalchemy.exc import IntegrityError

from sarna.auxiliary import redirect_back
from sarna.core.auth import login_required, current_user, admin_required
from sarna.forms import OtpConfirmForm, ChangePasswordForm, AddUserForm
from sarna.model import User, db

ROUTE_NAME = os.path.basename(__file__).split('.')[0]
blueprint = Blueprint('users', __name__)


@blueprint.route('/profile')
@login_required
def index():
    context = dict(
        route=ROUTE_NAME,
        otp_form=OtpConfirmForm(),
        change_passwd_form=ChangePasswordForm(),
        add_user_form=AddUserForm(request.form),
        users=User.query.all()
    )
    return render_template('users/profile.html', **context)


@blueprint.route('/enable_otp', methods=('POST',))
@login_required
def enable_otp():
    form = OtpConfirmForm(request.form)
    user: User = current_user

    try:
        if user.enable_otp(form.otp.data):
            flash('OTP enabled successfully', 'success')
        else:
            raise ValueError('invalid otp')
    except ValueError:
        flash('Invalid OTP, please try to enroll again.', 'danger')

    return redirect_back('users.index')


@blueprint.route('/disable_otp', methods=('POST',))
@login_required
def disable_otp():
    form = OtpConfirmForm(request.form)
    user: User = current_user

    try:
        if user.disable_otp(form.otp.data):
            flash('OTP disabled successfully', 'success')
        else:
            raise ValueError('invalid otp')
    except ValueError:
        flash('Invalid OTP, please try again.', 'danger')

    return redirect_back('users.index')


@blueprint.route('/change_passwd', methods=('POST',))
@login_required
def change_passwd():
    form = ChangePasswordForm()
    user: User = current_user

    if (not user.otp_enabled or user.check_otp(form.otp.data)) and user.check_password(form.oldpassword.data):
        if form.newpassword.data == form.newpasswordrep.data:
            user.set_passwd(form.newpassword.data)
            flash('Password changed successfully', 'success')
        else:
            flash('Password repeat invalid', 'danger')
    else:
        flash('Invalid credentials', 'danger')

    return redirect_back('users.index')


@blueprint.route('/add_user', methods=('POST',))
@admin_required
def add_user():
    form = AddUserForm(request.form)

    if form.validate_on_submit():
        username = form.username.data
        if form.password.data == form.passwordrep.data:
            try:
                user = User(username=username)
                user.set_passwd(form.password.data)
            except IntegrityError:
                flash('User {} already exist'.format(username), 'danger')
                db.session.rollback()
        else:
            flash('Password repeat invalid', 'danger')

    return redirect_back('users.index')


@blueprint.route('/del_user/<username>', methods=('POST',))
@admin_required
def del_user(username):
    User.query.filter_by(username=username).one().delete()
    return redirect_back('users.index')
