import os

from flask import Blueprint, render_template, request, flash

from sarna.auxiliary import redirect_back
from sarna.core.auth import login_required, current_user
from sarna.forms import OtpConfirmForm, ChangePasswordForm
from sarna.model import db_session, User

ROUTE_NAME = os.path.basename(__file__).split('.')[0]
blueprint = Blueprint('users', __name__)


@blueprint.route('/profile')
@db_session
@login_required
def index():
    context = dict(
        route=ROUTE_NAME,
        otp_form=OtpConfirmForm(),
        change_passwd_form=ChangePasswordForm()
    )
    return render_template('users/profile.html', **context)


@blueprint.route('/enable_otp', methods=('POST',))
@db_session
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
@db_session
@login_required
def disable_otp():
    form = OtpConfirmForm(request.form)
    user: User = current_user

    try:
        if user.confirm_otp(form.otp.data):
            user.otp_enabled = False
            flash('OTP disabled successfully', 'success')
        else:
            raise ValueError('invalid otp')
    except ValueError:
        flash('Invalid OTP, please try again.', 'danger')

    return redirect_back('users.index')


@blueprint.route('/changepass_otp', methods=('POST',))
@db_session
@login_required
def change_passwd():
    form = ChangePasswordForm()
    user: User = current_user

    if not user.otp_enabled or user.check_otp(form.otp.data):
        if user.check_password(form.oldpassword.data):
            if form.newpassword.data == form.newpasswordrep.data:
                pass
            else:
                flash('Password repea')
    return redirect_back('user.index')
