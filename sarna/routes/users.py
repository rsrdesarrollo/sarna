import os

from flask import Blueprint, render_template, request, flash

from sarna.auxiliary import redirect_back
from sarna.core import login_required, current_user
from sarna.forms import OtpConfirmForm
from sarna.model import db_session, User

ROUTE_NAME = os.path.basename(__file__).split('.')[0]
blueprint = Blueprint('users', __name__)


@blueprint.route('/profile')
@db_session
@login_required
def index():
    form = OtpConfirmForm()
    context = dict(
        route=ROUTE_NAME,
        form=form
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
