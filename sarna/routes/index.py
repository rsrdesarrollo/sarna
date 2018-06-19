import os

from flask import Blueprint, render_template, request, flash

from sarna.auxiliary import redirect_back
from sarna.core.auth import login_required, logout_user
from sarna.forms import LoginForm
from sarna.model import User

ROUTE_NAME = os.path.basename(__file__).split('.')[0]
blueprint = Blueprint('index', __name__)


@blueprint.route('/', methods=('GET', 'POST'))
def index():
    form = LoginForm(request.form)
    context = dict(
        route=ROUTE_NAME,
        form=form,
        need_otp=False
    )

    if form.validate_on_submit():
        user: User = None
        try:
            user = User[form.username.data]
        except ObjectNotFound:
            pass

        if user and user.check_password(form.password.data):
            if not user.otp_enabled or user.otp_enabled and user.confirm_otp(form.otp.data):
                user.login()

                flash('Logged in successfully.', 'success')
                return redirect_back('index.index')

        if form.otp.data:
            flash('Invalid credentials', 'danger')
        else:
            form.otp.errors.append('Google Authenticator OTP required.')

        context['need_otp'] = True

    return render_template('index.html', **context)


@blueprint.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect_back('index.index')
