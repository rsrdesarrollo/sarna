from flask import Blueprint, render_template, request, flash

from sarna.core.auth_engine.auth_controller import AuthController
from sarna.core.auth_engine.exceptions import AuthException
from sarna.auxiliary import redirect_back
from sarna.core.auth import login_required, logout_user
from sarna.core.security import limiter
from sarna.forms.auth import LoginForm

blueprint = Blueprint('index', __name__)


@blueprint.route('/', methods=('GET', 'POST'))
@limiter.limit('10 per minute')
def index():
    form = LoginForm(request.form)
    context = dict(
        form=form,
        need_otp=False
    )

    if form.validate_on_submit():
        controller = AuthController()

        try:
            controller.authenticate(
                form.username.data,
                form.password.data,
                form.otp.data
            )
            flash('Logged in successfully.', 'success')
            return redirect_back('index.index')

        except AuthException:
            context['need_otp'] = True

        if form.otp.data:
            flash('Invalid credentials', 'danger')
        else:
            form.otp.errors.append('Google Authenticator OTP required.')

    return render_template('index.html', **context)


@blueprint.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect_back('index.index')
