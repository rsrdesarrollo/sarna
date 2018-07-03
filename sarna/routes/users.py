from flask import Blueprint, render_template, request, flash
from sqlalchemy.exc import IntegrityError

from sarna.auxiliary import redirect_back
from sarna.core.auth import login_required, current_user, admin_required
from sarna.forms.auth import OtpConfirmForm, ChangePasswordForm, AddUserForm
from sarna.model import db
from sarna.model.user import User

blueprint = Blueprint('users', __name__)


@blueprint.route('/profile')
@login_required
def index():
    if current_user.is_admin:
        users = User.query.all()
    else:
        users = []

    context = dict(
        otp_form=OtpConfirmForm(),
        change_passwd_form=ChangePasswordForm(),
        add_user_form=AddUserForm(request.form),
        users=users
    )
    return render_template('users/profile.html', **context)


@blueprint.route('/enable_otp', methods=('POST',))
@login_required
def enable_otp():
    form = OtpConfirmForm(request.form)

    try:
        if current_user.enable_otp(form.otp.data):
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

    try:
        if current_user.disable_otp(form.otp.data):
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

    if (not current_user.otp_enabled or current_user.check_otp(form.otp.data)) and current_user.check_password(
            form.oldpassword.data):
        if form.newpassword.data == form.newpasswordrep.data:
            current_user.set_passwd(form.newpassword.data)
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
    user = User.query.filter_by(username=username).one()
    if user == current_user:
        flash('You can not delete yourself', 'danger')
    else:
        user.delete()

    return redirect_back('users.index')
