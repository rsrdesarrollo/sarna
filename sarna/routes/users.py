import secrets

from flask import Blueprint, render_template, request, flash
from sqlalchemy.exc import IntegrityError

from sarna.auxiliary import redirect_back
from sarna.core.auth import current_user
from sarna.core.roles import admin_required
from sarna.forms.auth import AddUserForm
from sarna.forms.user_administration import EditUserForm
from sarna.model import db
from sarna.model.user import User

blueprint = Blueprint('users', __name__)


@blueprint.route('/users')
@admin_required
def index():
    users = User.query.all()
    context = dict(
        users=users
    )
    return render_template('users/list.html', **context)


@blueprint.route('/add', methods=('POST', 'GET'))
@admin_required
def new():
    form = AddUserForm(request.form)
    context = dict(
        form=form
    )
    if form.validate_on_submit():
        try:
            user = User(username=form.username.data, user_type=form.type.data)
            user.set_database_passwd(secrets.token_hex(16))
            db.session.add(user)
            db.session.commit()
        except IntegrityError:
            flash('User {} already exist'.format(form.username.data), 'danger')
            db.session.rollback()
        flash('User {} successfully created'.format(user.username), 'success')
        return redirect_back('users.index')

    return render_template('users/new.html', **context)


@blueprint.route('/<username>', methods=('POST', 'GET'))
@admin_required
def edit_user(username):
    user = User.query.filter_by(username=username).one()
    if not user:
        flash('User {} not found'.format(username), 'warning')
        return redirect_back('users.index')

    if request.method == 'POST':
        form = EditUserForm(request.form)
    else:
        form = EditUserForm(type=user.user_type)

    context = dict(
        form=form,
        username=username
    )

    if request.method == 'POST' and form.validate_on_submit():
        user.user_type = form.type.data
        db.session.commit()
        flash("User {} updated with role {}".format(username, form.type.data), 'success')
        return redirect_back('users.index')
    else:
        return render_template('users/edit.html', **context)
  

@blueprint.route('/<username>/delete', methods=('POST',))
@admin_required
def del_user(username):
    user = User.query.filter_by(username=username).one()
    if user == current_user:
        flash('You can not delete yourself', 'danger')
    else:
        db.session.delete(user)
        db.session.commit()
        flash("User {} deleted".format(username), 'success')

    return redirect_back('users.index')
