from sarna.forms.base_entity_form import BaseEntityForm
from sarna.model.user import User


class EditUserForm(BaseEntityForm(
    User,
    skip_attrs={'username', 'source', 'creation_date', 'last_access', 'otp_seed'}
)):
    pass
