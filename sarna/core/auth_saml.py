from sarna.core import app
from flask import url_for, flash
from flask_saml2.sp import ServiceProvider
from flask_saml2.utils import certificate_from_file, private_key_from_file
from sarna.config import BaseConfig
from sarna.core.auth_engine.auth_controller import AuthController
from sarna.core.auth_engine.exceptions import UserNotFoundException

def getLoginUrl():
    return url_for('flask_saml2_sp.login')

def getLogoutUrl():
    return url_for('flask_saml2_sp.logout')

def isEnabledSAML():
    return BaseConfig.SAML_AUTH

def getServiceProvider():
    if isEnabledSAML:
        return sp
    else:
        return None

class MyServiceProvider(ServiceProvider):

    def __init__(self, app):
        ServiceProvider.__init__(self)
        self.blueprint = self.create_blueprint()

    def get_logout_return_url(self):
        return url_for('index.index', _external=True)

    def get_default_login_return_url(self):
        return url_for('index.index', _external=True)

    def login_successful(self, auth_data, relay_state):
        controller = AuthController()
        try:
            controller.authenticate(auth_data.nameid, None, None)
        except UserNotFoundException:
            ServiceProvider.logout(self)
            flash('Invalid credentials', 'danger')
        return ServiceProvider.login_successful(self, auth_data, relay_state)

if BaseConfig.SAML_AUTH:

    def checkParam(param):
        if not param:
           raise AttributeError("There are errors in the SAML config attibutes.")

    params = [ BaseConfig.SAML_IDP_EID,
        BaseConfig.SAML_IDP_CERT,
        BaseConfig.SAML_IDP_SSO,
        BaseConfig.SAML_IDP_SLO,
        BaseConfig.SAML_SP_CERT,
        BaseConfig.SAML_SP_PK,
        BaseConfig.SERVER_NAME]
    
    for param in params:
        checkParam(param)

    sp = MyServiceProvider(app)

    app.config['SERVER_NAME'] = BaseConfig.SERVER_NAME
    app.config['SAML2_SP'] = {
        'certificate': certificate_from_file(BaseConfig.SAML_SP_CERT),
        'private_key': private_key_from_file(BaseConfig.SAML_SP_PK),
    }

    app.config['SAML2_IDENTITY_PROVIDERS'] = [
        {
            'CLASS': 'flask_saml2.sp.idphandler.IdPHandler',
            'OPTIONS': {
                'display_name': 'My Identity Provider',
                'entity_id': BaseConfig.SAML_IDP_EID,
                'sso_url': BaseConfig.SAML_IDP_SSO,
                'slo_url': BaseConfig.SAML_IDP_SLO,
                'certificate': certificate_from_file(BaseConfig.SAML_IDP_CERT),
            },
        },
    ]
