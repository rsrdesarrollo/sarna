from wtforms import validators, StringField

from sarna.forms.base_entity_form import BaseEntityForm
from sarna.model.finding_template import FindingTemplate, FindingTemplateTranslation, Solution


class FindingTemplateCreateNewForm(
    BaseEntityForm(FindingTemplate, hide_attrs={'cvss_v3_score', 'cvss_v3_vector'}),
    BaseEntityForm(FindingTemplateTranslation, skip_pk=False)
):
    masvs = StringField(
        label = "MASVS - OWASP Mobile Application Security Verification Standard Requirement #", 
        render_kw = {'placeholder': '0.0.0'},
        validators = [validators.Regexp('[0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2}')]
    )
    asvs = StringField(
        label = "ASVS - OWASP Application Security Verification Standard Requirement #", 
        render_kw = {'placeholder': '0.0.0'},
        validators = [validators.Regexp('[0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2}')])

class FindingTemplateEditForm(BaseEntityForm(FindingTemplate, hide_attrs={'cvss_v3_score', 'cvss_v3_vector'})):

    masvs = StringField(
        label = "MASVS - OWASP Mobile Application Security Verification Standard Requirement #", 
        render_kw = {'placeholder': '0.0.0'},
        validators = [validators.Regexp('[0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2}')]
    )
    asvs = StringField(
        label = "ASVS - OWASP Application Security Verification Standard Requirement #", 
        render_kw={'placeholder': '0.0.0'},
        validators = [validators.Regexp('[0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2}')])

class FindingTemplateAddTranslationForm(BaseEntityForm(
    FindingTemplateTranslation,
    skip_pk=False
)):
    pass


class FindingTemplateEditTranslationForm(BaseEntityForm(FindingTemplateTranslation, skip_attrs={'lang'})):
    pass


class FindingTemplateAddSolutionForm(BaseEntityForm(
    Solution,
    skip_pk=False,
    custom_validators=dict(
        name=[validators.Regexp('[\w_-]+')]
    )
)):
    pass


class FindingTemplateEditSolutionForm(BaseEntityForm(
    Solution,
    skip_attrs={'lang'},
    custom_validators=dict(
        name=[validators.Regexp('[\w_-]+')]
    )
)):
    pass
