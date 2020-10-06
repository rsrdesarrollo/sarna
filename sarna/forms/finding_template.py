from wtforms import validators, StringField, HiddenField, SelectField

from sarna.forms.base_entity_form import BaseEntityForm
from sarna.model.finding_template import FindingTemplate, FindingTemplateTranslation, Solution
from sarna.model.enums import Score, AssessmentStatus, AssessmentType, Language, WSTG, MSTG, CWE



class FindingTemplateCreateNewForm(
    BaseEntityForm(
        FindingTemplate,
        hide_attrs={ 'cvss_v3_score', 'cvss_v3_vector' },
        skip_attrs={ 'owisam_category' }),
    BaseEntityForm(FindingTemplateTranslation, skip_pk=False)
):
    owasp_category = SelectField("Web Security Testing Guide", choices=WSTG.choices(), coerce=WSTG.coerce)
    owasp_mobile_category = SelectField("Mobile Security Testing Guide", choices=MSTG.choices(), coerce=MSTG.coerce)
    cwe = SelectField("Common Weakness Enumeration", choices=CWE.choices(), coerce=CWE.coerce)
    masvs = StringField(
        label = "MASVS - OWASP Mobile Application Security Verification Standard Requirement #", 
        render_kw = {'placeholder': '0.0.0'},
        validators = [validators.Regexp('[0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2}')],
        default = "0.0.0"
    )
    asvs = StringField(
        label = "ASVS - OWASP Application Security Verification Standard Requirement #", 
        render_kw = {'placeholder': '0.0.0'},
        validators = [validators.Regexp('[0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2}')],
        default = "0.0.0"
    )
    status = SelectField("Status", choices=AssessmentStatus.choices(), default=AssessmentStatus.Open, coerce=AssessmentStatus.coerce)
    type = SelectField("Type", choices=AssessmentType.choices(), default=AssessmentType.Web, coerce=AssessmentType.coerce)
    lang = SelectField("Language", choices=Language.choices(), default=Language.Spanish, coerce=Language.coerce)
    tech_risk = HiddenField(default=Score.NA)
    business_risk = HiddenField(default=Score.NA)
    exploitability = HiddenField(default=Score.NA)
    dissemination = HiddenField(default=Score.NA)
    solution_complexity = HiddenField(default=Score.NA)


class FindingTemplateEditForm(
    BaseEntityForm(
        FindingTemplate,
        hide_attrs={ 'cvss_v3_score', 'cvss_v3_vector' },
        skip_attrs={ 'owisam_category' }
    )
):
    masvs = StringField(
        label = "MASVS - OWASP Mobile Application Security Verification Standard Requirement #", 
        render_kw = {'placeholder': '0.0.0'},
        validators = [validators.Regexp('[0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2}')],
        default = "0.0.0"
    )
    asvs = StringField(
        label = "ASVS - OWASP Application Security Verification Standard Requirement #", 
        render_kw={'placeholder': '0.0.0'},
        validators = [validators.Regexp('[0-9]{1,2}.[0-9]{1,2}.[0-9]{1,2}')],
        default = "0.0.0"
    )
    status = SelectField("Status", choices=AssessmentStatus.choices(), default=AssessmentStatus.Open, coerce=AssessmentStatus.coerce)
    type = SelectField("Type", choices=AssessmentType.choices(), default=AssessmentType.Web, coerce=AssessmentType.coerce)
    lang = SelectField("Language", choices=Language.choices(), default=Language.Spanish, coerce=Language.coerce)
    tech_risk = HiddenField(default=Score.NA)
    business_risk = HiddenField(default=Score.NA)
    exploitability = HiddenField(default=Score.NA)
    dissemination = HiddenField(default=Score.NA)
    solution_complexity = HiddenField(default=Score.NA)

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
