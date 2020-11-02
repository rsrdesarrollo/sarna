from wtforms import validators, StringField, HiddenField, SelectField, SelectMultipleField

from sarna.forms.base_entity_form import BaseEntityForm
from sarna.model.finding_template import FindingTemplate, FindingTemplateTranslation, Solution, \
    FindingTemplateWebRequirement, FindingTemplateMobileRequirement, FindingTemplateWebTest, \
    FindingTemplateMobileTest, FindingTemplateCWE
from sarna.model.enums import Score, FindingStatus, FindingType, Language, WSTG, MSTG, CWE, ASVS, MASVS


class FindingTemplateCreateNewForm(
    BaseEntityForm(
        FindingTemplate,
        hide_attrs={'cvss_v3_score', 'cvss_v3_vector'},
        skip_attrs={'owisam_category'}),
    BaseEntityForm(FindingTemplateTranslation, skip_pk=False),
    BaseEntityForm(FindingTemplateWebRequirement, skip_pk=False),
    BaseEntityForm(FindingTemplateMobileRequirement, skip_pk=False),
    BaseEntityForm(FindingTemplateWebTest, skip_pk=False),
    BaseEntityForm(FindingTemplateMobileTest, skip_pk=False),
    BaseEntityForm(FindingTemplateCWE, skip_pk=False)
):
    cwe_ref = SelectMultipleField(
        "Common Weakness Enumeration",
        choices=CWE.choices(),
        coerce=CWE.coerce,
        validators=[validators.DataRequired()])
    status = SelectField(
        "Status",
        choices=FindingStatus.choices(),
        default=FindingStatus.Pending,
        coerce=FindingStatus.coerce)
    type = SelectField(
        "Type",
        choices=FindingType.choices(),
        default=FindingType.Web,
        coerce=FindingType.coerce)
    lang = SelectField(
        "Language",
        choices=Language.choices(),
        default=Language.Spanish,
        coerce=Language.coerce)
    tech_risk = HiddenField(default=Score.NA)
    business_risk = HiddenField(default=Score.NA)
    exploitability = HiddenField(default=Score.NA)
    dissemination = HiddenField(default=Score.NA)
    solution_complexity = HiddenField(default=Score.NA)    
    asvs_req = SelectMultipleField(
        label="ASVS - OWASP Application Security Verification Standard Requirement #",
        choices=ASVS.choices(),
        coerce=ASVS.coerce)
    masvs_req = SelectMultipleField(
        label="MASVS - OWASP Mobile Application Security Verification Standard Requirement #",
        choices=MASVS.choices(),
        coerce=MASVS.coerce)
    wstg_ref = SelectMultipleField(
        label="Web Security Testing Guide",
        choices=WSTG.choices(),
        coerce=WSTG.coerce)
    mstg_ref = SelectMultipleField(
        label="Mobile Security Testing Guide",
        choices=MSTG.choices(),
        coerce=MSTG.coerce)


class FindingTemplateEditForm(
    BaseEntityForm(
        FindingTemplate,
        hide_attrs={'cvss_v3_score', 'cvss_v3_vector'},
        skip_attrs={'owisam_category'}
    ),
    BaseEntityForm(FindingTemplateWebRequirement, skip_pk=False),
    BaseEntityForm(FindingTemplateMobileRequirement, skip_pk=False),
    BaseEntityForm(FindingTemplateWebTest, skip_pk=False),
    BaseEntityForm(FindingTemplateMobileTest, skip_pk=False),
    BaseEntityForm(FindingTemplateCWE, skip_pk=False)
):
    cwe_ref = SelectMultipleField(
        "Common Weakness Enumeration",
        choices=CWE.choices(),
        coerce=CWE.coerce,
        validators=[validators.DataRequired()])
    status = SelectField(
        "Status",
        choices=FindingStatus.choices(),
        default=FindingStatus.Pending,
        coerce=FindingStatus.coerce)
    type = SelectField(
        "Type",
        choices=FindingType.choices(),
        default=FindingType.Web,
        coerce=FindingType.coerce)
    lang = SelectField(
        "Language",
        choices=Language.choices(),
        default=Language.Spanish,
        coerce=Language.coerce)
    tech_risk = HiddenField(default=Score.NA)
    business_risk = HiddenField(default=Score.NA)
    exploitability = HiddenField(default=Score.NA)
    dissemination = HiddenField(default=Score.NA)
    solution_complexity = HiddenField(default=Score.NA)
    asvs_req = SelectMultipleField(
        label="ASVS - OWASP Application Security Verification Standard Requirement #",
        choices=ASVS.choices(),
        coerce=ASVS.coerce)
    masvs_req = SelectMultipleField(
        label="MASVS - OWASP Mobile Application Security Verification Standard Requirement #",
        choices=MASVS.choices(),
        coerce=MASVS.coerce)
    wstg_ref = SelectMultipleField(
        label="Web Security Testing Guide",
        choices=WSTG.choices(),
        coerce=WSTG.coerce)
    mstg_ref = SelectMultipleField(
        label="Mobile Security Testing Guide",
        choices=MSTG.choices(),
        coerce=MSTG.coerce)


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
