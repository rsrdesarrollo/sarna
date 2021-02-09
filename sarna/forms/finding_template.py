from wtforms import validators, SelectField, SelectMultipleField

from sarna.forms.base_entity_form import BaseEntityForm
from sarna.model.finding_template import FindingTemplate, FindingTemplateTranslation, Solution, \
    FindingTemplateWebRequirement, FindingTemplateMobileRequirement, FindingTemplateWebTest, \
    FindingTemplateMobileTest, FindingTemplateCWE
from sarna.model.enums import FindingStatus, FindingType, Language, WSTG, MSTG, CWE, ASVS, MASVS


class FindingTemplateCreateNewForm(
    BaseEntityForm(
        FindingTemplate,
        hide_attrs={'cvss_v3_score', 'cvss_v3_vector'}
    ),
    BaseEntityForm(FindingTemplateTranslation, skip_pk=False),
    BaseEntityForm(FindingTemplateWebRequirement, skip_pk=False),
    BaseEntityForm(FindingTemplateMobileRequirement, skip_pk=False),
    BaseEntityForm(FindingTemplateWebTest, skip_pk=False),
    BaseEntityForm(FindingTemplateMobileTest, skip_pk=False),
    BaseEntityForm(FindingTemplateCWE, skip_pk=False)
):
    cwe_ref = SelectMultipleField(
        "Common Weakness Enumeration",
        choices=CWE.none_blank_choices(),
        coerce=CWE.coerce,
        validators=[
            validators.DataRequired()
        ]
    )
    status = SelectField(
        "Status",
        choices=FindingStatus.none_blank_choices(),
        default=FindingStatus.Pending,
        coerce=FindingStatus.coerce,
        validators=[
            validators.DataRequired()
        ]
    )
    type = SelectField(
        "Type",
        choices=FindingType.none_blank_choices(),
        default=FindingType.Web,
        coerce=FindingType.coerce,
        validators=[
            validators.DataRequired()
        ]
    )
    lang = SelectField(
        "Language",
        choices=Language.none_blank_choices(),
        default=Language.Spanish,
        coerce=Language.coerce,
        validators=[
            validators.DataRequired()
        ]
    )
    asvs_req = SelectMultipleField(
        label="ASVS - OWASP Application Security Verification Standard Requirement #",
        choices=ASVS.none_blank_choices(),
        coerce=ASVS.coerce,
        validators=[
            validators.Optional()
        ]
    )
    masvs_req = SelectMultipleField(
        label="MASVS - OWASP Mobile Application Security Verification Standard Requirement #",
        choices=MASVS.none_blank_choices(),
        coerce=MASVS.coerce,
        validators=[
            validators.Optional()
        ]
    )
    wstg_ref = SelectMultipleField(
        label="Web Security Testing Guide",
        choices=WSTG.none_blank_choices(),
        coerce=WSTG.coerce,
        validators=[
            validators.Optional()
        ]
    )
    mstg_ref = SelectMultipleField(
        label="Mobile Security Testing Guide",
        choices=MSTG.none_blank_choices(),
        coerce=MSTG.coerce,
        validators=[
            validators.Optional()
        ]
    )


class FindingTemplateEditForm(
    BaseEntityForm(
        FindingTemplate,
        hide_attrs={'cvss_v3_score', 'cvss_v3_vector'}
    ),
    BaseEntityForm(FindingTemplateWebRequirement, skip_pk=False),
    BaseEntityForm(FindingTemplateMobileRequirement, skip_pk=False),
    BaseEntityForm(FindingTemplateWebTest, skip_pk=False),
    BaseEntityForm(FindingTemplateMobileTest, skip_pk=False),
    BaseEntityForm(FindingTemplateCWE, skip_pk=False)
):
    cwe_ref = SelectMultipleField(
        "Common Weakness Enumeration",
        choices=CWE.none_blank_choices(),
        coerce=CWE.coerce,
        validators=[
            validators.DataRequired()
        ]
    )
    status = SelectField(
        "Status",
        choices=FindingStatus.none_blank_choices(),
        default=FindingStatus.Pending,
        coerce=FindingStatus.coerce,
        validators=[
            validators.DataRequired()
        ]
    )
    type = SelectField(
        "Type",
        choices=FindingType.none_blank_choices(),
        default=FindingType.Web,
        coerce=FindingType.coerce,
        validators=[
            validators.DataRequired()
        ]
    )
    lang = SelectField(
        "Language",
        choices=Language.none_blank_choices(),
        default=Language.Spanish,
        coerce=Language.coerce,
        validators=[
            validators.DataRequired()
        ]
    )
    asvs_req = SelectMultipleField(
        label="ASVS - OWASP Application Security Verification Standard Requirement #",
        choices=ASVS.none_blank_choices(),
        coerce=ASVS.coerce,
        validators=[
            validators.Optional()
        ]
    )
    masvs_req = SelectMultipleField(
        label="MASVS - OWASP Mobile Application Security Verification Standard Requirement #",
        choices=MASVS.none_blank_choices(),
        coerce=MASVS.coerce,
        validators=[
            validators.Optional()
        ]
    )
    wstg_ref = SelectMultipleField(
        label="Web Security Testing Guide",
        choices=WSTG.none_blank_choices(),
        coerce=WSTG.coerce,
        validators=[
            validators.Optional()
        ]
    )
    mstg_ref = SelectMultipleField(
        label="Mobile Security Testing Guide",
        choices=MSTG.none_blank_choices(),
        coerce=MSTG.coerce,
        validators=[
            validators.Optional()
        ]
    )


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
