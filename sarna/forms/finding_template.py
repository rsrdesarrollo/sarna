from wtforms import validators

from sarna.forms.base_entity_form import BaseEntityForm
from sarna.model.finding_template import FindingTemplate, FindingTemplateTranslation, Solution


class FindingTemplateCreateNewForm(
    BaseEntityForm(FindingTemplate, hide_attrs={'cvss_v3_score', 'cvss_v3_vector'}),
    BaseEntityForm(FindingTemplateTranslation, skip_pk=False)
):
    pass


class FindingTemplateEditForm(BaseEntityForm(FindingTemplate, hide_attrs={'cvss_v3_score', 'cvss_v3_vector'})):
    pass


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
