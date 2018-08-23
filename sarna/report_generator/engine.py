import os
import shutil
import tempfile
import zipfile
from datetime import datetime
from typing import *

import jinja2
import time
from docxtpl import DocxTemplate
from werkzeug.utils import secure_filename

from sarna.core.config import config
from sarna.model import Assessment
from sarna.model.client import Template
from sarna.model.enums import FindingStatus
from sarna.report_generator.locale_choice import locale_choice
from sarna.report_generator.markdown import markdown_to_docx, DOCXRenderer
from sarna.report_generator.scores import score_to_docx
from sarna.report_generator.style import get_document_render_styles
from sarna.report_generator.xrefs import xref, bookmark
from sarna.routes import parse_url


def dateformat(value, fmt='%d/%m/%Y'):
    return value.strftime(fmt)


def clean_temp_dir():
    for path, dirs, files in os.walk('/tmp'):
        for directory in dirs:
            if not directory.startswith('sarna-'):
                continue

            dir_path = os.path.join(path, directory)
            now = time.time()
            if now - os.path.getctime(dir_path) > 120:
                shutil.rmtree(dir_path)

        for file in files:
            if not file.startswith('sarna-'):
                continue

            now = time.time()
            file_path = os.path.join(path, file)
            if now - os.path.getctime(file_path) > 120:
                os.unlink(file_path)


def mk_working_dir():
    return tempfile.mkdtemp(prefix='sarna-', dir='/tmp')


def generate_reports_bundle(assessment: Assessment, templates: Collection[Template]) -> Tuple[AnyStr, AnyStr]:
    """
    :param assessment: Assessment object
    :param templates: List of templates
    :return: Path to report bundle
    """

    clean_temp_dir()

    out_dir = mk_working_dir()
    out_file = ""

    def image_path_converter(path):
        not_found_image_path = os.path.join(config.PROJECT_PATH, 'resources', 'images', 'img_not_found.png')
        try:
            _, args = parse_url(path)
            file_path = os.path.abspath(
                os.path.join(assessment.evidence_path(), args['evidence_name'])
            )
            if os.path.isfile(file_path):
                return file_path
            else:
                return not_found_image_path
        except Exception:
            return not_found_image_path

    for template in templates:
        template_path = os.path.join(assessment.client.template_path(), template.file)

        template_render = DocxTemplate(template_path)
        render_styles = get_document_render_styles(template_path)

        render = DOCXRenderer(template_render, image_path_converter)

        def markdown(text, style='default'):
            render.set_style(render_styles.get_style(style))
            return markdown_to_docx(text, render)

        def score(text, style='default'):
            return score_to_docx(text, render_styles.get_style(style), assessment.lang)

        def locale(choice):
            return locale_choice(choice, assessment.lang)
        
        finding_status_valid = {FindingStatus.Confirmed, FindingStatus.Reviewed}
        assessment_data = assessment.to_dict()
        assessment_data['findings'] = list(
            filter(lambda f: f.status in finding_status_valid, assessment.findings)
        )

        # apply jinja template
        jinja2_env = jinja2.Environment()
        jinja2_env.filters['markdown'] = markdown
        jinja2_env.filters['score'] = score
        jinja2_env.filters['locale'] = locale
        jinja2_env.filters['xref'] = xref
        jinja2_env.filters['bookmark'] = bookmark
        jinja2_env.filters['dateformat'] = dateformat

        template_render.render(
            dict(
                client=assessment.client,
                assessment=assessment_data,
                date=datetime.date(datetime.now())
            ),
            jinja_env=jinja2_env
        )
        out_file = secure_filename("{}-{}.docx".format(assessment.name, template.name))
        template_render.save(os.path.join(out_dir, out_file))

    if len(templates) > 1:
        _, out_file = tempfile.mkstemp(prefix='sarna-reports', suffix='.zip', dir='/tmp')
        zipf = zipfile.ZipFile(out_file, 'w', zipfile.ZIP_DEFLATED)
        for root, dirs, files in os.walk(out_dir):
            for file in files:
                zipf.write(os.path.join(root, file), file)
        zipf.close()

        out_dir = '/tmp'
        out_file = out_file.split('/')[-1]

    # return file path of output
    return out_dir, out_file
