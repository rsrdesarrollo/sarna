from typing import *
from docxtpl import DocxTemplate
from sarna import PROJECT_PATH
from sarna.routes import parse_url
from sarna.model import Assessment, Template
from sarna.model import db_session
from sarna.report_generator.style import get_document_render_styles
from sarna.report_generator.markdown import markdown_to_docx, DOCXRenderer
from sarna.report_generator.scores import score_to_docx
from werkzeug.utils import secure_filename

import tempfile
import os
import time
import shutil
import jinja2


def clean_temp_dir():
    for path, dirs, _ in os.walk('/tmp'):
        for dir in dirs:
            if not dir.startswith('sarna-'):
                continue

            dir_path = os.path.join(path, dir)
            now = time.time()
            if now - os.path.getctime(dir_path) > 120:
                shutil.rmtree(dir_path)


def mk_working_dir():
    return tempfile.mkdtemp(prefix='sarna-', dir='/tmp')


@db_session
def generate_reports_bundle(assessment: Assessment, templates: List[Template]) -> AnyStr:
    """
    :param assessment: Assessment object
    :param templates: List of templates
    :return: Path to report bundle
    """

    clean_temp_dir()

    out_dir = mk_working_dir()

    def image_path_converter(path):
        not_found_image_path = os.path.join(PROJECT_PATH, 'resources', 'images', 'img_not_found.png')
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
            return score_to_docx(text, render_styles.get_style(style))

        # apply jinja template
        jinja2_env = jinja2.Environment()
        jinja2_env.filters['markdown'] = markdown
        jinja2_env.filters['score'] = score

        template_render.render(
            dict(
                client=assessment.client,
                assessment=assessment,
                date='2018/05/19'
            ),
            jinja_env=jinja2_env
        )
        out_file = secure_filename("{}-{}.docx".format(assessment.name, template.name))
        template_render.save(os.path.join(out_dir, out_file))

    if len(templates) > 1:
        # make a zip file with all the reports
        pass

    # return file path of output
    return out_dir, out_file
