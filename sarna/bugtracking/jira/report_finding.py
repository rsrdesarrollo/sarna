import os
import datetime
import re

from sarna.core.auth import current_user
from sarna.model import db
from sarna.model.enums import Score, AssessmentType
from jira import JIRA
from flask import flash, abort

__all__ = [ 'JiraAPI' ]

class JiraAPI:
    attachment_regex = re.compile('!\[.+\]\((.+)\)')
    reference_regex = re.compile('\[([^\[\]].+)]\((http.+)\)')
    project_regex = re.compile('^' + os.getenv('JIRA_SERVER').replace(".", "\.") + '/projects/' + '([A-Z]+)$')

    def create_finding(self, finding):
        horizontal_line = "\n----\n"
        
        jira = JIRA({ 
            'server': os.getenv('JIRA_SERVER'), 
            'verify': os.getenv('JIRA_SSL_CERT')
            },         
            auth=(os.getenv('JIRA_USER'), os.getenv('JIRA_PASSWORD'))
        )

        project_to_report = None
        # Affected resources might have a reference to a bugtracking project
        for resource in finding.affected_resources:
            match = self.project_regex.search(resource.uri)
            if match:
                project_to_report = jira.project(match.group(1)).raw
                break

        # If not, default to related field at assessment
        if project_to_report is None and finding.assessment.bugtracking:
            assessment_ticket = jira.issue(finding.assessment.bugtracking, fields='customfield_19160')
            if assessment_ticket:
                project_to_report = assessment_ticket.raw['fields']['customfield_19160']
        elif finding.assessment.bugtracking:
            assessment_ticket = jira.issue(finding.assessment.bugtracking, fields='customfield_19160')

        if project_to_report is None:
            abort(400, description='Unable to determine project for issue creation.')
        
        # Gather Issue information
        severity = None
        goal_date = datetime.datetime.now()

        if finding.cvss_v3_severity is Score.Info:
            severity = { 'id': 0 } # Trivial
            goal_date = goal_date + datetime.timedelta(weeks=52)
        elif finding.cvss_v3_severity is Score.Low:
            severity = { 'id': 1 } # Menor
            goal_date = goal_date + datetime.timedelta(weeks=52)
        elif finding.cvss_v3_severity is Score.Medium:
            severity = { 'id': 2 } # Importante
            goal_date = goal_date + datetime.timedelta(weeks=24)
        elif finding.cvss_v3_severity is Score.High:
            severity = { 'id': 3 } # Muy Importante
            goal_date = goal_date + datetime.timedelta(weeks=12)
        else:
            severity = { 'id': 4 } # Critico
            goal_date = goal_date + datetime.timedelta(weeks=4)

        # Compose issue description
        description = finding.definition + horizontal_line + finding.description
        if finding.solution:
            description += horizontal_line + finding.solution
        if finding.references:
            description += horizontal_line + finding.references

        """ 
        Change ocurrences of
            (attachment) ![Evidence 1](/assessments/<id>/evidences/<filename>)
            (reference) [Lorem](https://www.lipsum.com/)            
        for jira syntax:
            !filename|thumbnail! 
            [Lorem|https://www.lipsum.com/]
        """
        attachments = []        
        for match in self.attachment_regex.finditer(description):
            filename = match.group(1).split("/")
            filename = filename[len(filename) - 1]
            description = description.replace(match.group(0), "!" + filename + "|thumbnail!")
            attachments.append(filename)
        for match in self.reference_regex.finditer(description):
            description = description.replace(match.group(0), "[" + match.group(1) + "|" + match.group(2) + "]")
        
        data = dict({
            'labels': [ "SEC_DV" ],
            'customfield_18560': finding.cvss_v3_score, 
            'customfield_18561': finding.cvss_v3_vector,
            #'customfield_19768':  { 'id': severity['id'] },
            'customfield_20964': finding.owasp_category.code if finding.owasp_category is not None else finding.owasp_mobile_category.code,
            'customfield_20963': finding.asvs if finding.asvs != '0.0.0' else finding.masvs,
            #'priority': { 'id': severity['id'] },
            'customfield_12660': { 'id': '16775' },
            'summary': finding.title,
            #'reporter': current_user.username ,
            'issuetype': { 'id': 13201 },
            'project': { 'key': project_to_report['key'], 'id': project_to_report['id'] },
            'security': { 'name': 'AdminSeguridad', 'id': '15060' },
            'customfield_13069': goal_date.strftime("%Y-%m-%d"),
            'description': description
        })
        
        task = jira.create_issue(fields=data)

        flash('Security Task {} created. Some fields can not be informed on creation. Remember to review it.'.format(task.key), category='warning')

        finding.bugtracking = task.key

        db.session.commit()

        if assessment_ticket:
            jira.create_issue_link('Relates', task, assessment_ticket)
        
        base_path = finding.assessment.evidence_path()
        for att in attachments:
            jira.add_attachment(task, base_path + "/" + att)
        
        """
        task.update(fields={ 
            'customfield_19768':  { 'id': severity['id'] },
            'priority': { 'id': severity['id'] }
            })
        """      
