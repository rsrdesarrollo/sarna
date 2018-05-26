from pony.orm.dbapiprovider import IntConverter, Json
from aenum import Enum


class LocaleText(Json):
    pass


class Choice(Enum):
    @classmethod
    def choices(cls):
        return [("", "---")] + [cls.choice(elem) for elem in cls]

    @classmethod
    def choice(cls, elem):
        if isinstance(elem, cls):
            return elem, getattr(elem, 'desc', elem.name.replace("_", " "))
        elif elem:
            return cls[elem], cls[elem].name.replace("_", " ")
        else:
            return None

    @classmethod
    def coerce(cls, item):
        if not item:
            return ''

        return cls[item.replace(" ", "_")] if not isinstance(item, cls) else item

    def __str__(self):
        return self.name.replace("_", " ")


class Score(Choice):
    Info = 1
    Low = 2
    Medium = 3
    High = 4
    Critical = 5


class Language(Choice):
    Spanish = 1
    English = 2


class AssessmentType(Choice):
    Web = 1
    External_pentest = 2
    Mobile = 3
    iOS = 4
    Android = 5
    WiFi = 6


class FindingType(Choice):
    Web = 1
    Infra = 3
    Config = 4


class FindingStatus(Choice):
    Pending = 1
    Reviewed = 2
    Confirmed = 3
    False_Positive = 4
    Other = 5


class AssessmentStatus(Choice):
    Open = 1
    Closed = 2
    Archived = 3


class OWASPCategory(Choice):
    _init_ = "value desc"
    OTG_INFO_001 = 1, 'OTG-INFO-001 - Conduct Search Engine Discovery and Reconnaissance for Information Leakage'
    OTG_INFO_002 = 2, 'OTG-INFO-002 - Fingerprint Web Server'
    OTG_INFO_003 = 3, 'OTG-INFO-003 - Review Webserver Metafiles for Information Leakage'
    OTG_INFO_004 = 4, 'OTG-INFO-004 - Enumerate Applications on Webserver'
    OTG_INFO_005 = 5, 'OTG-INFO-005 - Review Webpage Comments and Metadata for Information Leakage'
    OTG_INFO_006 = 6, 'OTG-INFO-006 - Identify application entry points'
    OTG_INFO_007 = 7, 'OTG-INFO-007 - Map execution paths through application'
    OTG_INFO_008 = 8, 'OTG-INFO-008 - Fingerprint Web Application Framework'
    OTG_INFO_009 = 9, 'OTG-INFO-009 - Fingerprint Web Application'
    OTG_INFO_010 = 10, 'OTG-INFO-010 - Map Application Architecture'
    OTG_CONFIG_001 = 11, 'OTG-CONFIG-001 - Test Network/Infrastructure Configuration'
    OTG_CONFIG_002 = 12, 'OTG-CONFIG-002 - Test Application Platform Configuration'
    OTG_CONFIG_003 = 13, 'OTG-CONFIG-003 - Test File Extensions Handling for Sensitive Information'
    OTG_CONFIG_004 = 14, 'OTG-CONFIG-004 - Backup and Unreferenced Files for Sensitive Information'
    OTG_CONFIG_005 = 15, 'OTG-CONFIG-005 - Enumerate Infrastructure and Application Admin Interfaces'
    OTG_CONFIG_006 = 16, 'OTG-CONFIG-006 - Test HTTP Methods'
    OTG_CONFIG_007 = 17, 'OTG-CONFIG-007 - Test HTTP Strict Transport Security'
    OTG_CONFIG_008 = 18, 'OTG-CONFIG-008 - Test RIA cross domain policy'
    OTG_IDENT_001 = 19, 'OTG-IDENT-001 - Test Role Definitions'
    OTG_IDENT_002 = 20, 'OTG-IDENT-002 - Test User Registration Process'
    OTG_IDENT_003 = 21, 'OTG-IDENT-003 - Test Account Provisioning Process'
    OTG_IDENT_004 = 22, 'OTG-IDENT-004 - Testing for Account Enumeration and Guessable User Account'
    OTG_IDENT_005 = 23, 'OTG-IDENT-005 - Testing for Weak or unenforced username policy'
    OTG_IDENT_006 = 24, 'OTG-IDENT-006 - Test Permissions of Guest/Training Accounts'
    OTG_IDENT_007 = 25, 'OTG-IDENT-007 - Test Account Suspension/Resumption Process'
    OTG_AUTHN_001 = 26, 'OTG-AUTHN-001 - Testing for Credentials Transported over an Encrypted Channel'
    OTG_AUTHN_002 = 27, 'OTG-AUTHN-002 - Testing for default credentials'
    OTG_AUTHN_003 = 28, 'OTG-AUTHN-003 - Testing for Weak lock out mechanism'
    OTG_AUTHN_004 = 29, 'OTG-AUTHN-004 - Testing for bypassing authentication schema'
    OTG_AUTHN_005 = 30, 'OTG-AUTHN-005 - Test remember password functionality'
    OTG_AUTHN_006 = 31, 'OTG-AUTHN-006 - Testing for Browser cache weakness'
    OTG_AUTHN_007 = 32, 'OTG-AUTHN-007 - Testing for Weak password policy'
    OTG_AUTHN_008 = 33, 'OTG-AUTHN-008 - Testing for Weak security question/answer'
    OTG_AUTHN_009 = 34, 'OTG-AUTHN-009 - Testing for weak password change or reset functionalities'
    OTG_AUTHN_010 = 35, 'OTG-AUTHN-010 - Testing for Weaker authentication in alternative channel'
    OTG_AUTHZ_001 = 36, 'OTG-AUTHZ-001 - Testing Directory traversal/file include'
    OTG_AUTHZ_002 = 37, 'OTG-AUTHZ-002 - Testing for bypassing authorization schema'
    OTG_AUTHZ_003 = 38, 'OTG-AUTHZ-003 - Testing for Privilege Escalation'
    OTG_AUTHZ_004 = 39, 'OTG-AUTHZ-004 - Testing for Insecure Direct Object References'
    OTG_SESS_001 = 40, 'OTG-SESS-001 - Testing for Bypassing Session Management Schema'
    OTG_SESS_002 = 41, 'OTG-SESS-002 - Testing for Cookies attributes'
    OTG_SESS_003 = 42, 'OTG-SESS-003 - Testing for Session Fixation'
    OTG_SESS_004 = 43, 'OTG-SESS-004 - Testing for Exposed Session Variables'
    OTG_SESS_005 = 44, 'OTG-SESS-005 - Testing for Cross Site Request Forgery'
    OTG_SESS_006 = 45, 'OTG-SESS-006 - Testing for logout functionality'
    OTG_SESS_007 = 46, 'OTG-SESS-007 - Test Session Timeout'
    OTG_SESS_008 = 47, 'OTG-SESS-008 - Testing for Session puzzling'
    OTG_INPVAL_001 = 48, 'OTG-INPVAL-001 - Testing for Reflected Cross Site Scripting'
    OTG_INPVAL_002 = 49, 'OTG-INPVAL-002 - Testing for Stored Cross Site Scripting'
    OTG_INPVAL_003 = 50, 'OTG-INPVAL-003 - Testing for HTTP Verb Tampering'
    OTG_INPVAL_004 = 51, 'OTG-INPVAL-004 - Testing for HTTP Parameter pollution'
    OTG_INPVAL_005 = 52, 'OTG-INPVAL-005 - Testing for SQL Injection'
    OTG_INPVAL_006 = 53, 'OTG-INPVAL-006 - Testing for LDAP Injection'
    OTG_INPVAL_007 = 54, 'OTG-INPVAL-007 - Testing for ORM Injection'
    OTG_INPVAL_008 = 55, 'OTG-INPVAL-008 - Testing for XML Injection'
    OTG_INPVAL_009 = 56, 'OTG-INPVAL-009 - Testing for SSI Injection'
    OTG_INPVAL_010 = 57, 'OTG-INPVAL-010 - Testing for XPath Injection'
    OTG_INPVAL_011 = 58, 'OTG-INPVAL-011 - IMAP/SMTP Injection'
    OTG_INPVAL_012 = 59, 'OTG-INPVAL-012 - Testing for Code Injection'
    OTG_INPVAL_013 = 60, 'OTG-INPVAL-013 - Testing for Command Injection'
    OTG_INPVAL_014 = 61, 'OTG-INPVAL-014 - Testing for Buffer overflow'
    OTG_INPVAL_015 = 62, 'OTG-INPVAL-015 - Testing for incubated vulnerabilities'
    OTG_INPVAL_016 = 63, 'OTG-INPVAL-016 - Testing for HTTP Splitting/Smuggling'
    OTG_ERR_001 = 64, 'OTG-ERR-001 - Analysis of Error Codes'
    OTG_ERR_002 = 65, 'OTG-ERR-002 - Analysis of Stack Traces'
    OTG_CRYPST_002 = 66, 'OTG-CRYPST-002 - Testing for Padding Oracle'
    OTG_CRYPST_003 = 67, 'OTG-CRYPST-003 - Testing for Sensitive information sent via unencrypted channels'
    OTG_BUSLOGIC_001 = 68, 'OTG-BUSLOGIC-001 - Test Business Logic Data Validation'
    OTG_BUSLOGIC_002 = 69, 'OTG-BUSLOGIC-002 - Test Ability to Forge Requests'
    OTG_BUSLOGIC_003 = 70, 'OTG-BUSLOGIC-003 - Test Integrity Checks'
    OTG_BUSLOGIC_004 = 71, 'OTG-BUSLOGIC-004 - Test for Process Timing'
    OTG_BUSLOGIC_005 = 72, 'OTG-BUSLOGIC-005 - Test Number of Times a Function Can be Used Limits'
    OTG_BUSLOGIC_006 = 73, 'OTG-BUSLOGIC-006 - Testing for the Circumvention of Work Flows'
    OTG_BUSLOGIC_007 = 74, 'OTG-BUSLOGIC-007 - Test Defenses Against Application Mis-use'
    OTG_BUSLOGIC_008 = 75, 'OTG-BUSLOGIC-008 - Test Upload of Unexpected File Types'
    OTG_BUSLOGIC_009 = 76, 'OTG-BUSLOGIC-009 - Test Upload of Malicious Files'
    OTG_CLIENT_001 = 77, 'OTG-CLIENT-001 - Testing for DOM based Cross Site Scripting'
    OTG_CLIENT_002 = 78, 'OTG-CLIENT-002 - Testing for JavaScript Execution'
    OTG_CLIENT_003 = 79, 'OTG-CLIENT-003 - Testing for HTML Injection'
    OTG_CLIENT_004 = 80, 'OTG-CLIENT-004 - Testing for Client Side URL Redirect'
    OTG_CLIENT_005 = 81, 'OTG-CLIENT-005 - Testing for CSS Injection'
    OTG_CLIENT_006 = 82, 'OTG-CLIENT-006 - Testing for Client Side Resource Manipulation'
    OTG_CLIENT_007 = 83, 'OTG-CLIENT-007 - Test Cross Origin Resource Sharing'
    OTG_CLIENT_008 = 84, 'OTG-CLIENT-008 - Testing for Cross Site Flashing'
    OTG_CLIENT_009 = 85, 'OTG-CLIENT-009 - Testing for Clickjacking'
    OTG_CLIENT_010 = 86, 'OTG-CLIENT-010 - Testing WebSockets'
    OTG_CLIENT_011 = 87, 'OTG-CLIENT-011 - Test Web Messaging'
    OTG_CLIENT_012 = 88, 'OTG-CLIENT-012 - Test Local Storage'


class ChoiceEnumConverter(IntConverter):
    def validate(self, val, obj=None):
        if not isinstance(val, Enum):
            raise ValueError('Must be an Enum.  Got {}'.format(type(val)))
        return val

    def sql2py(self, val):
        if not val:
            return None
        return self.py_type(val)

    def py2sql(self, val):
        return val.value
