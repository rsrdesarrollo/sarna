from aenum import OrderedEnum, Enum
from pony.orm.dbapiprovider import IntConverter, Json


class LocaleText(Json):
    pass


class Choice(OrderedEnum):
    @classmethod
    def choices(cls):
        return [("", "---")] + [cls.choice(elem) for elem in cls]

    @classmethod
    def choice(cls, elem):
        if isinstance(elem, cls):
            desc = getattr(elem, 'desc', None)
            name = getattr(elem, 'code', elem.name.replace("_", " "))
            if desc:
                return elem, "{} - {}".format(name, desc)
            else:
                return elem, name
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


class Language(Choice):
    Spanish = 1
    English = 2


class Score(Choice):
    _init_ = "value translation"
    Info = 1, {
        Language.English: 'Info',
        Language.Spanish: 'Informativo'
    }
    Low = 2, {
        Language.English: 'Low',
        Language.Spanish: 'Bajo'
    }
    Medium = 3, {
        Language.English: 'Medium',
        Language.Spanish: 'Medio'
    }
    High = 4, {
        Language.English: 'High',
        Language.Spanish: 'Alto'
    }
    Critical = 5, {
        Language.English: 'Critical',
        Language.Spanish: 'Crítico'
    }
    NA = 6, {
        Language.English: 'N/A',
        Language.Spanish: 'N/A'
    }


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
    _init_ = "value code desc translation"
    OTG_INFO_001 = 1, 'OTG-INFO-001', 'Conduct Search Engine Discovery and Reconnaissance for Information Leakage', {
        Language.English: 'Conduct Search Engine Discovery and Reconnaissance for Information Leakage',
        Language.Spanish: 'Busqueda de fugas de información por Motores de Busqueda'
    }
    OTG_INFO_002 = 2, 'OTG-INFO-002', 'Fingerprint Web Server', {
        Language.English: 'Fingerprint Web Server',
        Language.Spanish: 'Identificación del Servidor Web'
    }
    OTG_INFO_003 = 3, 'OTG-INFO-003', 'Review Webserver Metafiles for Information Leakage', {
        Language.English: 'Review Webserver Metafiles for Information Leakage',
        Language.Spanish: 'Comprobación de Metaficheros del Servidor en busca de fugas de información'
    }
    OTG_INFO_004 = 4, 'OTG-INFO-004', 'Enumerate Applications on Webserver', {
        Language.English: 'Enumerate Applications on Webserver',
        Language.Spanish: 'Enumeración de Applicaciones en el Servidor'
    }
    OTG_INFO_005 = 5, 'OTG-INFO-005', 'Review Webpage Comments and Metadata for Information Leakage', {
        Language.English: 'Review Webpage Comments and Metadata for Information Leakage',
        Language.Spanish: 'Revisión del comentarios y metadatos en la Web en busca de fugas de información'
    }
    OTG_INFO_006 = 6, 'OTG-INFO-006', 'Identify application entry points', {
        Language.English: 'Identify application entry points',
        Language.Spanish: 'Identificación de puntos de entrada de la aplicación'
    }
    OTG_INFO_007 = 7, 'OTG-INFO-007', 'Map execution paths through application', {
        Language.English: 'Map execution paths through application',
        Language.Spanish: 'Creación de mapa de rutas de ejecución a través de la aplicación'
    }
    OTG_INFO_008 = 8, 'OTG-INFO-008', 'Fingerprint Web Application Framework', {
        Language.English: 'Fingerprint Web Application Framework',
        Language.Spanish: 'Identificación de Framework Web de Aplicación'
    }
    OTG_INFO_009 = 9, 'OTG-INFO-009', 'Fingerprint Web Application', {
        Language.English: 'Fingerprint Web Application',
        Language.Spanish: 'Identificación de Aplicación Web'
    }
    OTG_INFO_010 = 10, 'OTG-INFO-010', 'Map Application Architecture', {
        Language.English: 'Map Application Architecture',
        Language.Spanish: 'Creación de Mapa de Arquitectura de Aplicación'
    }
    OTG_CONFIG_001 = 11, 'OTG-CONFIG-001', 'Test Network/Infrastructure Configuration', {
        Language.English: 'Test Network/Infrastructure Configuration',
        Language.Spanish: 'Pruebas de Configuración de Red/Infraestructura'
    }
    OTG_CONFIG_002 = 12, 'OTG-CONFIG-002', 'Test Application Platform Configuration', {
        Language.English: 'Test Application Platform Configuration',
        Language.Spanish: 'Pruebas de Configuración de Plataforma'
    }
    OTG_CONFIG_003 = 13, 'OTG-CONFIG-003', 'Test File Extensions Handling for Sensitive Information', {
        Language.English: 'Test File Extensions Handling for Sensitive Information',
        Language.Spanish: 'Pruebas de Manejo de Extensiones de Ficheros'
    }
    OTG_CONFIG_004 = 14, 'OTG-CONFIG-004', 'Backup and Unreferenced Files for Sensitive Information', {
        Language.English: 'Backup and Unreferenced Files for Sensitive Information',
        Language.Spanish: 'Backups y Archivos no referenciados en búsqueda de Información Sensible'
    }
    OTG_CONFIG_005 = 15, 'OTG-CONFIG-005', 'Enumerate Infrastructure and Application Admin Interfaces', {
        Language.English: 'Enumerate Infrastructure and Application Admin Interfaces',
        Language.Spanish: 'Enumeración de Interfaces de Administración de Infraestructura y Aplicación'
    }
    OTG_CONFIG_006 = 16, 'OTG-CONFIG-006', 'Test HTTP Methods', {
        Language.English: 'Test HTTP Methods',
        Language.Spanish: 'Prueba de Métodos HTTP'
    }
    OTG_CONFIG_007 = 17, 'OTG-CONFIG-007', 'Test HTTP Strict Transport Security', {
        Language.English: 'Test HTTP Strict Transport Security',
        Language.Spanish: 'Pruebas de HTTP Strict Transport Security'
    }
    OTG_CONFIG_008 = 18, 'OTG-CONFIG-008', 'Test RIA cross domain policy', {
        Language.English: 'Test RIA cross domain policy',
        Language.Spanish: 'Pruebas de RIA cross domain policy'
    }
    OTG_IDENT_001 = 19, 'OTG-IDENT-001', 'Test Role Definitions', {
        Language.English: 'Test Role Definitions',
        Language.Spanish: 'Pruebas de Definición de Roles'
    }
    OTG_IDENT_002 = 20, 'OTG-IDENT-002', 'Test User Registration Process', {
        Language.English: 'Test User Registration Process',
        Language.Spanish: 'Pruebas en el Proceso de Registro de Usuarios'
    }
    OTG_IDENT_003 = 21, 'OTG-IDENT-003', 'Test Account Provisioning Process', {
        Language.English: 'Test Account Provisioning Process',
        Language.Spanish: 'Pruebas en el Proceso de Aprovisionamiento de Cuentas'
    }
    OTG_IDENT_004 = 22, 'OTG-IDENT-004', 'Testing for Account Enumeration and Guessable User Account', {
        Language.English: 'Testing for Account Enumeration and Guessable User Account',
        Language.Spanish: 'Pruebas de Enumeración de Usuarios y Cuentas Predecibles'
    }
    OTG_IDENT_005 = 23, 'OTG-IDENT-005', 'Testing for Weak or unenforced username policy', {
        Language.English: 'Testing for Weak or unenforced username policy',
        Language.Spanish: 'Pruebas de política de nombres de usuario Debil'
    }
    OTG_IDENT_006 = 24, 'OTG-IDENT-006', 'Test Permissions of Guest/Training Accounts', {
        Language.English: 'Test Permissions of Guest/Training Accounts',
        Language.Spanish: 'Pruebas de Permisos de Cuentas de Invitado/Prueba'
    }
    OTG_IDENT_007 = 25, 'OTG-IDENT-007', 'Test Account Suspension/Resumption Process', {
        Language.English: 'Test Account Suspension/Resumption Process',
        Language.Spanish: ''
    }
    OTG_AUTHN_001 = 26, 'OTG-AUTHN-001', 'Testing for Credentials Transported over an Encrypted Channel', {
        Language.English: 'Testing for Credentials Transported over an Encrypted Channel',
        Language.Spanish: ''
    }
    OTG_AUTHN_002 = 27, 'OTG-AUTHN-002', 'Testing for default credentials', {
        Language.English: 'Testing for default credentials',
        Language.Spanish: ''
    }
    OTG_AUTHN_003 = 28, 'OTG-AUTHN-003', 'Testing for Weak lock out mechanism', {
        Language.English: 'Testing for Weak lock out mechanism',
        Language.Spanish: ''
    }
    OTG_AUTHN_004 = 29, 'OTG-AUTHN-004', 'Testing for bypassing authentication schema', {
        Language.English: 'Testing for bypassing authentication schema',
        Language.Spanish: ''
    }
    OTG_AUTHN_005 = 30, 'OTG-AUTHN-005', 'Test remember password functionality', {
        Language.English: 'Test remember password functionality',
        Language.Spanish: ''
    }
    OTG_AUTHN_006 = 31, 'OTG-AUTHN-006', 'Testing for Browser cache weakness', {
        Language.English: 'Testing for Browser cache weakness',
        Language.Spanish: ''
    }
    OTG_AUTHN_007 = 32, 'OTG-AUTHN-007', 'Testing for Weak password policy', {
        Language.English: 'Testing for Weak password policy',
        Language.Spanish: ''
    }
    OTG_AUTHN_008 = 33, 'OTG-AUTHN-008', 'Testing for Weak security question/answer', {
        Language.English: 'Testing for Weak security question/answer',
        Language.Spanish: ''
    }
    OTG_AUTHN_009 = 34, 'OTG-AUTHN-009', 'Testing for weak password change or reset functionalities', {
        Language.English: 'Testing for weak password change or reset functionalities',
        Language.Spanish: ''
    }
    OTG_AUTHN_010 = 35, 'OTG-AUTHN-010', 'Testing for Weaker authentication in alternative channel', {
        Language.English: 'Testing for Weaker authentication in alternative channel',
        Language.Spanish: ''
    }
    OTG_AUTHZ_001 = 36, 'OTG-AUTHZ-001', 'Testing Directory traversal/file include', {
        Language.English: 'Testing Directory traversal/file include',
        Language.Spanish: ''
    }
    OTG_AUTHZ_002 = 37, 'OTG-AUTHZ-002', 'Testing for bypassing authorization schema', {
        Language.English: 'Testing for bypassing authorization schema',
        Language.Spanish: ''
    }
    OTG_AUTHZ_003 = 38, 'OTG-AUTHZ-003', 'Testing for Privilege Escalation', {
        Language.English: 'Testing for Privilege Escalation',
        Language.Spanish: ''
    }
    OTG_AUTHZ_004 = 39, 'OTG-AUTHZ-004', 'Testing for Insecure Direct Object References', {
        Language.English: 'Testing for Insecure Direct Object References',
        Language.Spanish: ''
    }
    OTG_SESS_001 = 40, 'OTG-SESS-001', 'Testing for Bypassing Session Management Schema', {
        Language.English: 'Testing for Bypassing Session Management Schema',
        Language.Spanish: ''
    }
    OTG_SESS_002 = 41, 'OTG-SESS-002', 'Testing for Cookies attributes', {
        Language.English: 'Testing for Cookies attributes',
        Language.Spanish: ''
    }
    OTG_SESS_003 = 42, 'OTG-SESS-003', 'Testing for Session Fixation', {
        Language.English: 'Testing for Session Fixation',
        Language.Spanish: ''
    }
    OTG_SESS_004 = 43, 'OTG-SESS-004', 'Testing for Exposed Session Variables', {
        Language.English: 'Testing for Exposed Session Variables',
        Language.Spanish: ''
    }
    OTG_SESS_005 = 44, 'OTG-SESS-005', 'Testing for Cross Site Request Forgery', {
        Language.English: 'Testing for Cross Site Request Forgery',
        Language.Spanish: ''
    }
    OTG_SESS_006 = 45, 'OTG-SESS-006', 'Testing for logout functionality', {
        Language.English: 'Testing for logout functionality',
        Language.Spanish: ''
    }
    OTG_SESS_007 = 46, 'OTG-SESS-007', 'Test Session Timeout', {
        Language.English: 'Test Session Timeout',
        Language.Spanish: ''
    }
    OTG_SESS_008 = 47, 'OTG-SESS-008', 'Testing for Session puzzling', {
        Language.English: 'Testing for Session puzzling',
        Language.Spanish: ''
    }
    OTG_INPVAL_001 = 48, 'OTG-INPVAL-001', 'Testing for Reflected Cross Site Scripting', {
        Language.English: 'Testing for Reflected Cross Site Scripting',
        Language.Spanish: ''
    }
    OTG_INPVAL_002 = 49, 'OTG-INPVAL-002', 'Testing for Stored Cross Site Scripting', {
        Language.English: 'Testing for Stored Cross Site Scripting',
        Language.Spanish: ''
    }
    OTG_INPVAL_003 = 50, 'OTG-INPVAL-003', 'Testing for HTTP Verb Tampering', {
        Language.English: 'Testing for HTTP Verb Tampering',
        Language.Spanish: ''
    }
    OTG_INPVAL_004 = 51, 'OTG-INPVAL-004', 'Testing for HTTP Parameter pollution', {
        Language.English: 'Testing for HTTP Parameter pollution',
        Language.Spanish: ''
    }
    OTG_INPVAL_005 = 52, 'OTG-INPVAL-005', 'Testing for SQL Injection', {
        Language.English: 'Testing for SQL Injection',
        Language.Spanish: ''
    }
    OTG_INPVAL_006 = 53, 'OTG-INPVAL-006', 'Testing for LDAP Injection', {
        Language.English: 'Testing for LDAP Injection',
        Language.Spanish: ''
    }
    OTG_INPVAL_007 = 54, 'OTG-INPVAL-007', 'Testing for ORM Injection', {
        Language.English: 'Testing for ORM Injection',
        Language.Spanish: ''
    }
    OTG_INPVAL_008 = 55, 'OTG-INPVAL-008', 'Testing for XML Injection', {
        Language.English: 'Testing for XML Injection',
        Language.Spanish: ''
    }
    OTG_INPVAL_009 = 56, 'OTG-INPVAL-009', 'Testing for SSI Injection', {
        Language.English: 'Testing for SSI Injection',
        Language.Spanish: ''
    }
    OTG_INPVAL_010 = 57, 'OTG-INPVAL-010', 'Testing for XPath Injection', {
        Language.English: 'Testing for XPath Injection',
        Language.Spanish: ''
    }
    OTG_INPVAL_011 = 58, 'OTG-INPVAL-011', 'IMAP/SMTP Injection', {
        Language.English: 'IMAP/SMTP Injection',
        Language.Spanish: ''
    }
    OTG_INPVAL_012 = 59, 'OTG-INPVAL-012', 'Testing for Code Injection', {
        Language.English: 'Testing for Code Injection',
        Language.Spanish: ''
    }
    OTG_INPVAL_013 = 60, 'OTG-INPVAL-013', 'Testing for Command Injection', {
        Language.English: 'Testing for Command Injection',
        Language.Spanish: ''
    }
    OTG_INPVAL_014 = 61, 'OTG-INPVAL-014', 'Testing for Buffer overflow', {
        Language.English: 'Testing for Buffer overflow',
        Language.Spanish: ''
    }
    OTG_INPVAL_015 = 62, 'OTG-INPVAL-015', 'Testing for incubated vulnerabilities', {
        Language.English: 'Testing for incubated vulnerabilities',
        Language.Spanish: ''
    }
    OTG_INPVAL_016 = 63, 'OTG-INPVAL-016', 'Testing for HTTP Splitting/Smuggling', {
        Language.English: 'Testing for HTTP Splitting/Smuggling',
        Language.Spanish: ''
    }
    OTG_ERR_001 = 64, 'OTG-ERR-001', 'Analysis of Error Codes', {
        Language.English: 'Analysis of Error Codes',
        Language.Spanish: ''
    }
    OTG_ERR_002 = 65, 'OTG-ERR-002', 'Analysis of Stack Traces', {
        Language.English: 'Analysis of Stack Traces',
        Language.Spanish: ''
    }
    OTG_CRYPST_002 = 66, 'OTG-CRYPST-002', 'Testing for Padding Oracle', {
        Language.English: 'Testing for Padding Oracle',
        Language.Spanish: ''
    }
    OTG_CRYPST_003 = 67, 'OTG-CRYPST-003', 'Testing for Sensitive information sent via unencrypted channels', {
        Language.English: 'Testing for Sensitive information sent via unencrypted channels',
        Language.Spanish: ''
    }
    OTG_BUSLOGIC_001 = 68, 'OTG-BUSLOGIC-001', 'Test Business Logic Data Validation', {
        Language.English: 'Test Business Logic Data Validation',
        Language.Spanish: ''
    }
    OTG_BUSLOGIC_002 = 69, 'OTG-BUSLOGIC-002', 'Test Ability to Forge Requests', {
        Language.English: 'Test Ability to Forge Requests',
        Language.Spanish: ''
    }
    OTG_BUSLOGIC_003 = 70, 'OTG-BUSLOGIC-003', 'Test Integrity Checks', {
        Language.English: 'Test Integrity Checks',
        Language.Spanish: ''
    }
    OTG_BUSLOGIC_004 = 71, 'OTG-BUSLOGIC-004', 'Test for Process Timing', {
        Language.English: 'Test for Process Timing',
        Language.Spanish: ''
    }
    OTG_BUSLOGIC_005 = 72, 'OTG-BUSLOGIC-005', 'Test Number of Times a Function Can be Used Limits', {
        Language.English: 'Test Number of Times a Function Can be Used Limits',
        Language.Spanish: ''
    }
    OTG_BUSLOGIC_006 = 73, 'OTG-BUSLOGIC-006', 'Testing for the Circumvention of Work Flows', {
        Language.English: 'Testing for the Circumvention of Work Flows',
        Language.Spanish: ''
    }
    OTG_BUSLOGIC_007 = 74, 'OTG-BUSLOGIC-007', 'Test Defenses Against Application Mis-use', {
        Language.English: 'Test Defenses Against Application Mis-use',
        Language.Spanish: ''
    }
    OTG_BUSLOGIC_008 = 75, 'OTG-BUSLOGIC-008', 'Test Upload of Unexpected File Types', {
        Language.English: 'Test Upload of Unexpected File Types',
        Language.Spanish: ''
    }
    OTG_BUSLOGIC_009 = 76, 'OTG-BUSLOGIC-009', 'Test Upload of Malicious Files', {
        Language.English: 'Test Upload of Malicious Files',
        Language.Spanish: ''
    }
    OTG_CLIENT_001 = 77, 'OTG-CLIENT-001', 'Testing for DOM based Cross Site Scripting', {
        Language.English: 'Testing for DOM based Cross Site Scripting',
        Language.Spanish: ''
    }
    OTG_CLIENT_002 = 78, 'OTG-CLIENT-002', 'Testing for JavaScript Execution', {
        Language.English: 'Testing for JavaScript Execution',
        Language.Spanish: ''
    }
    OTG_CLIENT_003 = 79, 'OTG-CLIENT-003', 'Testing for HTML Injection', {
        Language.English: 'Testing for HTML Injection',
        Language.Spanish: ''
    }
    OTG_CLIENT_004 = 80, 'OTG-CLIENT-004', 'Testing for Client Side URL Redirect', {
        Language.English: 'Testing for Client Side URL Redirect',
        Language.Spanish: ''
    }
    OTG_CLIENT_005 = 81, 'OTG-CLIENT-005', 'Testing for CSS Injection', {
        Language.English: 'Testing for CSS Injection',
        Language.Spanish: ''
    }
    OTG_CLIENT_006 = 82, 'OTG-CLIENT-006', 'Testing for Client Side Resource Manipulation', {
        Language.English: 'Testing for Client Side Resource Manipulation',
        Language.Spanish: ''
    }
    OTG_CLIENT_007 = 83, 'OTG-CLIENT-007', 'Test Cross Origin Resource Sharing', {
        Language.English: 'Test Cross Origin Resource Sharing',
        Language.Spanish: ''
    }
    OTG_CLIENT_008 = 84, 'OTG-CLIENT-008', 'Testing for Cross Site Flashing', {
        Language.English: 'Testing for Cross Site Flashing',
        Language.Spanish: ''
    }
    OTG_CLIENT_009 = 85, 'OTG-CLIENT-009', 'Testing for Clickjacking', {
        Language.English: 'Testing for Clickjacking',
        Language.Spanish: ''
    }
    OTG_CLIENT_010 = 86, 'OTG-CLIENT-010', 'Testing WebSockets', {
        Language.English: 'Testing WebSockets',
        Language.Spanish: ''
    }
    OTG_CLIENT_011 = 87, 'OTG-CLIENT-011', 'Test Web Messaging', {
        Language.English: 'Test Web Messaging',
        Language.Spanish: ''
    }
    OTG_CLIENT_012 = 88, 'OTG-CLIENT-012', 'Test Local Storage', {
        Language.English: 'Test Local Storage',
        Language.Spanish: ''
    }


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
