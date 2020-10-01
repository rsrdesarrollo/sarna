from sarna.model.enums.base_choice import BaseChoice
from sarna.model.enums.language import Language

class OWISAMCategory(BaseChoice):
    _init_ = "value code desc translation"
    DI_001 = 1, 'DI-001', 'Discovering of access points', {
        Language.English: 'Discovering of access points',
        Language.Spanish: 'Descubrimiento de dispositivos WiFi no autorizados'
    }
    DI_002 = 2, 'DI-002', 'Hidden networks discovering', {
        Language.English: 'Hidden networks discovering',
        Language.Spanish: 'Descubrimiento de redes ocultas'
    }
    DI_003 = 3, 'DI-003', 'Passive MAC address identification', {
        Language.English: 'Passive MAC address identification',
        Language.Spanish: 'Identificación pasiva de direcciones MAC de dispositivos'
    }
    DI_004 = 4, 'DI-004', 'Discovering of clients\' Preferred Network Lists (PNL)', {
        Language.English: 'Discovering of clients\' Preferred Network Lists (PNL)',
        Language.Spanish: 'Descubrimiento de preferencias de redes conocidas de clientes'
    }
    DI_005 = 5, 'DI-005', 'Active device and network discovering', {
        Language.English: 'Active device and network discovering',
        Language.Spanish: 'Descubrimiento activo de dispositivos'
    }
    DI_006 = 6, 'DI-006', 'Identification of relationships between devices', {
        Language.English: 'Identification of relationships between devices',
        Language.Spanish: 'Identificación de relaciones entre dispositivos'
    }
    FP_001 = 7, 'FP-001', 'Devices identification', {
        Language.English: 'Devices identification',
        Language.Spanish: 'Identificación del dispositivos'
    }
    FP_002 = 8, 'FP-002', 'Identification of device supported functionalities', {
        Language.English: 'Identification of device supported functionalities',
        Language.Spanish: 'Identificación de funcionalidades soportadas por el dispositivo'
    }
    FP_003 = 9, 'FP-003', 'Enumeration of RADIUS authentication mechanisms (802.1x)', {
        Language.English: 'Enumeration of RADIUS authentication mechanisms (802.1x)',
        Language.Spanish: 'Enumeración de mecanismos de autenticación RADIUS (802.1x)'
    }
    FP_004 = 10, 'FP-004', 'Detection of rogue APs', {
        Language.English: 'Detection of rogue APs',
        Language.Spanish: 'Detección de rogue APs'
    }
    FP_005 = 11, 'FP-005', 'Client isolation tests', {
        Language.English: 'Client isolation tests',
        Language.Spanish: 'Pruebas de client isolation'
    }
    FP_006 = 12, 'FP-006', 'Detection of attacks by WiFi devices', {
        Language.English: 'Detection of attacks by WiFi devices',
        Language.Spanish: 'Detección de ataques por parte de dispositivos WiFi'
    }
    AU_001 = 13, 'AU-001', 'MAC-based access protection detection', {
        Language.English: 'MAC-based access protection detection',
        Language.Spanish: 'Detección de protección de acceso basada en MAC'
    }
    AU_002 = 14, 'AU-002', 'Tests on WPS', {
        Language.English: 'Tests on WPS',
        Language.Spanish: 'Pruebas sobre WPS'
    }
    AU_003 = 15, 'AU-003', 'Authentication method downgrading tests', {
        Language.English: 'Authentication method downgrading tests',
        Language.Spanish: 'Pruebas de downgrading del método de autenticación'
    }
    AU_004 = 16, 'AU-004', 'Capturing and cracking transmitted keys in the authentication process', {
        Language.English: 'Capturing and cracking transmitted keys in the authentication process',
        Language.Spanish: 'Captura y cracking de claves transmitidas en el proceso de autenticación'
    }
    AU_005 = 17, 'AU-005', 'Use of insecure authentication protocols (FAST-EAP, LEAP, EAP-MD5...)', {
        Language.English: 'Use of insecure authentication protocols (FAST-EAP, LEAP, EAP-MD5...)',
        Language.Spanish: 'Uso de protocolos de autenticación inseguros (FAST-EAP, LEAP, EAP-MD5...)'
    }
    AU_006 = 18, 'AU-006', 'Brute force testing of RADIUS users and passwords (802.1x)', {
        Language.English: 'Brute force testing of RADIUS users and passwords (802.1x)',
        Language.Spanish: 'Pruebas de fuerza bruta contra usuarios y contraseñas de RADIUS (802.1x)'
    }
    AU_007 = 19, 'AU-007', 'Brute force testing of passwords against the authentication process (PSK)', {
        Language.English: 'Brute force testing of passwords against the authentication process (PSK)',
        Language.Spanish: 'Pruebas de fuerza bruta de contraseñas contra el proceso de autenticación (PSK)'
    }
    AU_008 = 20, 'AU-008', 'Weaknesses in credential repository', {
        Language.English: 'Weaknesses in credential repository',
        Language.Spanish: 'Debilidades en repositorio de credenciales'
    }
    CP_001 = 21, 'CP-001', 'Open network traffic capturing and analysis', {
        Language.English: 'Open network traffic capturing and analysis',
        Language.Spanish: 'Captura y análisis de tráfico en red abierta'
    }
    CP_002 = 22, 'CP-002', 'Decryption of encrypted traffic', {
        Language.English: 'Decryption of encrypted traffic',
        Language.Spanish: 'Descifrado de tráfico cifrado'
    }
    CP_003 = 23, 'CP-003', 'Analysis of information transmitted through Wireless', {
        Language.English: 'Analysis of information transmitted through Wireless',
        Language.Spanish: 'Pruebas de análisis de información transmitida a través de Wireless'
    }
    CP_004 = 24, 'CP-004', 'Analysis of insecure encryption protocols (WEP, TKIP...)', {
        Language.English: 'Analysis of insecure encryption protocols (WEP, TKIP...)',
        Language.Spanish: 'Análisis de protocolos de cifrado inseguros (WEP, TKIP...)'
    }
    CP_005 = 25, 'CP-005', 'Tests for encryption keys renewal', {
        Language.English: 'Tests for encryption keys renewal',
        Language.Spanish: 'Pruebas de renovación de claves de cifrado'
    }
    CP_006 = 26, 'CP-006', 'Traffic replay tests (replay attack, Mic...)', {
        Language.English: 'Traffic replay tests (replay attack, Mic...)',
        Language.Spanish: 'Pruebas de re-inyección de tráfico'
    }
    CF_001 = 27, 'CF-001', 'Identification of wireless networks with generic ESSID', {
        Language.English: 'Identification of wireless networks with generic ESSID',
        Language.Spanish: 'Identificación de redes wireless con ESSID genérico'
    }
    CF_002 = 28, 'CF-002', 'Generic passwords in the access point administrative interface', {
        Language.English: 'Generic passwords in the access point administrative interface',
        Language.Spanish: 'Contraseñas genéricas en interfaz administrativa del punto de acceso'
    }
    CF_003 = 29, 'CF-003', 'Verification of signal strength level or coverage area', {
        Language.English: 'Verification of signal strength level or coverage area',
        Language.Spanish: 'Verificación del nivel de intensidad de señal o área de cobertura'
    }
    CF_004 = 30, 'CF-004', 'Analysis of network overlapping in the same communications channel', {
        Language.English: 'Analysis of network overlapping in the same communications channel',
        Language.Spanish: 'Análisis del solapamiento de redes en el mismo canal de comunicaciones'
    }
    CF_005 = 31, 'CF-005', 'Generation of keys based on known algorithms', {
        Language.English: 'Generation of keys based on known algorithms',
        Language.Spanish: 'Generación de claves en base a algoritmos conocidos'
    }
    CF_006 = 32, 'CF-006', 'Tests for UPnP', {
        Language.English: 'Tests for UPnP',
        Language.Spanish: 'Pruebas sobre UPnP'
    }
    IF_001 = 33, 'IF-001', 'Weaknesses in the AP firmware', {
        Language.English: 'Weaknesses in the AP firmware',
        Language.Spanish: 'Debilidades en el firmware del AP'
    }
    IF_002 = 34, 'IF-002', 'Administrative interfaces exposed', {
        Language.English: 'Administrative interfaces exposed',
        Language.Spanish: 'Interfaces administrativas expuestas a la red'
    }
    IF_003 = 35, 'IF-003', 'Incorrect firewall policy', {
        Language.English: 'Incorrect firewall policy',
        Language.Spanish: 'Política de firewall incorrecta'
    }
    IF_004 = 36, 'IF-004', 'Controls on intrusion detection mechanisms', {
        Language.English: 'Controls on intrusion detection mechanisms',
        Language.Spanish: 'Controles sobre mecanismos de detección de intrusos'
    }
    IF_005 = 37, 'IF-005', 'Verification tests for VPN tunnels', {
        Language.English: 'Verification tests for VPN tunnels',
        Language.Spanish: 'Pruebas de verificación de túneles VPN (sobre redes abiertas...)'
    }
    IF_006 = 38, 'IF-006', 'Weaknesses in RADIUS server', {
        Language.English: 'Weaknesses in RADIUS server',
        Language.Spanish: 'Debilidades en servidor RADIUS'
    }
    IF_007 = 39, 'IF-007', 'Incubated vulnerabilities', {
        Language.English: 'Incubated vulnerabilities',
        Language.Spanish: 'Vulnerabilidades incubadas'
    }
    IF_008 = 40, 'IF-008', 'Keys and certificates life cycle management', {
        Language.English: 'Keys and certificates life cycle management',
        Language.Spanish: 'Gestión del ciclo de vida de claves y certificados'
    }
    IF_009 = 41, 'IF-009', 'Accessible/physically exposed communication devices', {
        Language.English: 'Accessible/physically exposed communication devices',
        Language.Spanish: 'Dispositivos de comunicaciones accesible/expuestos físicamente'
    }
    IF_010 = 42, 'IF-010', 'Detection and analysis of SCADA systems', {
        Language.English: 'Detection and analysis of SCADA systems',
        Language.Spanish: 'Detección y análisis de sistemas SCADA'
    }
    DS_001 = 43, 'DS-001', 'Deauthentication tests', {
        Language.English: 'Deauthentication tests',
        Language.Spanish: 'Pruebas de desautenticación'
    }
    DS_002 = 44, 'DS-002', 'Saturation of the communications channel (CTS/RTS, noise, jammering...)', {
        Language.English: 'Saturation of the communications channel (CTS/RTS, noise, jammering...)',
        Language.Spanish: 'Saturación del canal de comunicaciones (CTS/RTS, noise, jammering...)'
    }
    DS_003 = 45, 'DS-003', 'User accounts blocking', {
        Language.English: 'User accounts blocking',
        Language.Spanish: 'Bloqueo de cuentas de usuario'
    }
    DS_004 = 46, 'DS-004', 'Communication device blocking', {
        Language.English: 'Communication device blocking',
        Language.Spanish: 'Bloqueo de dispositivo de comunicaciones'
    }
    DS_005 = 47, 'DS-005', 'Communications channel degradation tests', {
        Language.English: 'Communications channel degradation tests',
        Language.Spanish: 'Pruebas de degradación del canal de comunicaciones'
    }
    GD_001 = 48, 'GD-001', 'Identification of devices that do not meet the standard/proprietary', {
        Language.English: 'Identification of devices that do not meet the standard/proprietary',
        Language.Spanish: 'Identificación de dispositivos que no cumplen el estándar/propietarios'
    }
    GD_002 = 49, 'GD-002', 'Detection of devices emitting at restricted frequencies', {
        Language.English: 'Detection of devices emitting at restricted frequencies',
        Language.Spanish: 'Detección de dispositivos emitiendo en frecuencias restringidas'
    }
    GD_003 = 50, 'GD-003', 'Analysis of the policy of use/restriction of uses of wireless networks', {
        Language.English: 'Analysis of the policy of use/restriction of use of wireless networks',
        Language.Spanish: 'Análisis de la política de uso/restricción de uso de redes inalámbricas'
    }
    GD_004 = 51, 'GD-004', 'Analysis of devices configuration', {
        Language.English: 'Analysis of devices configuration',
        Language.Spanish: 'Análisis de la configuración de dispositivos'
    }
    GD_005 = 52, 'GD-005', 'Analysis of the key management and change policy', {
        Language.English: 'Analysis of the key management and change policy',
        Language.Spanish: 'Análisis de la política de gestión y cambio de claves'
    }
    GD_006 = 53, 'GD-006', 'Verification of authorized devices inventory', {
        Language.English: 'Verification of authorized devices inventory',
        Language.Spanish: 'Verificación de inventario de dispositivos autorizados'
    }
    CT_001 = 54, 'CT-001', 'Rogue AP and automatic association tests', {
        Language.English: 'Rogue AP and automatic association tests',
        Language.Spanish: 'Pruebas de Rogue AP y asociación automática'
    }
    CT_002 = 55, 'CT-002', 'Analysis of APTs (Advanced Persistent Threats) on Wireless', {
        Language.English: 'Analysis of APTs (Advanced Persistent Threats) on Wireless',
        Language.Spanish: 'Analisis de APTs (Advanced Persistent Threats) sobre Wireless'
    }
    CT_003 = 56, 'CT-003', 'Client buffer overflow', {
        Language.English: 'Client buffer overflow',
        Language.Spanish: 'Desbordamiento de búfer en cliente'
    }
    CT_004 = 57, 'CT-004', 'Extraction of user identifiers (802.1x)', {
        Language.English: 'Extraction of user identifiers (802.1x)',
        Language.Spanish: 'Extracción de identificadores de usuarios (802.1x)'
    }
    CT_005 = 58, 'CT-005', 'Tests for weak or insecure supplicant', {
        Language.English: 'Tests for weak or insecure supplicant',
        Language.Spanish: 'Pruebas sobre supplicant débil o inseguro'
    }
    CT_006 = 59, 'CT-006', 'Attacks against clients', {
        Language.English: 'Attacks against clients',
        Language.Spanish: 'Ataques contra clientes'
    }
    CT_007 = 60, 'CT-007', 'Extraction of customer credentials', {
        Language.English: 'Extraction of customer credentials',
        Language.Spanish: 'Extracción de credenciales de los clientes'
    }
    HS_001 = 61, 'HS-001', 'Access to other network segments without authentication', {
        Language.English: 'Access to other network segments without authentication',
        Language.Spanish: 'Acceso a otros segmentos de red sin autenticación'
    }
    HS_002 = 62, 'HS-002', 'Weaknesses in the authentication mechanism', {
        Language.English: 'Weaknesses in the authentication mechanism',
        Language.Spanish: 'Debilidades en el mecanismo de autenticación'
    }
    HS_003 = 63, 'HS-003', 'Tests for external traffic encapsulation', {
        Language.English: 'Tests for external traffic encapsulation',
        Language.Spanish: 'Pruebas de encapsulación de tráfico con el exterior'
    }
    HS_004 = 64, 'HS-004', 'Weaknesses in captive portal', {
        Language.English: 'Weaknesses in captive portal',
        Language.Spanish: 'Debilidades en portal cautivo'
    }

class WSTG(BaseChoice):
    _init_ = "value code desc"
    WSTG_INFO_01 = 1, 'WSTG-INFO-01', 'Conduct Search Engine Discovery Reconnaissance for Information Leakage'
    WSTG_INFO_02 = 2, 'WSTG-INFO-02', 'Fingerprint Web Server'
    WSTG_INFO_03 = 3, 'WSTG-INFO-03', 'Review Webserver Metafiles for Information Leakage'
    WSTG_INFO_04 = 4, 'WSTG-INFO-04', 'Enumerate Applications on Webserver'
    WSTG_INFO_05 = 5, 'WSTG-INFO-05', 'Review Webpage Comments and Metadata for Information Leakage'
    WSTG_INFO_06 = 6, 'WSTG-INFO-06', 'Identify application entry points'
    WSTG_INFO_07 = 7, 'WSTG-INFO-07', 'Map execution paths through application'
    WSTG_INFO_08 = 8, 'WSTG-INFO-08', 'Fingerprint Web Application Framework'
    WSTG_INFO_09 = 9, 'WSTG-INFO-09', 'Fingerprint Web Application'
    WSTG_INFO_10 = 10, 'WSTG-INFO-10', 'Map Application Architecture'
    WSTG_CONF_01 = 11, 'WSTG-CONF-01', 'Test Network/Infrastructure Configuration'
    WSTG_CONF_02 = 12, 'WSTG-CONF-02', 'Test Application Platform Configuration'
    WSTG_CONF_03 = 13, 'WSTG-CONF-03', 'Test File Extensions Handling for Sensitive Information'
    WSTG_CONF_04 = 14, 'WSTG-CONF-04', 'Backup and Unreferenced Files for Sensitive Information'
    WSTG_CONF_05 = 15, 'WSTG-CONF-05', 'Enumerate Infrastructure and Application Admin Interfaces'
    WSTG_CONF_06 = 16, 'WSTG-CONF-06', 'Test HTTP Methods'
    WSTG_CONF_07 = 17, 'WSTG-CONF-07', 'Test HTTP Strict Transport Security'
    WSTG_CONF_08 = 18, 'WSTG-CONF-08', 'Test RIA cross domain policy'
    WSTG_CONF_09 = 19, 'WSTG-CONF-09', 'Test File Permission'
    WSTG_CONF_10 = 20, 'WSTG-CONF-10', 'Test for Subdomain Takeover'
    WSTG_CONF_11 = 21, 'WSTG-CONF-11', 'Test Cloud Storage'
    WSTG_IDNT_01 = 21, 'WSTG-IDNT-01', 'Test Role Definitions'
    WSTG_IDNT_02 = 22, 'WSTG-IDNT-02', 'Test User Registration Process'
    WSTG_IDNT_03 = 23, 'WSTG-IDNT-03', 'Test Account Provisioning Process'
    WSTG_IDNT_04 = 24, 'WSTG-IDNT-04', 'Testing for Account Enumeration and Guessable User Account'
    WSTG_IDNT_05 = 25, 'WSTG-IDNT-05', 'Testing for Weak or unenforced username policy'
    WSTG_ATHN_01 = 26, 'WSTG-ATHN-01', 'Testing for Credentials Transported over an Encrypted Channel'
    WSTG_ATHN_02 = 27, 'WSTG-ATHN-02', 'Testing for default credentials'
    WSTG_ATHN_03 = 28, 'WSTG-ATHN-03', 'Testing for Weak lock out mechanism'
    WSTG_ATHN_04 = 29, 'WSTG-ATHN-04', 'Testing for bypassing authentication schema'
    WSTG_ATHN_05 = 30, 'WSTG-ATHN-05', 'Test remember password functionality'
    WSTG_ATHN_06 = 31, 'WSTG-ATHN-06', 'Testing for Browser cache weakness'
    WSTG_ATHN_07 = 32, 'WSTG-ATHN-07', 'Testing for Weak password policy'
    WSTG_ATHN_08 = 33, 'WSTG-ATHN-08', 'Testing for Weak security question/answer'
    WSTG_ATHN_09 = 34, 'WSTG-ATHN-09', 'Testing for weak password change or reset functionalities'
    WSTG_ATHN_10 = 35, 'WSTG-ATHN-10', 'Testing for Weaker authentication in alternative channel'
    WSTG_ATHZ_01 = 36, 'WSTG-ATHZ-01', 'Testing Directory Traversal - File Include'
    WSTG_ATHZ_02 = 37, 'WSTG-ATHZ-02', 'Testing for bypassing authorization schema'
    WSTG_ATHZ_03 = 38, 'WSTG-ATHZ-03', 'Testing for Privilege Escalation'
    WSTG_ATHZ_04 = 39, 'WSTG-ATHZ-04', 'Testing for Insecure Direct Object References'
    WSTG_SESS_01 = 40, 'WSTG-SESS-01', 'Testing for Bypassing Session Management Schema'
    WSTG_SESS_02 = 41, 'WSTG-SESS-02', 'Testing for Cookies attributes'
    WSTG_SESS_03 = 42, 'WSTG-SESS-03', 'Testing for Session Fixation'
    WSTG_SESS_04 = 43, 'WSTG-SESS-04', 'Testing for Exposed Session Variables'
    WSTG_SESS_05 = 44, 'WSTG-SESS-05', 'Testing for Cross Site Request Forgery'
    WSTG_SESS_06 = 45, 'WSTG-SESS-06', 'Testing for logout functionality'
    WSTG_SESS_07 = 46, 'WSTG-SESS-07', 'Test Session Timeout'
    WSTG_SESS_08 = 47, 'WSTG-SESS-08', 'Testing for Session puzzling'
    WSTG_INPV_01 = 48, 'WSTG-INPV-01', 'Testing for Reflected Cross Site Scripting'
    WSTG_INPV_02 = 49, 'WSTG-INPV-02', 'Testing for Stored Cross Site Scripting'
    WSTG_INPV_03 = 50, 'WSTG-INPV-03', 'Testing for HTTP Verb Tampering'
    WSTG_INPV_04 = 51, 'WSTG-INPV-04', 'Testing for HTTP Parameter pollution'
    WSTG_INPV_05 = 52, 'WSTG-INPV-05', 'Testing for SQL Injection'
    WSTG_INPV_06 = 53, 'WSTG-INPV-05', 'Oracle Testing'
    WSTG_INPV_07 = 54, 'WSTG-INPV-05', 'MySQL Testing'
    WSTG_INPV_08 = 55, 'WSTG-INPV-05', 'SQL Server Testing'
    WSTG_INPV_09 = 56, 'WSTG-INPV-05', 'Testing PostgreSQL'
    WSTG_INPV_10 = 57, 'WSTG-INPV-05', 'MS Access Testing'
    WSTG_INPV_11 = 58, 'WSTG-INPV-05', 'Testing for NoSQL injection'
    WSTG_INPV_12 = 59, 'WSTG-INPV-05', 'Testing for ORM Injection'
    WSTG_INPV_13 = 60, 'WSTG-INPV-06', 'Testing for LDAP Injection'
    WSTG_INPV_14 = 61, 'WSTG-INPV-07', 'Testing for XML Injection'
    WSTG_INPV_15 = 62, 'WSTG-INPV-08', 'Testing for SSI Injection'
    WSTG_INPV_16 = 63, 'WSTG-INPV-09', 'Testing for XPath Injection'
    WSTG_INPV_17 = 64, 'WSTG-INPV-10', 'IMAP/SMTP Injection'
    WSTG_INPV_18 = 65, 'WSTG-INPV-11', 'Testing for Code Injection'
    WSTG_INPV_19 = 66, 'WSTG-INPV-11', 'Testing for Local File Inclusion'
    WSTG_INPV_20 = 67, 'WSTG-INPV-11', 'Testing for Remote File Inclusion'
    WSTG_INPV_21 = 68, 'WSTG-INPV-12', 'Testing for Command Injection'
    WSTG_INPV_22 = 69, 'WSTG-INPV-13', 'Testing for Buffer overflow'
    WSTG_INPV_23 = 70, 'WSTG-INPV-13', 'Testing for Heap overflow'
    WSTG_INPV_24 = 71, 'WSTG-INPV-13', 'Testing for Stack overflow'
    WSTG_INPV_25 = 72, 'WSTG-INPV-13', 'Testing for Format string'
    WSTG_INPV_26 = 73, 'WSTG-INPV-14', 'Testing for incubated vulnerabilities'
    WSTG_INPV_27 = 74, 'WSTG-INPV-15', 'Testing for HTTP Splitting/Smuggling'
    WSTG_INPV_28 = 75, 'WSTG-INPV-16', 'Testing for HTTP Incoming Requests'
    WSTG_INPV_29 = 76, 'WSTG-INPV-17', 'Testing for Host Header Injection'
    WSTG_INPV_30 = 77, 'WSTG-INPV-18', 'Testing for Server-side Template Injection'
    WSTG_ERRH_01 = 78, 'WSTG-ERRH-01', 'Analysis of Error Codes'
    WSTG_ERRH_02 = 79, 'WSTG-ERRH-02', 'Analysis of Stack Traces'
    WSTG_CRYP_01 = 80, 'WSTG-CRYP-01', 'Testing for Weak SSL/TSL Ciphers  Insufficient Transport Layer Protection'
    WSTG_CRYP_02 = 81, 'WSTG-CRYP-02', 'Testing for Padding Oracle'
    WSTG_CRYP_03 = 82, 'WSTG-CRYP-03', 'Testing for Sensitive information sent via unencrypted channels'
    WSTG_CRYP_04 = 83, 'WSTG-CRYP-04', 'Testing for Weak Encryption'
    WSTG_BUSL_01 = 84, 'WSTG-BUSL-01', 'Test Business Logic Data Validation'
    WSTG_BUSL_02 = 85, 'WSTG-BUSL-02', 'Test Ability to Forge Requests'
    WSTG_BUSL_03 = 86, 'WSTG-BUSL-03', 'Test Integrity Checks'
    WSTG_BUSL_04 = 87, 'WSTG-BUSL-04', 'Test for Process Timing'
    WSTG_BUSL_05 = 89, 'WSTG-BUSL-05', 'Test Number of Times a Function Can be Used Limits'
    WSTG_BUSL_06 = 90, 'WSTG-BUSL-06', 'Testing for the Circumvention of Work Flows'
    WSTG_BUSL_07 = 91, 'WSTG-BUSL-07', 'Test Defenses Against Application Mis-use'
    WSTG_BUSL_08 = 92, 'WSTG-BUSL-08', 'Test Upload of Unexpected File Types'
    WSTG_BUSL_09 = 93, 'WSTG-BUSL-09', 'Test Upload of Malicious Files'
    WSTG_CLNT_01 = 94, 'WSTG-CLNT-01', 'Testing for DOM based Cross Site Scripting'
    WSTG_CLNT_02 = 95, 'WSTG-CLNT-02', 'Testing for JavaScript Execution'
    WSTG_CLNT_03 = 96, 'WSTG-CLNT-03', 'Testing for HTML Injection'
    WSTG_CLNT_04 = 97, 'WSTG-CLNT-04', 'Testing for Client Side URL Redirect'
    WSTG_CLNT_05 = 98, 'WSTG-CLNT-05', 'Testing for CSS Injection'
    WSTG_CLNT_06 = 99, 'WSTG-CLNT-06', 'Testing for Client Side Resource Manipulation'
    WSTG_CLNT_07 = 100, 'WSTG-CLNT-07', 'Test Cross Origin Resource Sharing'
    WSTG_CLNT_08 = 101, 'WSTG-CLNT-08', 'Testing for Cross Site Flashing'
    WSTG_CLNT_09 = 102, 'WSTG-CLNT-09', 'Testing for Clickjacking'
    WSTG_CLNT_10 = 103, 'WSTG-CLNT-10', 'Testing WebSockets'
    WSTG_CLNT_11 = 104, 'WSTG-CLNT-11', 'Test Web Messaging'
    WSTG_CLNT_12 = 105, 'WSTG-CLNT-12', 'Test Local Storage'
    WSTG_CLNT_13 = 106, 'WSTG-CLNT-13', 'Testing for Cross Site Script Inclusion'

class MSTG(BaseChoice):
    _init_ = "value code desc"
    MSTG_ARCH_1 = 0, 'MSTG-ARCH-1', 'All app components are identified and known to be needed.'
    MSTG_ARCH_2 = 1, 'MSTG-ARCH-2', 'Security controls are never enforced only on the client side, but on the respective remote endpoints.'
    MSTG_ARCH_3 = 2, 'MSTG-ARCH-3', 'A high-level architecture for the mobile app and all connected remote services has been defined and security has been addressed in that architecture.'
    MSTG_ARCH_4 = 3, 'MSTG-ARCH-4', 'Data considered sensitive in the context of the mobile app is clearly identified.'
    MSTG_ARCH_5 = 4, 'MSTG-ARCH-5', 'All app components are defined in terms of the business functions and/or security functions they provide.'
    MSTG_ARCH_6 = 5, 'MSTG-ARCH-6', 'A threat model for the mobile app and the associated remote services has been produced that identifies potential threats and countermeasures.'
    MSTG_ARCH_7 = 6, 'MSTG-ARCH-7', 'All security controls have a centralized implementation.'
    MSTG_ARCH_8 = 7, 'MSTG-ARCH-8', 'There is an explicit policy for how cryptographic keys (if any) are managed, and the lifecycle of cryptographic keys is enforced. Ideally, follow a key management standard such as NIST SP 800-57.'
    MSTG_ARCH_9 = 8, 'MSTG-ARCH-9', 'A mechanism for enforcing updates of the mobile app exists.'
    MSTG_ARCH_10 = 9, 'MSTG-ARCH-10', 'Security is addressed within all parts of the software development lifecycle.'
    MSTG_ARCH_11 = 10, 'MSTG-ARCH-11', 'A responsible disclosure policy is in place and effectively applied.'
    MSTG_ARCH_12 = 11, 'MSTG-ARCH-12', 'The app should comply with privacy laws and regulations.'
    MSTG_STORAGE_1 = 12, 'MSTG-STORAGE-1', 'System credential storage facilities need to be used to store sensitive data, such as PII, user credentials or cryptographic keys.'
    MSTG_STORAGE_2 = 13, 'MSTG-STORAGE-2', 'No sensitive data should be stored outside of the app container or system credential storage facilities.'
    MSTG_STORAGE_3 = 14, 'MSTG-STORAGE-3', 'No sensitive data is written to application logs.'
    MSTG_STORAGE_4 = 15, 'MSTG-STORAGE-4', 'No sensitive data is shared with third parties unless it is a necessary part of the architecture.'
    MSTG_STORAGE_5 = 16, 'MSTG-STORAGE-5', 'The keyboard cache is disabled on text inputs that process sensitive data.'
    MSTG_STORAGE_6 = 17, 'MSTG-STORAGE-6', 'No sensitive data is exposed via IPC mechanisms.'
    MSTG_STORAGE_7 = 19, 'MSTG-STORAGE-7', 'No sensitive data, such as passwords or pins, is exposed through the user interface.'
    MSTG_STORAGE_8 = 20, 'MSTG-STORAGE-8', 'No sensitive data is included in backups generated by the mobile operating system.'
    MSTG_STORAGE_9 = 21, 'MSTG-STORAGE-9', 'The app removes sensitive data from views when moved to the background.'
    MSTG_STORAGE_10 = 22, 'MSTG-STORAGE-10', 'The app does not hold sensitive data in memory longer than necessary, and memory is cleared explicitly after use.'
    MSTG_STORAGE_11 = 23, 'MSTG-STORAGE-11', 'The app enforces a minimum device-access-security policy, such as requiring the user to set a device passcode.'
    MSTG_STORAGE_12 = 24, 'MSTG-STORAGE-12', 'The app educates the user about the types of personally identifiable information processed, as well as security best practices the user should follow in using the app.'
    MSTG_STORAGE_13 = 25, 'MSTG-STORAGE-13', 'No sensitive data should be stored locally on the mobile device. Instead, data should be retrieved from a remote endpoint when needed and only be kept in memory.'
    MSTG_STORAGE_14 = 26, 'MSTG-STORAGE-14', 'If sensitive data is still required to be stored locally, it should be encrypted using a key derived from hardware backed storage which requires authentication.'
    MSTG_STORAGE_15 = 27, 'MSTG-STORAGE-15', 'The app’s local storage should be wiped after an excessive number of failed authentication attempts.'
    MSTG_CRYPTO_1 = 28, 'MSTG-CRYPTO-1', 'The app does not rely on symmetric cryptography with hardcoded keys as a sole method of encryption.'
    MSTG_CRYPTO_2 = 29, 'MSTG-CRYPTO-2', 'The app uses proven implementations of cryptographic primitives.'
    MSTG_CRYPTO_3 = 30, 'MSTG-CRYPTO-3', 'The app uses cryptographic primitives that are appropriate for the particular use-case, configured with parameters that adhere to industry best practices.'
    MSTG_CRYPTO_4 = 31, 'MSTG-CRYPTO-4', 'The app does not use cryptographic protocols or algorithms that are widely considered deprecated for security purposes.'
    MSTG_CRYPTO_5 = 32, 'MSTG-CRYPTO-5', 'The app doesn\'t re-use the same cryptographic key for multiple purposes.'
    MSTG_CRYPTO_6 = 33, 'MSTG-CRYPTO-6', 'All random values are generated using a sufficiently secure random number generator.'
    MSTG_AUTH_1 = 34, 'MSTG-AUTH-1', 'If the app provides users access to a remote service, some form of authentication, such as username/password authentication, is performed at the remote endpoint.'
    MSTG_AUTH_2 = 35, 'MSTG-AUTH-2', 'If stateful session management is used, the remote endpoint uses randomly generated session identifiers to authenticate client requests without sending the user\'s credentials.'
    MSTG_AUTH_3 = 36, 'MSTG-AUTH-3', 'If stateless token-based authentication is used, the server provides a token that has been signed using a secure algorithm.'
    MSTG_AUTH_4 = 37, 'MSTG-AUTH-4', 'The remote endpoint terminates the existing session when the user logs out.'
    MSTG_AUTH_5 = 38, 'MSTG-AUTH-5', 'A password policy exists and is enforced at the remote endpoint.'
    MSTG_AUTH_6 = 39, 'MSTG-AUTH-6', 'The remote endpoint implements a mechanism to protect against the submission of credentials an excessive number of times.'
    MSTG_AUTH_7 = 40, 'MSTG-AUTH-7', 'Sessions are invalidated at the remote endpoint after a predefined period of inactivity and access tokens expire.'
    MSTG_AUTH_8 = 41, 'MSTG-AUTH-8', 'Biometric authentication, if any, is not event-bound (i.e. using an API that simply returns "true" or "false"). Instead, it is based on unlocking the keychain/keystore.'
    MSTG_AUTH_9 = 42, 'MSTG-AUTH-9', 'A second factor of authentication exists at the remote endpoint and the 2FA requirement is consistently enforced.'
    MSTG_AUTH_10 = 43, 'MSTG-AUTH-10', 'Sensitive transactions require step-up authentication.'
    MSTG_AUTH_11 = 44, 'MSTG-AUTH-11', 'The app informs the user of all sensitive activities with their account. Users are able to view a list of devices, view contextual information (IP address, location, etc.), and to block specific devices.'
    MSTG_AUTH_12 = 45, 'MSTG-AUTH-12', 'Authorization models should be defined and enforced at the remote endpoint.'
    MSTG_NETWORK_1 = 46, 'MSTG-NETWORK-1', 'Data is encrypted on the network using TLS. The secure channel is used consistently throughout the app.'
    MSTG_NETWORK_2 = 47, 'MSTG-NETWORK-2', 'The TLS settings are in line with current best practices, or as close as possible if the mobile operating system does not support the recommended standards.'
    MSTG_NETWORK_3 = 48, 'MSTG-NETWORK-3', 'The app verifies the X.509 certificate of the remote endpoint when the secure channel is established. Only certificates signed by a trusted CA are accepted.'
    MSTG_NETWORK_4 = 49, 'MSTG-NETWORK-4', 'The app either uses its own certificate store, or pins the endpoint certificate or public key, and subsequently does not establish connections with endpoints that offer a different certificate or key, even if signed by a trusted CA.'
    MSTG_NETWORK_5 = 50, 'MSTG-NETWORK-5', 'The app doesn\'t rely on a single insecure communication channel (email or SMS) for critical operations, such as enrollments and account recovery.'
    MSTG_NETWORK_6 = 51, 'MSTG-NETWORK-6', 'The app only depends on up-to-date connectivity and security libraries.'
    MSTG_PLATFORM_1 = 52, 'MSTG-PLATFORM-1', 'The app only requests the minimum set of permissions necessary.'
    MSTG_PLATFORM_2 = 53, 'MSTG-PLATFORM-2', 'All inputs from external sources and the user are validated and if necessary sanitized. This includes data received via the UI, IPC mechanisms such as intents, custom URLs, and network sources.'
    MSTG_PLATFORM_3 = 54, 'MSTG-PLATFORM-3', 'The app does not export sensitive functionality via custom URL schemes, unless these mechanisms are properly protected.'
    MSTG_PLATFORM_4 = 55, 'MSTG-PLATFORM-4', 'The app does not export sensitive functionality through IPC facilities, unless these mechanisms are properly protected.'
    MSTG_PLATFORM_5 = 56, 'MSTG-PLATFORM-5', 'JavaScript is disabled in WebViews unless explicitly required.'
    MSTG_PLATFORM_6 = 57, 'MSTG-PLATFORM-6', 'WebViews are configured to allow only the minimum set of protocol handlers required (ideally, only https is supported). Potentially dangerous handlers, such as file, tel and app-id, are disabled.'
    MSTG_PLATFORM_7 = 58, 'MSTG-PLATFORM-7', 'If native methods of the app are exposed to a WebView, verify that the WebView only renders JavaScript contained within the app package.'
    MSTG_PLATFORM_8 = 59, 'MSTG-PLATFORM-8', 'Object deserialization, if any, is implemented using safe serialization APIs.'
    MSTG_PLATFORM_9 = 60, 'MSTG-PLATFORM-9', 'The app protects itself against screen overlay attacks. (Android only)'
    MSTG_PLATFORM_10 = 61, 'MSTG-PLATFORM-10', 'A WebView\'s cache, storage, and loaded resources (JavaScript, etc.) should be cleared before the WebView is destroyed.'
    MSTG_PLATFORM_11 = 62, 'MSTG-PLATFORM-11', 'Verify that the app prevents usage of custom third-party keyboards whenever sensitive data is entered.'
    MSTG_CODE_1 = 63, 'MSTG-CODE-1', 'The app is signed and provisioned with a valid certificate, of which the private key is properly protected.'
    MSTG_CODE_2 = 64, 'MSTG-CODE-2', 'The app has been built in release mode, with settings appropriate for a release build (e.g. non-debuggable).'
    MSTG_CODE_3 = 65, 'MSTG-CODE-3', 'Debugging symbols have been removed from native binaries.'
    MSTG_CODE_4 = 66, 'MSTG-CODE-4', 'Debugging code and developer assistance code (e.g. test code, backdoors, hidden settings) have been removed. The app does not log verbose errors or debugging messages.'
    MSTG_CODE_5 = 67, 'MSTG-CODE-5', 'All third party components used by the mobile app, such as libraries and frameworks, are identified, and checked for known vulnerabilities.'
    MSTG_CODE_6 = 68, 'MSTG-CODE-6', 'The app catches and handles possible exceptions.'
    MSTG_CODE_7 = 69, 'MSTG-CODE-7', 'Error handling logic in security controls denies access by default.'
    MSTG_CODE_8 = 70, 'MSTG-CODE-8', 'In unmanaged code, memory is allocated, freed and used securely.'
    MSTG_CODE_9 = 71, 'MSTG-CODE-9', 'Free security features offered by the toolchain, such as byte-code minification, stack protection, PIE support and automatic reference counting, are activated.'
    
