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
    
class CWE(BaseChoice):
    CWE_15 = 15, 'CWE-15', 'External Control of System or Configuration Setting'
    CWE_23 = 23, 'CWE-23', 'Relative Path Traversal'
    CWE_36 = 36, 'CWE-36', 'Absolute Path Traversal'
    CWE_41 = 41, 'CWE-41', 'Improper Resolution of Path Equivalence'
    CWE_59 = 59, 'CWE-59', 'Improper Link Resolution Before File Access (\'Link Following\')'
    CWE_66 = 66, 'CWE-66', 'Improper Handling of File Names that Identify Virtual Resources'
    CWE_73 = 73, 'CWE-73', 'External Control of File Name or Path'
    CWE_76 = 76, 'CWE-76', 'Improper Neutralization of Equivalent Special Elements'
    CWE_78 = 78, 'CWE-78', 'Improper Neutralization of Special Elements used in an OS Command (\'OS Command Injection\')'
    CWE_79 = 79, 'CWE-79', 'Improper Neutralization of Input During Web Page Generation (\'Cross-site Scripting\')'
    CWE_88 = 88, 'CWE-88', 'Improper Neutralization of Argument Delimiters in a Command (\'Argument Injection\')'
    CWE_89 = 89, 'CWE-89', 'Improper Neutralization of Special Elements used in an SQL Command (\'SQL Injection\')'
    CWE_90 = 90, 'CWE-90', 'Improper Neutralization of Special Elements used in an LDAP Query (\'LDAP Injection\')'
    CWE_91 = 91, 'CWE-91', 'XML Injection (aka Blind XPath Injection)'
    CWE_93 = 93, 'CWE-93', 'Improper Neutralization of CRLF Sequences (\'CRLF Injection\')'
    CWE_94 = 94, 'CWE-94', 'Improper Control of Generation of Code (\'Code Injection\')'
    CWE_96 = 96, 'CWE-96', 'Improper Neutralization of Directives in Statically Saved Code (\'Static Code Injection\')'
    CWE_112 = 112, 'CWE-112', 'Missing XML Validation'
    CWE_115 = 115, 'CWE-115', 'Misinterpretation of Input'
    CWE_117 = 117, 'CWE-117', 'Improper Output Neutralization for Logs'
    CWE_120 = 120, 'CWE-120', 'Buffer Copy without Checking Size of Input (\'Classic Buffer Overflow\')'
    CWE_123 = 123, 'CWE-123', 'Write-what-where Condition'
    CWE_124 = 124, 'CWE-124', 'Buffer Underwrite (\'Buffer Underflow\')'
    CWE_125 = 125, 'CWE-125', 'Out-of-bounds Read'
    CWE_128 = 128, 'CWE-128', 'Wrap-around Error'
    CWE_129 = 129, 'CWE-129', 'Improper Validation of Array Index'
    CWE_130 = 130, 'CWE-130', 'Improper Handling of Length Parameter Inconsistency'
    CWE_131 = 131, 'CWE-131', 'Incorrect Calculation of Buffer Size'
    CWE_134 = 134, 'CWE-134', 'Use of Externally-Controlled Format String'
    CWE_135 = 135, 'CWE-135', 'Incorrect Calculation of Multi-Byte String Length'
    CWE_140 = 140, 'CWE-140', 'Improper Neutralization of Delimiters'
    CWE_166 = 166, 'CWE-166', 'Improper Handling of Missing Special Element'
    CWE_167 = 167, 'CWE-167', 'Improper Handling of Additional Special Element'
    CWE_168 = 168, 'CWE-168', 'Improper Handling of Inconsistent Special Elements'
    CWE_170 = 170, 'CWE-170', 'Improper Null Termination'
    CWE_178 = 178, 'CWE-178', 'Improper Handling of Case Sensitivity'
    CWE_179 = 179, 'CWE-179', 'Incorrect Behavior Order: Early Validation'
    CWE_182 = 182, 'CWE-182', 'Collapse of Data into Unsafe Value'
    CWE_183 = 183, 'CWE-183', 'Permissive List of Allowed Inputs'
    CWE_184 = 184, 'CWE-184', 'Incomplete List of Disallowed Inputs'
    CWE_186 = 186, 'CWE-186', 'Overly Restrictive Regular Expression'
    CWE_188 = 188, 'CWE-188', 'Reliance on Data/Memory Layout'
    CWE_190 = 190, 'CWE-190', 'Integer Overflow or Wraparound'
    CWE_191 = 191, 'CWE-191', 'Integer Underflow (Wrap or Wraparound)'
    CWE_192 = 192, 'CWE-192', 'Integer Coercion Error'
    CWE_193 = 193, 'CWE-193', 'Off-by-one Error'
    CWE_197 = 197, 'CWE-197', 'Numeric Truncation Error'
    CWE_198 = 198, 'CWE-198', 'Use of Incorrect Byte Ordering'
    CWE_201 = 201, 'CWE-201', 'Insertion of Sensitive Information Into Sent Data'
    CWE_204 = 204, 'CWE-204', 'Observable Response Discrepancy'
    CWE_205 = 205, 'CWE-205', 'Observable Behavioral Discrepancy'
    CWE_208 = 208, 'CWE-208', 'Observable Timing Discrepancy'
    CWE_209 = 209, 'CWE-209', 'Generation of Error Message Containing Sensitive Information'
    CWE_212 = 212, 'CWE-212', 'Improper Removal of Sensitive Information Before Storage or Transfer'
    CWE_213 = 213, 'CWE-213', 'Exposure of Sensitive Information Due to Incompatible Policies'
    CWE_214 = 214, 'CWE-214', 'Invocation of Process Using Visible Sensitive Information'
    CWE_215 = 215, 'CWE-215', 'Insertion of Sensitive Information Into Debugging Code'
    CWE_222 = 222, 'CWE-222', 'Truncation of Security-relevant Information'
    CWE_223 = 223, 'CWE-223', 'Omission of Security-relevant Information'
    CWE_224 = 224, 'CWE-224', 'Obscured Security-relevant Information by Alternate Name'
    CWE_226 = 226, 'CWE-226', 'Sensitive Information in Resource Not Removed Before Reuse'
    CWE_229 = 229, 'CWE-229', 'Improper Handling of Values'
    CWE_233 = 233, 'CWE-233', 'Improper Handling of Parameters'
    CWE_237 = 237, 'CWE-237', 'Improper Handling of Structural Elements'
    CWE_241 = 241, 'CWE-241', 'Improper Handling of Unexpected Data Type'
    CWE_242 = 242, 'CWE-242', 'Use of Inherently Dangerous Function'
    CWE_243 = 243, 'CWE-243', 'Creation of chroot Jail Without Changing Working Directory'
    CWE_248 = 248, 'CWE-248', 'Uncaught Exception'
    CWE_250 = 250, 'CWE-250', 'Execution with Unnecessary Privileges'
    CWE_252 = 252, 'CWE-252', 'Unchecked Return Value'
    CWE_253 = 253, 'CWE-253', 'Incorrect Check of Function Return Value'
    CWE_256 = 256, 'CWE-256', 'Unprotected Storage of Credentials'
    CWE_257 = 257, 'CWE-257', 'Storing Passwords in a Recoverable Format'
    CWE_260 = 260, 'CWE-260', 'Password in Configuration File'
    CWE_261 = 261, 'CWE-261', 'Weak Encoding for Password'
    CWE_262 = 262, 'CWE-262', 'Not Using Password Aging'
    CWE_263 = 263, 'CWE-263', 'Password Aging with Long Expiration'
    CWE_266 = 266, 'CWE-266', 'Incorrect Privilege Assignment'
    CWE_267 = 267, 'CWE-267', 'Privilege Defined With Unsafe Actions'
    CWE_268 = 268, 'CWE-268', 'Privilege Chaining'
    CWE_270 = 270, 'CWE-270', 'Privilege Context Switching Error'
    CWE_272 = 272, 'CWE-272', 'Least Privilege Violation'
    CWE_273 = 273, 'CWE-273', 'Improper Check for Dropped Privileges'
    CWE_274 = 274, 'CWE-274', 'Improper Handling of Insufficient Privileges'
    CWE_276 = 276, 'CWE-276', 'Incorrect Default Permissions'
    CWE_277 = 277, 'CWE-277', 'Insecure Inherited Permissions'
    CWE_278 = 278, 'CWE-278', 'Insecure Preserved Inherited Permissions'
    CWE_279 = 279, 'CWE-279', 'Incorrect Execution-Assigned Permissions'
    CWE_280 = 280, 'CWE-280', 'Improper Handling of Insufficient Permissions or Privileges '
    CWE_281 = 281, 'CWE-281', 'Improper Preservation of Permissions'
    CWE_283 = 283, 'CWE-283', 'Unverified Ownership'
    CWE_288 = 288, 'CWE-288', 'Authentication Bypass Using an Alternate Path or Channel'
    CWE_290 = 290, 'CWE-290', 'Authentication Bypass by Spoofing'
    CWE_294 = 294, 'CWE-294', 'Authentication Bypass by Capture-replay'
    CWE_295 = 295, 'CWE-295', 'Improper Certificate Validation'
    CWE_296 = 296, 'CWE-296', 'Improper Following of a Certificate\'s Chain of Trust'
    CWE_299 = 299, 'CWE-299', 'Improper Check for Certificate Revocation'
    CWE_303 = 303, 'CWE-303', 'Incorrect Implementation of Authentication Algorithm'
    CWE_304 = 304, 'CWE-304', 'Missing Critical Step in Authentication'
    CWE_305 = 305, 'CWE-305', 'Authentication Bypass by Primary Weakness'
    CWE_306 = 306, 'CWE-306', 'Missing Authentication for Critical Function'
    CWE_307 = 307, 'CWE-307', 'Improper Restriction of Excessive Authentication Attempts'
    CWE_308 = 308, 'CWE-308', 'Use of Single-factor Authentication'
    CWE_309 = 309, 'CWE-309', 'Use of Password System for Primary Authentication'
    CWE_312 = 312, 'CWE-312', 'Cleartext Storage of Sensitive Information'
    CWE_317 = 317, 'CWE-317', 'Cleartext Storage of Sensitive Information in GUI'
    CWE_319 = 319, 'CWE-319', 'Cleartext Transmission of Sensitive Information'
    CWE_321 = 321, 'CWE-321', 'Use of Hard-coded Cryptographic Key'
    CWE_322 = 322, 'CWE-322', 'Key Exchange without Entity Authentication'
    CWE_323 = 323, 'CWE-323', 'Reusing a Nonce, Key Pair in Encryption'
    CWE_324 = 324, 'CWE-324', 'Use of a Key Past its Expiration Date'
    CWE_325 = 325, 'CWE-325', 'Missing Cryptographic Step'
    CWE_328 = 328, 'CWE-328', 'Reversible One-Way Hash'
    CWE_331 = 331, 'CWE-331', 'Insufficient Entropy'
    CWE_334 = 334, 'CWE-334', 'Small Space of Random Values'
    CWE_335 = 335, 'CWE-335', 'Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)'
    CWE_338 = 338, 'CWE-338', 'Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)'
    CWE_341 = 341, 'CWE-341', 'Predictable from Observable State'
    CWE_342 = 342, 'CWE-342', 'Predictable Exact Value from Previous Values'
    CWE_343 = 343, 'CWE-343', 'Predictable Value Range from Previous Values'
    CWE_346 = 346, 'CWE-346', 'Origin Validation Error'
    CWE_347 = 347, 'CWE-347', 'Improper Verification of Cryptographic Signature'
    CWE_348 = 348, 'CWE-348', 'Use of Less Trusted Source'
    CWE_349 = 349, 'CWE-349', 'Acceptance of Extraneous Untrusted Data With Trusted Data'
    CWE_351 = 351, 'CWE-351', 'Insufficient Type Distinction'
    CWE_353 = 353, 'CWE-353', 'Missing Support for Integrity Check'
    CWE_354 = 354, 'CWE-354', 'Improper Validation of Integrity Check Value'
    CWE_356 = 356, 'CWE-356', 'Product UI does not Warn User of Unsafe Actions'
    CWE_357 = 357, 'CWE-357', 'Insufficient UI Warning of Dangerous Operations'
    CWE_359 = 359, 'CWE-359', 'Exposure of Private Personal Information to an Unauthorized Actor'
    CWE_363 = 363, 'CWE-363', 'Race Condition Enabling Link Following'
    CWE_364 = 364, 'CWE-364', 'Signal Handler Race Condition'
    CWE_365 = 365, 'CWE-365', 'Race Condition in Switch'
    CWE_366 = 366, 'CWE-366', 'Race Condition within a Thread'
    CWE_367 = 367, 'CWE-367', 'Time-of-check Time-of-use (TOCTOU) Race Condition'
    CWE_368 = 368, 'CWE-368', 'Context Switching Race Condition'
    CWE_369 = 369, 'CWE-369', 'Divide By Zero'
    CWE_372 = 372, 'CWE-372', 'Incomplete Internal State Distinction'
    CWE_374 = 374, 'CWE-374', 'Passing Mutable Objects to an Untrusted Method'
    CWE_375 = 375, 'CWE-375', 'Returning a Mutable Object to an Untrusted Caller'
    CWE_378 = 378, 'CWE-378', 'Creation of Temporary File With Insecure Permissions'
    CWE_379 = 379, 'CWE-379', 'Creation of Temporary File in Directory with Insecure Permissions'
    CWE_385 = 385, 'CWE-385', 'Covert Timing Channel'
    CWE_386 = 386, 'CWE-386', 'Symbolic Name not Mapping to Correct Object'
    CWE_390 = 390, 'CWE-390', 'Detection of Error Condition Without Action'
    CWE_391 = 391, 'CWE-391', 'Unchecked Error Condition'
    CWE_392 = 392, 'CWE-392', 'Missing Report of Error Condition'
    CWE_393 = 393, 'CWE-393', 'Return of Wrong Status Code'
    CWE_394 = 394, 'CWE-394', 'Unexpected Status Code or Return Value'
    CWE_395 = 395, 'CWE-395', 'Use of NullPointerException Catch to Detect NULL Pointer Dereference'
    CWE_396 = 396, 'CWE-396', 'Declaration of Catch for Generic Exception'
    CWE_397 = 397, 'CWE-397', 'Declaration of Throws for Generic Exception'
    CWE_403 = 403, 'CWE-403', 'Exposure of File Descriptor to Unintended Control Sphere (\'File Descriptor Leak\')'
    CWE_408 = 408, 'CWE-408', 'Incorrect Behavior Order: Early Amplification'
    CWE_409 = 409, 'CWE-409', 'Improper Handling of Highly Compressed Data (Data Amplification)'
    CWE_410 = 410, 'CWE-410', 'Insufficient Resource Pool'
    CWE_412 = 412, 'CWE-412', 'Unrestricted Externally Accessible Lock'
    CWE_413 = 413, 'CWE-413', 'Improper Resource Locking'
    CWE_414 = 414, 'CWE-414', 'Missing Lock Check'
    CWE_419 = 419, 'CWE-419', 'Unprotected Primary Channel'
    CWE_420 = 420, 'CWE-420', 'Unprotected Alternate Channel'
    CWE_421 = 421, 'CWE-421', 'Race Condition During Access to Alternate Channel'
    CWE_425 = 425, 'CWE-425', 'Direct Request (\'Forced Browsing\')'
    CWE_426 = 426, 'CWE-426', 'Untrusted Search Path'
    CWE_427 = 427, 'CWE-427', 'Uncontrolled Search Path Element'
    CWE_428 = 428, 'CWE-428', 'Unquoted Search Path or Element'
    CWE_430 = 430, 'CWE-430', 'Deployment of Wrong Handler'
    CWE_431 = 431, 'CWE-431', 'Missing Handler'
    CWE_432 = 432, 'CWE-432', 'Dangerous Signal Handler not Disabled During Sensitive Operations'
    CWE_433 = 433, 'CWE-433', 'Unparsed Raw Web Content Delivery'
    CWE_434 = 434, 'CWE-434', 'Unrestricted Upload of File with Dangerous Type'
    CWE_437 = 437, 'CWE-437', 'Incomplete Model of Endpoint Features'
    CWE_439 = 439, 'CWE-439', 'Behavioral Change in New Version or Environment'
    CWE_440 = 440, 'CWE-440', 'Expected Behavior Violation'
    CWE_444 = 444, 'CWE-444', 'Inconsistent Interpretation of HTTP Requests (\'HTTP Request Smuggling\')'
    CWE_447 = 447, 'CWE-447', 'Unimplemented or Unsupported Feature in UI'
    CWE_448 = 448, 'CWE-448', 'Obsolete Feature in UI'
    CWE_449 = 449, 'CWE-449', 'The UI Performs the Wrong Action'
    CWE_450 = 450, 'CWE-450', 'Multiple Interpretations of UI Input'
    CWE_454 = 454, 'CWE-454', 'External Initialization of Trusted Variables or Data Stores'
    CWE_455 = 455, 'CWE-455', 'Non-exit on Failed Initialization'
    CWE_459 = 459, 'CWE-459', 'Incomplete Cleanup'
    CWE_460 = 460, 'CWE-460', 'Improper Cleanup on Thrown Exception'
    CWE_462 = 462, 'CWE-462', 'Duplicate Key in Associative List (Alist)'
    CWE_463 = 463, 'CWE-463', 'Deletion of Data Structure Sentinel'
    CWE_464 = 464, 'CWE-464', 'Addition of Data Structure Sentinel'
    CWE_466 = 466, 'CWE-466', 'Return of Pointer Value Outside of Expected Range'
    CWE_467 = 467, 'CWE-467', 'Use of sizeof() on a Pointer Type'
    CWE_468 = 468, 'CWE-468', 'Incorrect Pointer Scaling'
    CWE_469 = 469, 'CWE-469', 'Use of Pointer Subtraction to Determine Size'
    CWE_470 = 470, 'CWE-470', 'Use of Externally-Controlled Input to Select Classes or Code (\'Unsafe Reflection\')'
    CWE_471 = 471, 'CWE-471', 'Modification of Assumed-Immutable Data (MAID)'
    CWE_472 = 472, 'CWE-472', 'External Control of Assumed-Immutable Web Parameter'
    CWE_474 = 474, 'CWE-474', 'Use of Function with Inconsistent Implementations'
    CWE_475 = 475, 'CWE-475', 'Undefined Behavior for Input to API'
    CWE_476 = 476, 'CWE-476', 'NULL Pointer Dereference'
    CWE_477 = 477, 'CWE-477', 'Use of Obsolete Function'
    CWE_478 = 478, 'CWE-478', 'Missing Default Case in Switch Statement'
    CWE_479 = 479, 'CWE-479', 'Signal Handler Use of a Non-reentrant Function'
    CWE_480 = 480, 'CWE-480', 'Use of Incorrect Operator'
    CWE_483 = 483, 'CWE-483', 'Incorrect Block Delimitation'
    CWE_484 = 484, 'CWE-484', 'Omitted Break Statement in Switch'
    CWE_487 = 487, 'CWE-487', 'Reliance on Package-level Scope'
    CWE_488 = 488, 'CWE-488', 'Exposure of Data Element to Wrong Session'
    CWE_489 = 489, 'CWE-489', 'Active Debug Code'
    CWE_494 = 494, 'CWE-494', 'Download of Code Without Integrity Check'
    CWE_497 = 497, 'CWE-497', 'Exposure of Sensitive System Information to an Unauthorized Control Sphere'
    CWE_501 = 501, 'CWE-501', 'Trust Boundary Violation'
    CWE_502 = 502, 'CWE-502', 'Deserialization of Untrusted Data'
    CWE_515 = 515, 'CWE-515', 'Covert Storage Channel'
    CWE_521 = 521, 'CWE-521', 'Weak Password Requirements'
    CWE_523 = 523, 'CWE-523', 'Unprotected Transport of Credentials'
    CWE_524 = 524, 'CWE-524', 'Use of Cache Containing Sensitive Information'
    CWE_532 = 532, 'CWE-532', 'Insertion of Sensitive Information into Log File'
    CWE_540 = 540, 'CWE-540', 'Inclusion of Sensitive Information in Source Code'
    CWE_544 = 544, 'CWE-544', 'Missing Standardized Error Handling Mechanism'
    CWE_546 = 546, 'CWE-546', 'Suspicious Comment'
    CWE_547 = 547, 'CWE-547', 'Use of Hard-coded, Security-relevant Constants'
    CWE_549 = 549, 'CWE-549', 'Missing Password Field Masking'
    CWE_551 = 551, 'CWE-551', 'Incorrect Behavior Order: Authorization Before Parsing and Canonicalization'
    CWE_561 = 561, 'CWE-561', 'Dead Code'
    CWE_562 = 562, 'CWE-562', 'Return of Stack Variable Address'
    CWE_563 = 563, 'CWE-563', 'Assignment to Variable without Use'
    CWE_565 = 565, 'CWE-565', 'Reliance on Cookies without Validation and Integrity Checking'
    CWE_567 = 567, 'CWE-567', 'Unsynchronized Access to Shared Data in a Multithreaded Context'
    CWE_570 = 570, 'CWE-570', 'Expression is Always False'
    CWE_571 = 571, 'CWE-571', 'Expression is Always True'
    CWE_580 = 580, 'CWE-580', 'clone() Method Without super.clone()'
    CWE_581 = 581, 'CWE-581', 'Object Model Violation: Just One of Equals and Hashcode Defined'
    CWE_584 = 584, 'CWE-584', 'Return Inside Finally Block'
    CWE_585 = 585, 'CWE-585', 'Empty Synchronized Block'
    CWE_586 = 586, 'CWE-586', 'Explicit Call to Finalize()'
    CWE_587 = 587, 'CWE-587', 'Assignment of a Fixed Address to a Pointer'
    CWE_588 = 588, 'CWE-588', 'Attempt to Access Child of a Non-structure Pointer'
    CWE_595 = 595, 'CWE-595', 'Comparison of Object References Instead of Object Contents'
    CWE_597 = 597, 'CWE-597', 'Use of Wrong Operator in String Comparison'
    CWE_600 = 600, 'CWE-600', 'Uncaught Exception in Servlet '
    CWE_601 = 601, 'CWE-601', 'URL Redirection to Untrusted Site (\'Open Redirect\')'
    CWE_603 = 603, 'CWE-603', 'Use of Client-Side Authentication'
    CWE_605 = 605, 'CWE-605', 'Multiple Binds to the Same Port'
    CWE_606 = 606, 'CWE-606', 'Unchecked Input for Loop Condition'
    CWE_609 = 609, 'CWE-609', 'Double-Checked Locking'
    CWE_611 = 611, 'CWE-611', 'Improper Restriction of XML External Entity Reference'
    CWE_612 = 612, 'CWE-612', 'Improper Authorization of Index Containing Sensitive Information'
    CWE_613 = 613, 'CWE-613', 'Insufficient Session Expiration'
    CWE_617 = 617, 'CWE-617', 'Reachable Assertion'
    CWE_618 = 618, 'CWE-618', 'Exposed Unsafe ActiveX Method'
    CWE_619 = 619, 'CWE-619', 'Dangling Database Cursor (\'Cursor Injection\')'
    CWE_620 = 620, 'CWE-620', 'Unverified Password Change'
    CWE_621 = 621, 'CWE-621', 'Variable Extraction Error'
    CWE_624 = 624, 'CWE-624', 'Executable Regular Expression Error'
    CWE_625 = 625, 'CWE-625', 'Permissive Regular Expression'
    CWE_627 = 627, 'CWE-627', 'Dynamic Variable Evaluation'
    CWE_628 = 628, 'CWE-628', 'Function Call with Incorrectly Specified Arguments'
    CWE_639 = 639, 'CWE-639', 'Authorization Bypass Through User-Controlled Key'
    CWE_640 = 640, 'CWE-640', 'Weak Password Recovery Mechanism for Forgotten Password'
    CWE_641 = 641, 'CWE-641', 'Improper Restriction of Names for Files and Other Resources'
    CWE_643 = 643, 'CWE-643', 'Improper Neutralization of Data within XPath Expressions (\'XPath Injection\')'
    CWE_645 = 645, 'CWE-645', 'Overly Restrictive Account Lockout Mechanism'
    CWE_648 = 648, 'CWE-648', 'Incorrect Use of Privileged APIs'
    CWE_649 = 649, 'CWE-649', 'Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking'
    CWE_652 = 652, 'CWE-652', 'Improper Neutralization of Data within XQuery Expressions (\'XQuery Injection\')'
    CWE_663 = 663, 'CWE-663', 'Use of a Non-reentrant Function in a Concurrent Context'
    CWE_676 = 676, 'CWE-676', 'Use of Potentially Dangerous Function'
    CWE_681 = 681, 'CWE-681', 'Incorrect Conversion between Numeric Types'
    CWE_694 = 694, 'CWE-694', 'Use of Multiple Resources with Duplicate Identifier'
    CWE_695 = 695, 'CWE-695', 'Use of Low-Level Functionality'
    CWE_698 = 698, 'CWE-698', 'Execution After Redirect (EAR)'
    CWE_708 = 708, 'CWE-708', 'Incorrect Ownership Assignment'
    CWE_733 = 733, 'CWE-733', 'Compiler Optimization Removal or Modification of Security-critical Code'
    CWE_749 = 749, 'CWE-749', 'Exposed Dangerous Method or Function'
    CWE_756 = 756, 'CWE-756', 'Missing Custom Error Page'
    CWE_763 = 763, 'CWE-763', 'Release of Invalid Pointer or Reference'
    CWE_764 = 764, 'CWE-764', 'Multiple Locks of a Critical Resource'
    CWE_765 = 765, 'CWE-765', 'Multiple Unlocks of a Critical Resource'
    CWE_766 = 766, 'CWE-766', 'Critical Data Element Declared Public'
    CWE_767 = 767, 'CWE-767', 'Access to Critical Private Variable via Public Method'
    CWE_770 = 770, 'CWE-770', 'Allocation of Resources Without Limits or Throttling'
    CWE_771 = 771, 'CWE-771', 'Missing Reference to Active Allocated Resource'
    CWE_772 = 772, 'CWE-772', 'Missing Release of Resource after Effective Lifetime'
    CWE_776 = 776, 'CWE-776', 'Improper Restriction of Recursive Entity References in DTDs (\'XML Entity Expansion\')'
    CWE_778 = 778, 'CWE-778', 'Insufficient Logging'
    CWE_779 = 779, 'CWE-779', 'Logging of Excessive Data'
    CWE_783 = 783, 'CWE-783', 'Operator Precedence Logic Error'
    CWE_786 = 786, 'CWE-786', 'Access of Memory Location Before Start of Buffer'
    CWE_787 = 787, 'CWE-787', 'Out-of-bounds Write'
    CWE_788 = 788, 'CWE-788', 'Access of Memory Location After End of Buffer'
    CWE_791 = 791, 'CWE-791', 'Incomplete Filtering of Special Elements'
    CWE_795 = 795, 'CWE-795', 'Only Filtering Special Elements at a Specified Location'
    CWE_798 = 798, 'CWE-798', 'Use of Hard-coded Credentials'
    CWE_804 = 804, 'CWE-804', 'Guessable CAPTCHA'
    CWE_805 = 805, 'CWE-805', 'Buffer Access with Incorrect Length Value'
    CWE_820 = 820, 'CWE-820', 'Missing Synchronization'
    CWE_821 = 821, 'CWE-821', 'Incorrect Synchronization'
    CWE_822 = 822, 'CWE-822', 'Untrusted Pointer Dereference'
    CWE_823 = 823, 'CWE-823', 'Use of Out-of-range Pointer Offset'
    CWE_824 = 824, 'CWE-824', 'Access of Uninitialized Pointer'
    CWE_825 = 825, 'CWE-825', 'Expired Pointer Dereference'
    CWE_826 = 826, 'CWE-826', 'Premature Release of Resource During Expected Lifetime'
    CWE_828 = 828, 'CWE-828', 'Signal Handler with Functionality that is not Asynchronous-Safe'
    CWE_829 = 829, 'CWE-829', 'Inclusion of Functionality from Untrusted Control Sphere'
    CWE_831 = 831, 'CWE-831', 'Signal Handler Function Associated with Multiple Signals'
    CWE_832 = 832, 'CWE-832', 'Unlock of a Resource that is not Locked'
    CWE_833 = 833, 'CWE-833', 'Deadlock'
    CWE_835 = 835, 'CWE-835', 'Loop with Unreachable Exit Condition (\'Infinite Loop\')'
    CWE_836 = 836, 'CWE-836', 'Use of Password Hash Instead of Password for Authentication'
    CWE_837 = 837, 'CWE-837', 'Improper Enforcement of a Single, Unique Action'
    CWE_838 = 838, 'CWE-838', 'Inappropriate Encoding for Output Context'
    CWE_839 = 839, 'CWE-839', 'Numeric Range Comparison Without Minimum Check'
    CWE_841 = 841, 'CWE-841', 'Improper Enforcement of Behavioral Workflow'
    CWE_842 = 842, 'CWE-842', 'Placement of User into Incorrect Group'
    CWE_843 = 843, 'CWE-843', 'Access of Resource Using Incompatible Type (\'Type Confusion\')'
    CWE_908 = 908, 'CWE-908', 'Use of Uninitialized Resource'
    CWE_909 = 909, 'CWE-909', 'Missing Initialization of Resource'
    CWE_910 = 910, 'CWE-910', 'Use of Expired File Descriptor'
    CWE_911 = 911, 'CWE-911', 'Improper Update of Reference Count'
    CWE_914 = 914, 'CWE-914', 'Improper Control of Dynamically-Identified Variables'
    CWE_915 = 915, 'CWE-915', 'Improperly Controlled Modification of Dynamically-Determined Object Attributes'
    CWE_916 = 916, 'CWE-916', 'Use of Password Hash With Insufficient Computational Effort'
    CWE_917 = 917, 'CWE-917', 'Improper Neutralization of Special Elements used in an Expression Language Statement (\'Expression Language Injection\')'
    CWE_920 = 920, 'CWE-920', 'Improper Restriction of Power Consumption'
    CWE_921 = 921, 'CWE-921', 'Storage of Sensitive Data in a Mechanism without Access Control'
    CWE_924 = 924, 'CWE-924', 'Improper Enforcement of Message Integrity During Transmission in a Communication Channel'
    CWE_939 = 939, 'CWE-939', 'Improper Authorization in Handler for Custom URL Scheme'
    CWE_940 = 940, 'CWE-940', 'Improper Verification of Source of a Communication Channel'
    CWE_941 = 941, 'CWE-941', 'Incorrectly Specified Destination in a Communication Channel'
    CWE_1007 = 1007, 'CWE-1007', 'Insufficient Visual Distinction of Homoglyphs Presented to User'
    CWE_1021 = 1021, 'CWE-1021', 'Improper Restriction of Rendered UI Layers or Frames'
    CWE_1024 = 1024, 'CWE-1024', 'Comparison of Incompatible Types'
    CWE_1025 = 1025, 'CWE-1025', 'Comparison Using Wrong Factors'
    CWE_1037 = 1037, 'CWE-1037', 'Processor Optimization Removal or Modification of Security-critical Code'
    CWE_1041 = 1041, 'CWE-1041', 'Use of Redundant Code'
    CWE_1043 = 1043, 'CWE-1043', 'Data Element Aggregating an Excessively Large Number of Non-Primitive Elements'
    CWE_1044 = 1044, 'CWE-1044', 'Architecture with Number of Horizontal Layers Outside of Expected Range'
    CWE_1045 = 1045, 'CWE-1045', 'Parent Class with a Virtual Destructor and a Child Class without a Virtual Destructor'
    CWE_1046 = 1046, 'CWE-1046', 'Creation of Immutable Text Using String Concatenation'
    CWE_1047 = 1047, 'CWE-1047', 'Modules with Circular Dependencies'
    CWE_1048 = 1048, 'CWE-1048', 'Invokable Control Element with Large Number of Outward Calls'
    CWE_1049 = 1049, 'CWE-1049', 'Excessive Data Query Operations in a Large Data Table'
    CWE_1050 = 1050, 'CWE-1050', 'Excessive Platform Resource Consumption within a Loop'
    CWE_1051 = 1051, 'CWE-1051', 'Initialization with Hard-Coded Network Resource Configuration Data'
    CWE_1052 = 1052, 'CWE-1052', 'Excessive Use of Hard-Coded Literals in Initialization'
    CWE_1053 = 1053, 'CWE-1053', 'Missing Documentation for Design'
    CWE_1054 = 1054, 'CWE-1054', 'Invocation of a Control Element at an Unnecessarily Deep Horizontal Layer'
    CWE_1055 = 1055, 'CWE-1055', 'Multiple Inheritance from Concrete Classes'
    CWE_1056 = 1056, 'CWE-1056', 'Invokable Control Element with Variadic Parameters'
    CWE_1057 = 1057, 'CWE-1057', 'Data Access Operations Outside of Expected Data Manager Component'
    CWE_1058 = 1058, 'CWE-1058', 'Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element'
    CWE_1060 = 1060, 'CWE-1060', 'Excessive Number of Inefficient Server-Side Data Accesses'
    CWE_1062 = 1062, 'CWE-1062', 'Parent Class with References to Child Class'
    CWE_1063 = 1063, 'CWE-1063', 'Creation of Class Instance within a Static Code Block'
    CWE_1064 = 1064, 'CWE-1064', 'Invokable Control Element with Signature Containing an Excessive Number of Parameters'
    CWE_1065 = 1065, 'CWE-1065', 'Runtime Resource Management Control Element in a Component Built to Run on Application Servers'
    CWE_1066 = 1066, 'CWE-1066', 'Missing Serialization Control Element'
    CWE_1067 = 1067, 'CWE-1067', 'Excessive Execution of Sequential Searches of Data Resource'
    CWE_1068 = 1068, 'CWE-1068', 'Inconsistency Between Implementation and Documented Design'
    CWE_1069 = 1069, 'CWE-1069', 'Empty Exception Block'
    CWE_1070 = 1070, 'CWE-1070', 'Serializable Data Element Containing non-Serializable Item Elements'
    CWE_1071 = 1071, 'CWE-1071', 'Empty Code Block'
    CWE_1072 = 1072, 'CWE-1072', 'Data Resource Access without Use of Connection Pooling'
    CWE_1073 = 1073, 'CWE-1073', 'Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses'
    CWE_1074 = 1074, 'CWE-1074', 'Class with Excessively Deep Inheritance'
    CWE_1075 = 1075, 'CWE-1075', 'Unconditional Control Flow Transfer outside of Switch Block'
    CWE_1077 = 1077, 'CWE-1077', 'Floating Point Comparison with Incorrect Operator'
    CWE_1079 = 1079, 'CWE-1079', 'Parent Class without Virtual Destructor Method'
    CWE_1080 = 1080, 'CWE-1080', 'Source Code File with Excessive Number of Lines of Code'
    CWE_1082 = 1082, 'CWE-1082', 'Class Instance Self Destruction Control Element'
    CWE_1083 = 1083, 'CWE-1083', 'Data Access from Outside Expected Data Manager Component'
    CWE_1084 = 1084, 'CWE-1084', 'Invokable Control Element with Excessive File or Data Access Operations'
    CWE_1085 = 1085, 'CWE-1085', 'Invokable Control Element with Excessive Volume of Commented-out Code'
    CWE_1086 = 1086, 'CWE-1086', 'Class with Excessive Number of Child Classes'
    CWE_1087 = 1087, 'CWE-1087', 'Class with Virtual Method without a Virtual Destructor'
    CWE_1088 = 1088, 'CWE-1088', 'Synchronous Access of Remote Resource without Timeout'
    CWE_1089 = 1089, 'CWE-1089', 'Large Data Table with Excessive Number of Indices'
    CWE_1090 = 1090, 'CWE-1090', 'Method Containing Access of a Member Element from Another Class'
    CWE_1091 = 1091, 'CWE-1091', 'Use of Object without Invoking Destructor Method'
    CWE_1092 = 1092, 'CWE-1092', 'Use of Same Invokable Control Element in Multiple Architectural Layers'
    CWE_1094 = 1094, 'CWE-1094', 'Excessive Index Range Scan for a Data Resource'
    CWE_1095 = 1095, 'CWE-1095', 'Loop Condition Value Update within the Loop'
    CWE_1097 = 1097, 'CWE-1097', 'Persistent Storable Data Element without Associated Comparison Control Element'
    CWE_1098 = 1098, 'CWE-1098', 'Data Element containing Pointer Item without Proper Copy Control Element'
    CWE_1099 = 1099, 'CWE-1099', 'Inconsistent Naming Conventions for Identifiers'
    CWE_1100 = 1100, 'CWE-1100', 'Insufficient Isolation of System-Dependent Functions'
    CWE_1101 = 1101, 'CWE-1101', 'Reliance on Runtime Component in Generated Code'
    CWE_1102 = 1102, 'CWE-1102', 'Reliance on Machine-Dependent Data Representation'
    CWE_1103 = 1103, 'CWE-1103', 'Use of Platform-Dependent Third Party Components'
    CWE_1104 = 1104, 'CWE-1104', 'Use of Unmaintained Third Party Components'
    CWE_1105 = 1105, 'CWE-1105', 'Insufficient Encapsulation of Machine-Dependent Functionality'
    CWE_1106 = 1106, 'CWE-1106', 'Insufficient Use of Symbolic Constants'
    CWE_1107 = 1107, 'CWE-1107', 'Insufficient Isolation of Symbolic Constant Definitions'
    CWE_1108 = 1108, 'CWE-1108', 'Excessive Reliance on Global Variables'
    CWE_1109 = 1109, 'CWE-1109', 'Use of Same Variable for Multiple Purposes'
    CWE_1110 = 1110, 'CWE-1110', 'Incomplete Design Documentation'
    CWE_1111 = 1111, 'CWE-1111', 'Incomplete I/O Documentation'
    CWE_1112 = 1112, 'CWE-1112', 'Incomplete Documentation of Program Execution'
    CWE_1113 = 1113, 'CWE-1113', 'Inappropriate Comment Style'
    CWE_1114 = 1114, 'CWE-1114', 'Inappropriate Whitespace Style'
    CWE_1115 = 1115, 'CWE-1115', 'Source Code Element without Standard Prologue'
    CWE_1116 = 1116, 'CWE-1116', 'Inaccurate Comments'
    CWE_1117 = 1117, 'CWE-1117', 'Callable with Insufficient Behavioral Summary'
    CWE_1118 = 1118, 'CWE-1118', 'Insufficient Documentation of Error Handling Techniques'
    CWE_1119 = 1119, 'CWE-1119', 'Excessive Use of Unconditional Branching'
    CWE_1121 = 1121, 'CWE-1121', 'Excessive McCabe Cyclomatic Complexity'
    CWE_1122 = 1122, 'CWE-1122', 'Excessive Halstead Complexity'
    CWE_1123 = 1123, 'CWE-1123', 'Excessive Use of Self-Modifying Code'
    CWE_1124 = 1124, 'CWE-1124', 'Excessively Deep Nesting'
    CWE_1125 = 1125, 'CWE-1125', 'Excessive Attack Surface'
    CWE_1126 = 1126, 'CWE-1126', 'Declaration of Variable with Unnecessarily Wide Scope'
    CWE_1127 = 1127, 'CWE-1127', 'Compilation with Insufficient Warnings or Errors'
    CWE_1173 = 1173, 'CWE-1173', 'Improper Use of Validation Framework'
    CWE_1188 = 1188, 'CWE-1188', 'Insecure Default Initialization of Resource'
    CWE_1220 = 1220, 'CWE-1220', 'Insufficient Granularity of Access Control'
    CWE_1230 = 1230, 'CWE-1230', 'Exposure of Sensitive Information Through Metadata'
    CWE_1235 = 1235, 'CWE-1235', 'Incorrect Use of Autoboxing and Unboxing for Performance Critical Operations'
    CWE_1236 = 1236, 'CWE-1236', 'Improper Neutralization of Formula Elements in a CSV File'
    CWE_1240 = 1240, 'CWE-1240', 'Use of a Risky Cryptographic Primitive'
    CWE_1241 = 1241, 'CWE-1241', 'Use of Predictable Algorithm in Random Number Generator'
    CWE_1265 = 1265, 'CWE-1265', 'Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls'
