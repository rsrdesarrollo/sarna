from sarna.model.enums.base_choice import BaseChoice
from sarna.model.enums.language import Language


class OWASPMobileTop10Category(BaseChoice):
    _init_ = "value code desc translation"
    M1 = 1, 'M1', 'Improper Platform Usage', {
        Language.English: 'Improper Platform Usage',
        Language.Spanish: 'Uso inapropiado de la plataforma'
    }
    M2 = 2, 'M2', 'Insecure Data Storage', {
        Language.English: 'Insecure Data Storage',
        Language.Spanish: 'Almacenamiento inseguro de información'
    }
    M3 = 3, 'M3', 'Insecure Communication', {
        Language.English: 'Insecure Communication',
        Language.Spanish: 'Comunicaciones inseguras'
    }
    M4 = 4, 'M4', 'Insecure Authentication', {
        Language.English: 'Insecure Authentication',
        Language.Spanish: 'Autenticación insegura'
    }
    M5 = 5, 'M5', 'Insufficient Cryptography', {
        Language.English: 'Insufficient Cryptography',
        Language.Spanish: 'Criptografía insuficiente'
    }
    M6 = 6, 'M6', 'Insecure Authorization', {
        Language.English: 'Insecure Authorization',
        Language.Spanish: 'Autorización insegura'
    }
    M7 = 7, 'M7', 'Poor Code Quality', {
        Language.English: 'Poor Code Quality',
        Language.Spanish: 'Mala calidad del código'
    }
    M8 = 8, 'M8', 'Code Tampering', {
        Language.English: 'Code Tampering',
        Language.Spanish: 'Modificaciones de código'
    }
    M9 = 9, 'M9', 'Reverse Engineering', {
        Language.English: 'Reverse Engineering',
        Language.Spanish: 'Ingeniería inversa'
    }
    M10 = 10, 'M10', 'Extraneous Functionality', {
        Language.English: 'Extraneous Functionality',
        Language.Spanish: 'Funcionalidad oculta'
    }


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
