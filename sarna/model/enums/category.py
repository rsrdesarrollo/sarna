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


class OWASPCategory(BaseChoice):
    _init_ = "value code desc translation"
    OTG_INFO_001 = 1, 'WSTG-INFO-01', 'Conduct Search Engine Discovery and Reconnaissance for Information Leakage', {
        Language.English: 'Conduct Search Engine Discovery and Reconnaissance for Information Leakage',
        Language.Spanish: 'Identificación y reconocimiento a través de motores de búsqueda'
    }
    OTG_INFO_002 = 2, 'WSTG-INFO-02', 'Fingerprint Web Server', {
        Language.English: 'Fingerprint Web Server',
        Language.Spanish: 'Identificación del servidor web'
    }
    OTG_INFO_003 = 3, 'WSTG-INFO-03', 'Review Webserver Metafiles for Information Leakage', {
        Language.English: 'Review Webserver Metafiles for Information Leakage',
        Language.Spanish: 'Identificación de fugas de información en metaficheros'
    }
    OTG_INFO_004 = 4, 'WSTG-INFO-04', 'Enumerate Applications on Webserver', {
        Language.English: 'Enumerate Applications on Webserver',
        Language.Spanish: 'Enumeración de aplicaciones en el servidor web'
    }
    OTG_INFO_005 = 5, 'WSTG-INFO-05', 'Review Webpage Content for Information Leakage', {
        Language.English: 'Review Webpage Content for Information Leakage',
        Language.Spanish: 'Identificación de fugas de información en el contenido de páginas web'
    }
    OTG_INFO_006 = 6, 'WSTG-INFO-06', 'Identify application entry points', {
        Language.English: 'Identify application entry points',
        Language.Spanish: 'Identificación de puntos de entrada de la aplicación'
    }
    OTG_INFO_007 = 7, 'WSTG-INFO-07', 'Map execution paths through application', {
        Language.English: 'Map execution paths through application',
        Language.Spanish: 'Identificación de rutas de la aplicación'
    }
    OTG_INFO_008 = 8, 'WSTG-INFO-08', 'Fingerprint Web Application Framework', {
        Language.English: 'Fingerprint Web Application Framework',
        Language.Spanish: 'Identificación del framework de la aplicación web'
    }
    OTG_INFO_009 = 9, 'WSTG-INFO-09', 'Fingerprint Web Application', {
        Language.English: 'Fingerprint Web Application',
        Language.Spanish: 'Identificación de la aplicación web'
    }
    OTG_INFO_010 = 10, 'WSTG-INFO-10', 'Map Application Architecture', {
        Language.English: 'Map Application Architecture',
        Language.Spanish: 'Mapeo de arquitectura de red y de aplicación'
    }
    OTG_CONFIG_001 = 11, 'WSTG-CONF-01', 'Test Network/Infrastructure Configuration', {
        Language.English: 'Test Network/Infrastructure Configuration',
        Language.Spanish: 'Pruebas de configuración de red y de infraestructura'
    }
    OTG_CONFIG_002 = 12, 'WSTG-CONF-02', 'Test Application Platform Configuration', {
        Language.English: 'Test Application Platform Configuration',
        Language.Spanish: 'Pruebas de configuración de la plataforma de la aplicación'
    }
    OTG_CONFIG_003 = 13, 'WSTG-CONF-03', 'Test File Extensions Handling for Sensitive Information', {
        Language.English: 'Test File Extensions Handling for Sensitive Information',
        Language.Spanish: 'Extracción de información sensible en la gestión de extensiones de archivo'
    }
    OTG_CONFIG_004 = 14, 'WSTG-CONF-04', 'Review Old, Backup and Unreferenced Files for Sensitive Information', {
        Language.English: 'Review Old, Backup and Unreferenced Files for Sensitive Information',
        Language.Spanish: 'Búsqueda de información sensible en ficheros no referenciados, antiguos y copias de seguridad'
    }
    OTG_CONFIG_005 = 15, 'WSTG-CONF-05', 'Enumerate Infrastructure and Application Admin Interfaces', {
        Language.English: 'Enumerate Infrastructure and Application Admin Interfaces',
        Language.Spanish: 'Enumeración de interfaces administrativas de aplicación y la infraestructura'
    }
    OTG_CONFIG_006 = 16, 'WSTG-CONF-06', 'Test HTTP Methods', {
        Language.English: 'Test HTTP Methods',
        Language.Spanish: 'Análisis de métodos HTTP'
    }
    OTG_CONFIG_007 = 17, 'WSTG-CONF-07', 'Test HTTP Strict Transport Security', {
        Language.English: 'Test HTTP Strict Transport Security',
        Language.Spanish: 'Pruebas sobre políticas de seguridad (HTTP Strict Transport Security)'
    }
    OTG_CONFIG_008 = 18, 'WSTG-CONF-08', 'Test RIA cross domain policy', {
        Language.English: 'Test RIA cross domain policy',
        Language.Spanish: 'Pruebas de políticas cross-domain RIA (Rich Internet Applications)'
    }
    OTG_CONFIG_009 = 90, 'WSTG-CONF-09', 'Test File Permission', {
        Language.English: 'Test File Permission',
        Language.Spanish: 'Pruebas sobre los permisos de archivos'
    }
    OTG_CONFIG_010 = 94, 'WSTG-CONF-10', 'Test for Subdomain Takeover', {
        Language.English: 'Test for Subdomain Takeover',
        Language.Spanish: 'Pruebas sobre adquisición de subdominios'
    }
    OTG_CONFIG_011 = 95, 'WSTG-CONF-11', 'Test Cloud Storage', {
        Language.English: 'Test Cloud Storage',
        Language.Spanish: 'Pruebas sobre almacenamiento en la nube'
    }
    OTG_IDENT_001 = 19, 'WSTG-IDNT-01', 'Test Role Definitions', {
        Language.English: 'Test Role Definitions',
        Language.Spanish: 'Análisis de definición de roles'
    }
    OTG_IDENT_002 = 20, 'WSTG-IDNT-02', 'Test User Registration Process', {
        Language.English: 'Test User Registration Process',
        Language.Spanish: 'Análisis del proceso de registro de usuario'
    }
    OTG_IDENT_003 = 21, 'WSTG-IDNT-03', 'Test Account Provisioning Process', {
        Language.English: 'Test Account Provisioning Process',
        Language.Spanish: 'Pruebas sobre procesos de aprovisionamiento de cuentas'
    }
    OTG_IDENT_004 = 22, 'WSTG-IDNT-04', 'Testing for Account Enumeration and Guessable User Account', {
        Language.English: 'Testing for Account Enumeration and Guessable User Account',
        Language.Spanish: 'Pruebas de identificación y enumeración de cuentas de usuario'
    }
    OTG_IDENT_005 = 23, 'WSTG-IDNT-05', 'Testing for Weak or unenforced username policy', {
        Language.English: 'Testing for Weak or unenforced username policy',
        Language.Spanish: 'Pruebas sobre identificadores de usuario débiles'
    }
    OTG_AUTHN_001 = 26, 'WSTG-ATHN-01', 'Testing for Credentials Transported over an Encrypted Channel', {
        Language.English: 'Testing for Credentials Transported over an Encrypted Channel',
        Language.Spanish: 'Pruebas de transmisión de credenciales por un canal sin cifrado'
    }
    OTG_AUTHN_002 = 27, 'WSTG-ATHN-02', 'Testing for default credentials', {
        Language.English: 'Testing for default credentials',
        Language.Spanish: 'Pruebas de credenciales por defecto'
    }
    OTG_AUTHN_003 = 28, 'WSTG-ATHN-03', 'Testing for Weak lock out mechanism', {
        Language.English: 'Testing for Weak lock out mechanism',
        Language.Spanish: 'Pruebas sobre sistemas de bloqueo de cuentas débiles'
    }
    OTG_AUTHN_004 = 29, 'WSTG-ATHN-04', 'Testing for bypassing authentication schema', {
        Language.English: 'Testing for bypassing authentication schema',
        Language.Spanish: 'Pruebas de evitar los mecanismos de autenticación'
    }
    OTG_AUTHN_005 = 30, 'WSTG-ATHN-05', 'Testing for vulnerable remember password', {
        Language.English: 'Test remember password functionality',
        Language.Spanish: 'Pruebas sobre los mecanismos de recordatorio de contraseña'
    }
    OTG_AUTHN_006 = 31, 'WSTG-ATHN-06', 'Testing for Browser cache weakness', {
        Language.English: 'Testing for Browser cache weakness',
        Language.Spanish: 'Pruebas de debilidades en la caché del navegador'
    }
    OTG_AUTHN_007 = 32, 'WSTG-ATHN-07', 'Testing for Weak password policy', {
        Language.English: 'Testing for Weak password policy',
        Language.Spanish: 'Pruebas sobre políticas de contraseñas débiles'
    }
    OTG_AUTHN_008 = 33, 'WSTG-ATHN-08', 'Testing for Weak security question/answer', {
        Language.English: 'Testing for Weak security question/answer',
        Language.Spanish: 'Pruebas sobre preguntas y respuestas de seguridad'
    }
    OTG_AUTHN_009 = 34, 'WSTG-ATHN-09', 'Testing for weak password change or reset functionalities', {
        Language.English: 'Testing for weak password change or reset functionalities',
        Language.Spanish: 'Pruebas sobre mecanismos de cambio y recuperación de contraseña'
    }
    OTG_AUTHN_010 = 35, 'WSTG-ATHN-10', 'Testing for Weaker authentication in alternative channel', {
        Language.English: 'Testing for Weaker authentication in alternative channel',
        Language.Spanish: 'Pruebas de autenticación débil en canales alternativos'
    }
    OTG_AUTHZ_001 = 36, 'WSTG-ATHZ-01', 'Testing Directory traversal/file include', {
        Language.English: 'Testing Directory traversal/file include',
        Language.Spanish: 'Pruebas de atravesamiento de directorio e inclusión de ficheros'
    }
    OTG_AUTHZ_002 = 37, 'WSTG-ATHZ-02', 'Testing for bypassing authorization schema', {
        Language.English: 'Testing for bypassing authorization schema',
        Language.Spanish: 'Pruebas para evitar el esquema de autorización'
    }
    OTG_AUTHZ_003 = 38, 'WSTG-ATHZ-03', 'Testing for Privilege Escalation', {
        Language.English: 'Testing for Privilege Escalation',
        Language.Spanish: 'Pruebas de escalado de privilegios'
    }
    OTG_AUTHZ_004 = 39, 'WSTG-ATHZ-04', 'Testing for Insecure Direct Object References', {
        Language.English: 'Testing for Insecure Direct Object References',
        Language.Spanish: 'Pruebas de referencias directas inseguras a objetos (IDOR)'
    }
    OTG_SESS_001 = 40, 'WSTG-SESS-01', 'Testing for Session Management Schema', {
        Language.English: 'Testing for Session Management Schema',
        Language.Spanish: 'Pruebas sobre el mecanismo de gestión de sesiones'
    }
    OTG_SESS_002 = 41, 'WSTG-SESS-02', 'Testing for Cookies attributes', {
        Language.English: 'Testing for Cookies attributes',
        Language.Spanish: 'Pruebas de los atributos de cookies de sesión'
    }
    OTG_SESS_003 = 42, 'WSTG-SESS-03', 'Testing for Session Fixation', {
        Language.English: 'Testing for Session Fixation',
        Language.Spanish: 'Pruebas de fijación de sesiones'
    }
    OTG_SESS_004 = 43, 'WSTG-SESS-04', 'Testing for Exposed Session Variables', {
        Language.English: 'Testing for Exposed Session Variables',
        Language.Spanish: 'Pruebas sobre la exposición de variables de sesión'
    }
    OTG_SESS_005 = 44, 'WSTG-SESS-05', 'Testing for Cross-Site Request Forgery', {
        Language.English: 'Testing for Cross-Site Request Forgery',
        Language.Spanish: 'Pruebas de Cross-Site Request Forgery (CSRF)'
    }
    OTG_SESS_006 = 45, 'WSTG-SESS-06', 'Testing for logout functionality', {
        Language.English: 'Testing for logout functionality',
        Language.Spanish: 'Pruebas sobre la funcionalidad de cierre de sesión'
    }
    OTG_SESS_007 = 46, 'WSTG-SESS-07', 'Test Session Timeout', {
        Language.English: 'Test Session Timeout',
        Language.Spanish: 'Pruebas sobre la caducidad de la sesión'
    }
    OTG_SESS_008 = 47, 'WSTG-SESS-08', 'Testing for Session puzzling', {
        Language.English: 'Testing for Session puzzling',
        Language.Spanish: 'Pruebas de puzzling de sesión'
    }
    OTG_SESS_009 = 96, 'WSTG-SESS-00', 'Testing for Session Hijacking', {
        Language.English: 'Testing for Session Hijacking',
        Language.Spanish: 'Pruebas de hijacking de sesión'
    }
    OTG_INPVAL_001 = 48, 'WSTG-INPV-01', 'Testing for Reflected Cross-Site Scripting', {
        Language.English: 'Testing for Reflected Cross-Site Scripting',
        Language.Spanish: 'Pruebas de Cross-Site Scripting reflejado'
    }
    OTG_INPVAL_002 = 49, 'WSTG-INPV-02', 'Testing for Stored Cross-Site Scripting', {
        Language.English: 'Testing for Stored Cross-Site Scripting',
        Language.Spanish: 'Pruebas de Cross-Site Scripting almacenado'
    }
    OTG_INPVAL_003 = 50, 'WSTG-INPV-03', 'Testing for HTTP Verb Tampering', {
        Language.English: 'Testing for HTTP Verb Tampering',
        Language.Spanish: 'Pruebas de manipulación de verbos HTTP'
    }
    OTG_INPVAL_004 = 51, 'WSTG-INPV-04', 'Testing for HTTP Parameter pollution', {
        Language.English: 'Testing for HTTP Parameter pollution',
        Language.Spanish: 'Pruebas de polución de parámetros HTTP'
    }
    OTG_INPVAL_005 = 52, 'WSTG-INPV-05', 'Testing for SQL Injection', {
        Language.English: 'Testing for SQL Injection',
        Language.Spanish: 'Pruebas de inyección SQL'
    }
    OTG_INPVAL_006 = 53, 'WSTG-INPV-06', 'Testing for LDAP Injection', {
        Language.English: 'Testing for LDAP Injection',
        Language.Spanish: 'Pruebas de inyección LDAP'
    }
    OTG_INPVAL_007 = 54, 'OTG-INPVAL-007', 'Testing for ORM Injection [DEPRECATED]', {
        Language.English: 'Testing for ORM Injection (OWASP 4.0)',
        Language.Spanish: 'Pruebas de inyección ORM (OWASP 4.0)'
    }
    OTG_INPVAL_008 = 55, 'WSTG-INPV-07', 'Testing for XML Injection', {
        Language.English: 'Testing for XML Injection',
        Language.Spanish: 'Pruebas de inyección XML'
    }
    OTG_INPVAL_009 = 56, 'WSTG-INPV-08', 'Testing for SSI Injection', {
        Language.English: 'Testing for SSI Injection',
        Language.Spanish: 'Pruebas de inyección SSI'
    }
    OTG_INPVAL_010 = 57, 'WSTG-INPV-09', 'Testing for XPath Injection', {
        Language.English: 'Testing for XPath Injection',
        Language.Spanish: 'Pruebas de inyección XPath'
    }
    OTG_INPVAL_011 = 58, 'WSTG-INPV-10', 'IMAP SMTP Injection', {
        Language.English: 'IMAP/SMTP Injection',
        Language.Spanish: 'Pruebas de inyección IMAP SMTP'
    }
    OTG_INPVAL_012 = 59, 'WSTG-INPV-11', 'Testing for Code Injection', {
        Language.English: 'Testing for Code Injection',
        Language.Spanish: 'Pruebas de inyección de código (LFI/RFI)'
    }
    OTG_INPVAL_013 = 60, 'WSTG-INPV-12', 'Testing for Command Injection', {
        Language.English: 'Testing for Command Injection',
        Language.Spanish: 'Pruebas de inyección de comandos'
    }
    OTG_INPVAL_014 = 61, 'OTG-INPVAL-014', 'Testing for Buffer overflow [DEPRECATED]', {
        Language.English: 'Testing for Buffer overflow (OWASP 4.0)',
        Language.Spanish: 'Pruebas de desbordamiento de búfer (OWASP 4.0)'
    }
    OTG_INPVAL_021 = 97, 'WSTG-INPV-13', 'Testing for Format String Injection', {
        Language.English: 'Testing for Format String Injection',
        Language.Spanish: 'Pruebas de inyección en format string'
    }
    OTG_INPVAL_015 = 62, 'WSTG-INPV-14', 'Testing for Incubated Vulnerability', {
        Language.English: 'Testing for Incubated Vulnerability',
        Language.Spanish: 'Pruebas de vulnerabilidad incubada'
    }
    OTG_INPVAL_016 = 63, 'WSTG-INPV-15', 'Testing for HTTP Splitting Smuggling', {
        Language.English: 'Testing for HTTP Splitting Smuggling',
        Language.Spanish: 'Pruebas de HTTP Splitting Smuggling'
    }
    OTG_INPVAL_017 = 91, 'WSTG-INPV-16', 'Testing for HTTP Incomming Requests', {
        Language.English: 'Testing for HTTP Incomming Requests',
        Language.Spanish: 'Pruebas de peticiones HTTP recibidas'
    }
    OTG_INPVAL_018 = 98, 'WSTG-INPV-17', 'Testing for Host Header Injection', {
        Language.English: 'Testing for Host Header Injection',
        Language.Spanish: 'Pruebas de inyección en cabeceras'
    }
    OTG_INPVAL_019 = 99, 'WSTG-INPV-18', 'Testing for Server-side Template Injection', {
        Language.English: 'Testing for Server-side Template Injection',
        Language.Spanish: 'Pruebas de inyección en plantillas de lado de servidor (SSTI)'
    }
    OTG_INPVAL_020 = 100, 'WSTG-INPV-19', 'Testing for Server-side Request Forgery', {
        Language.English: 'Testing for Server-side Request Forgery',
        Language.Spanish: 'Pruebas de Server-side Request Forgery'
    }
    OTG_ERR_001 = 64, 'OTG-ERR-001', 'Analysis of Error Codes [DEPRECATED]', {
        Language.English: 'Analysis of Error Codes (OWASP 4.0)',
        Language.Spanish: 'Análisis de códigos de error(OWASP 4.0)'
    }
    OTG_ERR_002 = 65, 'WSTG-ERRH-01', 'Testing for Improper Error Handling', {
        Language.English: 'Testing for Improper Error Handling',
        Language.Spanish: 'Análisis de la gestión de errores'
    }
    OTG_CRYPST_001 = 66, 'WSTG-CRYP-01', 'Testing for Weak Transport Layer Security', {
        Language.English: 'Testing for Weak Transport Layer Security',
        Language.Spanish: 'Pruebas de uso de protección insuficiente de la capa de transporte'
    }
    OTG_CRYPST_002 = 67, 'WSTG-CRYP-02', 'Testing for Padding Oracle', {
        Language.English: 'Testing for Padding Oracle',
        Language.Spanish: 'Pruebas de padding oracle'
    }
    OTG_CRYPST_003 = 68, 'WSTG-CRYP-03', 'Testing for Sensitive information sent via unencrypted channels', {
        Language.English: 'Testing for Sensitive information sent via unencrypted channels',
        Language.Spanish: 'Pruebas de transmisión de información sensible a través de canales sin cifrar'
    }
    OTG_CRYPST_004 = 92, 'WSTG-CRYP-04', 'Testing for Weak Encryption', {
        Language.English: 'Testing for Weak Encryption',
        Language.Spanish: 'Pruebas de cifrados débiles'
    }
    OTG_BUSLOGIC_001 = 69, 'WSTG-BUSL-01', 'Test Business Logic Data Validation', {
        Language.English: 'Test Business Logic Data Validation',
        Language.Spanish: 'Pruebas de validación de datos según la lógica de negocio'
    }
    OTG_BUSLOGIC_002 = 70, 'WSTG-BUSL-02', 'Test Ability to Forge Requests', {
        Language.English: 'Test Ability to Forge Requests',
        Language.Spanish: 'Pruebas de la viabilidad de construir peticiones'
    }
    OTG_BUSLOGIC_003 = 71, 'WSTG-BUSL-03', 'Test Integrity Checks', {
        Language.English: 'Test Integrity Checks',
        Language.Spanish: 'Pruebas sobre los controles de integridad'
    }
    OTG_BUSLOGIC_004 = 72, 'WSTG-BUSL-04', 'Test for Process Timing', {
        Language.English: 'Test for Process Timing',
        Language.Spanish: 'Pruebas sobre timing de procesos'
    }
    OTG_BUSLOGIC_005 = 73, 'WSTG-BUSL-05', 'Test Number of Times a Function Can be Used Limits', {
        Language.English: 'Test Number of Times a Function Can be Used Limits',
        Language.Spanish: 'Pruebas sobre el número de veces que una funcionalidad puede ser llamada/utilizada.'
    }
    OTG_BUSLOGIC_006 = 74, 'WSTG-BUSL-06', 'Testing for the Circumvention of Work Flows', {
        Language.English: 'Testing for the Circumvention of Work Flows',
        Language.Spanish: 'Pruebas de evitar la secuencia correcta de operaciones'
    }
    OTG_BUSLOGIC_007 = 75, 'WSTG-BUSL-07', 'Test Defenses Against Application Misuse', {
        Language.English: 'Test Defenses Against Application Mis-use',
        Language.Spanish: 'Pruebas de defensas contra uso fraudulento de la aplicación'
    }
    OTG_BUSLOGIC_008 = 76, 'WSTG-BUSL-08', 'Test Upload of Unexpected File Types', {
        Language.English: 'Test Upload of Unexpected File Types',
        Language.Spanish: 'Pruebas sobre la subida de ficheros con formato no esperado'
    }
    OTG_BUSLOGIC_009 = 77, 'WSTG-BUSL-09', 'Test Upload of Malicious Files', {
        Language.English: 'Test Upload of Malicious Files',
        Language.Spanish: 'Pruebas de subida de ficheros maliciosos'
    }
    OTG_CLIENT_001 = 78, 'WSTG-CLNT-01', 'Testing for DOM based Cross-Site Scripting', {
        Language.English: 'Testing for DOM based Cross-Site Scripting',
        Language.Spanish: 'Pruebas de Cross-Site Scripting basado en DOM'
    }
    OTG_CLIENT_002 = 79, 'WSTG-CLNT-02', 'Testing for JavaScript Execution', {
        Language.English: 'Testing for JavaScript Execution',
        Language.Spanish: 'Pruebas para la ejecución de código Javascript'
    }
    OTG_CLIENT_003 = 80, 'WSTG-CLNT-03', 'Testing for HTML Injection', {
        Language.English: 'Testing for HTML Injection',
        Language.Spanish: 'Pruebas de inyección HTML'
    }
    OTG_CLIENT_004 = 81, 'WSTG-CLNT-04', 'Testing for Client Side URL Redirect', {
        Language.English: 'Testing for Client Side URL Redirect',
        Language.Spanish: 'Pruebas sobre redirecciones en el lado del cliente'
    }
    OTG_CLIENT_005 = 82, 'WSTG-CLNT-05', 'Testing for CSS Injection', {
        Language.English: 'Testing for CSS Injection',
        Language.Spanish: 'Pruebas de inyección de código CSS'
    }
    OTG_CLIENT_006 = 83, 'WSTG-CLNT-06', 'Testing for Client Side Resource Manipulation', {
        Language.English: 'Testing for Client Side Resource Manipulation',
        Language.Spanish: 'Manipulación de recursos en el lado del cliente'
    }
    OTG_CLIENT_007 = 84, 'WSTG-CLNT-07', 'Test Cross Origin Resource Sharing', {
        Language.English: 'Test Cross Origin Resource Sharing',
        Language.Spanish: 'Pruebas de Cross Origin Resource Sharing (CORS)'
    }
    OTG_CLIENT_008 = 85, 'WSTG-CLNT-08', 'Testing for Cross Site Flashing', {
        Language.English: 'Testing for Cross Site Flashing',
        Language.Spanish: 'Pruebas de Cross Site Flashing'
    }
    OTG_CLIENT_009 = 86, 'WSTG-CLNT-09', 'Testing for Clickjacking', {
        Language.English: 'Testing for Clickjacking',
        Language.Spanish: 'Pruebas de clickjacking'
    }
    OTG_CLIENT_010 = 87, 'WSTG-CLNT-10', 'Testing WebSockets', {
        Language.English: 'Testing WebSockets',
        Language.Spanish: 'Pruebas sobre WebSockets'
    }
    OTG_CLIENT_011 = 88, 'WSTG-CLNT-11', 'Test Web Messaging', {
        Language.English: 'Test Web Messaging',
        Language.Spanish: 'Pruebas sobre mensajería web'
    }
    OTG_CLIENT_012 = 89, 'WSTG-CLNT-12', 'Test Browser Storage', {
        Language.English: 'Test Browser Storage',
        Language.Spanish: 'Pruebas de almacenamiento en el navegador'
    }
    OTG_CLIENT_013 = 93, 'WSTG-CLNT-13', 'Test Cross Site Script Inclusion', {
        Language.English: 'Test Cross Site Script Inclusion',
        Language.Spanish: 'Pruebas de inclusión de XSS'
    }
