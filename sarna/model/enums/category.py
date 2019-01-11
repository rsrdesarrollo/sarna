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
        Language.Spanish: 'Almacenamiento inseguro de datos'
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
        Language.Spanish: 'Calidad del código cliente'
    }
    M8 = 8, 'M8', 'Code Tampering', {
        Language.English: 'Code Tampering',
        Language.Spanish: 'Alteraciones de código'
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
        Language.Spanish: 'Descubrimiento de puntos de acceso'
    }
    DI_002 = 2, 'DI-002', 'Hidden networks discovering', {
        Language.English: 'Hidden networks discovering',
        Language.Spanish: 'Descubrimiento de redes ocultas'
    }
    DI_003 = 3, 'DI-003', 'Passive MAC address identification', {
        Language.English: 'Passive MAC address identification',
        Language.Spanish: 'Identificación pasiva de direcciones MAC'
    }
    DI_004 = 4, 'DI-004', 'Discovering of client Preferred Network Lists (PNL)', {
        Language.English: 'Discovering of client Preferred Network Lists (PNL)',
        Language.Spanish: 'Descubrimiento de redes preferidas de clientes'
    }
    DI_005 = 5, 'DI-005', 'Active device and network discovering', {
        Language.English: 'Active device and network discovering',
        Language.Spanish: 'Descubrimiento activo de clientes y redes'
    }
    DI_006 = 6, 'DI-006', 'Identification of relationships between devices', {
        Language.English: 'Identification of relationships between devices',
        Language.Spanish: 'Identificación de relaciones entre dispositivos'
    }
    FP_001 = 7, 'FP-001', 'Devices identification', {
        Language.English: 'Devices identification',
        Language.Spanish: 'Identificación del dispositivos'
    }
    FP_002 = 8, 'FP-002', 'Identification of device supported functionality', {
        Language.English: 'Identification of device supported functionality',
        Language.Spanish: 'Identificación de funcionalidades soportadas por el dispositivo'
    }
    FP_003 = 9, 'FP-003', 'Enumeration of RADIUS authentication mechanisms (802.1x)', {
        Language.English: 'Enumeration of RADIUS authentication mechanisms (802.1x)',
        Language.Spanish: 'Enumeración de mecanismos de autenticación radius (802.1x)'
    }
    FP_004 = 10, 'FP-004', 'Detection of Rogue APs', {
        Language.English: 'Detection of Rogue APs',
        Language.Spanish: 'Detección de Rogue APs'
    }
    FP_005 = 11, 'FP-005', 'Client isolation tests', {
        Language.English: 'Client isolation tests',
        Language.Spanish: 'Pruebas de client isolation'
    }
    FP_006 = 12, 'FP-006', 'Detection of attacks by Wi-Fi devices', {
        Language.English: 'Detection of attacks by Wi-Fi devices',
        Language.Spanish: 'Detección de ataques por parte de dispositivos Wi-Fi'
    }
    AU_001 = 13, 'AU-001', 'MAC-based access protection detection', {
        Language.English: 'MAC-based access protection detection',
        Language.Spanish: 'Detección de protección de acceso basado en MAC'
    }
    AU_002 = 14, 'AU-002', 'Tests on WPS', {
        Language.English: 'Tests on WPS',
        Language.Spanish: 'Pruebas sobre WPS'
    }
    AU_003 = 15, 'AU-003', 'Downgrade tests of the authentication method', {
        Language.English: 'Downgrade tests of the authentication method',
        Language.Spanish: 'Pruebas de downgrade del método de autenticación'
    }
    AU_004 = 16, 'AU-004', 'Capture and cracking of transmitted keys in the authentication process', {
        Language.English: 'Capture and cracking of transmitted keys in the authentication process',
        Language.Spanish: 'Captura y cracking de claves transmitidas en el proceso de autenticación'
    }
    AU_005 = 17, 'AU-005', 'Use of insecure authentication protocols', {
        Language.English: 'Use of insecure authentication protocols',
        Language.Spanish: 'Uso de protocolos de autenticación inseguros'
    }
    AU_006 = 18, 'AU-006', 'Brute force testing of RADIUS users and passwords (802.1x)', {
        Language.English: 'Brute force testing of RADIUS users and passwords (802.1x)',
        Language.Spanish: 'Pruebas de fuerza bruta de usuarios contraseñas de radius (802.1x)'
    }
    AU_007 = 19, 'AU-007', 'Brute force testing of passwords against the authentication process (PSK)', {
        Language.English: 'Brute force testing of passwords against the authentication process (PSK)',
        Language.Spanish: 'Pruebas de fuerza bruta de contraseñas contra el proceso de autenticación (PSK)'
    }
    AU_008 = 20, 'AU-008', 'Weaknesses in credential repository', {
        Language.English: 'Weaknesses in credential repository',
        Language.Spanish: 'Debilidades en repositorio de credenciales'
    }
    CP_001 = 21, 'CP-001', 'Open network capture and trafic analisys', {
        Language.English: 'Open network capture and trafic analisys',
        Language.Spanish: 'Captura y análisis de tráfico en red abierta'
    }
    CP_002 = 22, 'CP-002', 'Decryption of encrypted traffic', {
        Language.English: 'Decryption of encrypted traffic',
        Language.Spanish: 'Descifrado de trafico cifrado'
    }
    CP_003 = 23, 'CP-003', 'Tests of analysis of information transmitted through Wireless', {
        Language.English: 'Tests of analysis of information transmitted through Wireless',
        Language.Spanish: 'Pruebas de análisis de información transmitida a través de Wireless'
    }
    CP_004 = 24, 'CP-004', 'Analysis of insecure encryption protocols', {
        Language.English: 'Analysis of insecure encryption protocols',
        Language.Spanish: 'Análisis de protocolos de cifrado inseguro'
    }
    CP_005 = 25, 'CP-005', 'Renewal tests for encryption keys', {
        Language.English: 'Renewal tests for encryption keys',
        Language.Spanish: 'Pruebas de renovación de claves de cifrado'
    }
    CP_006 = 26, 'CP-006', 'Traffic re-injection tests', {
        Language.English: 'Traffic re-injection tests',
        Language.Spanish: 'Pruebas de re-inyección de tráfico'
    }
    CF_001 = 27, 'CF-001', 'Identification of wireless networks with generic ESSID', {
        Language.English: 'Identification of wireless networks with generic ESSID',
        Language.Spanish: 'Identificación de redes wireless con ESSID genérico'
    }
    CF_002 = 28, 'CF-002', 'Generic passwords in the administrative interface of the access point', {
        Language.English: 'Generic passwords in the administrative interface of the access point',
        Language.Spanish: 'Contraseñas genéricas en interfaz administrativa del punto de acceso'
    }
    CF_003 = 29, 'CF-003', 'Verification of signal strength level or coverage area', {
        Language.English: 'Verification of signal strength level or coverage area',
        Language.Spanish: 'Verificación del nivel de intensidad de señal o área de cobertura'
    }
    CF_004 = 30, 'CF-004', 'Analysis of the overlap of networks in the same communications channel', {
        Language.English: 'Analysis of the overlap of networks in the same communications channel',
        Language.Spanish: 'Análisis del solapamiento de redes en el mismo canal de comunicaciones'
    }
    CF_005 = 31, 'CF-005', 'Generation of keys based on known algorithms', {
        Language.English: 'Generation of keys based on known algorithms',
        Language.Spanish: 'Generación de claves en base a algoritmos conocidos'
    }
    CF_006 = 32, 'CF-006', 'Tests on UPnP', {
        Language.English: 'Tests on UPnP',
        Language.Spanish: 'Pruebas sobre Upnp'
    }
    IF_001 = 33, 'IF-001', 'Weaknesses in the AP firmware', {
        Language.English: 'Weaknesses in the AP firmware',
        Language.Spanish: 'Debilidades en el firmware del AP'
    }
    IF_002 = 34, 'IF-002', 'Administrative interfaces exposed to the network', {
        Language.English: 'Administrative interfaces exposed to the network',
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
    IF_005 = 37, 'IF-005', 'Verification tests of VPN tunnels', {
        Language.English: 'Verification tests of VPN tunnels',
        Language.Spanish: 'Pruebas de verificación de túneles VPN'
    }
    IF_006 = 38, 'IF-006', 'Weaknesses in RADIUS server', {
        Language.English: 'Weaknesses in RADIUS server',
        Language.Spanish: 'Debilidades en servidor radius'
    }
    IF_007 = 39, 'IF-007', 'Vulnerabilities incubated', {
        Language.English: 'Vulnerabilities incubated',
        Language.Spanish: 'Vulnerabilidades incubadas'
    }
    IF_008 = 40, 'IF-008', 'Management of keys and certificates life cycle', {
        Language.English: 'Management of keys and certificates life cycle',
        Language.Spanish: 'Gestión del ciclo de vida de claves y certificados'
    }
    IF_009 = 41, 'IF-009', 'Accessible / physically exposed communication devices', {
        Language.English: 'Accessible / physically exposed communication devices',
        Language.Spanish: 'Dispositivos de comunicaciones accesible/expuestos físicamente'
    }
    IF_010 = 42, 'IF-010', 'Detection and analysis of SCADA systems', {
        Language.English: 'Detection and analysis of SCADA systems',
        Language.Spanish: 'Detección y análisis de sistemas SCADA'
    }
    DS_001 = 43, 'DS-001', 'Deauthentication tests', {
        Language.English: 'Deauthentication tests',
        Language.Spanish: 'Pruebas de deautenticación'
    }
    DS_002 = 44, 'DS-002', 'Saturation of the communications channel', {
        Language.English: 'Saturation of the communications channel',
        Language.Spanish: 'Saturación del canal de comunicaciones'
    }
    DS_003 = 45, 'DS-003', 'Blocking user accounts', {
        Language.English: 'Blocking user accounts',
        Language.Spanish: 'Bloqueo de cuentas de usuario'
    }
    DS_004 = 46, 'DS-004', 'Communication device lock', {
        Language.English: 'Communication device lock',
        Language.Spanish: 'Bloqueo de dispositivo de comunicaciones'
    }
    DS_005 = 47, 'DS-005', 'Degradation tests of the communications channel', {
        Language.English: 'Degradation tests of the communications channel',
        Language.Spanish: 'Pruebas de degradación del canal de comunicaciones'
    }
    GD_001 = 48, 'GD-001', 'Identification of devices that do not meet the standard / owners', {
        Language.English: 'Identification of devices that do not meet the standard / owners',
        Language.Spanish: 'Identificación de dispositivos que no cumplen el estándar / propietarios'
    }
    GD_002 = 49, 'GD-002', 'Detection of devices emitting at restricted frequencies', {
        Language.English: 'Detection of devices emitting at restricted frequencies',
        Language.Spanish: 'Detección de dispositivos emitiendo en frecuencias restringidas'
    }
    GD_003 = 50, 'GD-003', 'Analysis of the policy of use / restriction of use of wireless networks', {
        Language.English: 'Analysis of the policy of use / restriction of use of wireless networks',
        Language.Spanish: 'Análisis de la política de uso/restricción de uso de redes inalámbricas'
    }
    GD_004 = 51, 'GD-004', 'Analysis of device configuration', {
        Language.English: 'Analysis of device configuration',
        Language.Spanish: 'Análisis de la configuración de dispositivos'
    }
    GD_005 = 52, 'GD-005', 'Analysis of the management policy and change of keys', {
        Language.English: 'Analysis of the management policy and change of keys',
        Language.Spanish: 'Análisis de la política de gestión y cambio de claves'
    }
    GD_006 = 53, 'GD-006', 'Verification of authorized devices inventory', {
        Language.English: 'Verification of authorized devices inventory',
        Language.Spanish: 'Verificación de inventario de dispositivos autorizados'
    }
    CT_001 = 54, 'CT-001', 'Rogue AP tests and automatic association', {
        Language.English: 'Rogue AP tests and automatic association',
        Language.Spanish: 'Pruebas de Rogue Ap y asociación automática'
    }
    CT_002 = 55, 'CT-002', 'Analysis of APTs (Advanced Persistent Threats) on Wireless', {
        Language.English: 'Analysis of APTs (Advanced Persistent Threats) on Wireless',
        Language.Spanish: 'Analisis de APTs (Advanced Persistent Threats) sobre Wireless'
    }
    CT_003 = 56, 'CT-003', 'Client buffer overflow', {
        Language.English: 'Client buffer overflow',
        Language.Spanish: 'Desbordamiento de buffer en cliente'
    }
    CT_004 = 57, 'CT-004', 'Extraction of user identifiers (802.1x)', {
        Language.English: 'Extraction of user identifiers (802.1x)',
        Language.Spanish: 'Extracción de identificadores de usuarios (802.1x)'
    }
    CT_005 = 58, 'CT-005', 'Tests on weak or insecure supplicant', {
        Language.English: 'Tests on weak or insecure supplicant',
        Language.Spanish: 'Pruebas sobre suplicant débil o inseguro'
    }
    CT_006 = 59, 'CT-006', 'Attacks against clients', {
        Language.English: 'Attacks against clients',
        Language.Spanish: 'Ataques contra clientes'
    }
    CT_007 = 60, 'CT-007', 'Removing customer credentials', {
        Language.English: 'Removing customer credentials',
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
    HS_003 = 63, 'HS-003', 'Evidence of encapsulation of traffic with the exterior', {
        Language.English: 'Evidence of encapsulation of traffic with the exterior',
        Language.Spanish: 'Pruebas de encapsulación de tráfico con el exterior'
    }
    HS_004 = 64, 'HS-004', 'Weakness in captive portal', {
        Language.English: 'Weakness in captive portal',
        Language.Spanish: 'Debilidades en portal cautivo'
    }


class OWASPCategory(BaseChoice):
    _init_ = "value code desc translation"
    OTG_INFO_001 = 1, 'OTG-INFO-001', 'Conduct Search Engine Discovery and Reconnaissance for Information Leakage', {
        Language.English: 'Conduct Search Engine Discovery and Reconnaissance for Information Leakage',
        Language.Spanish: 'Identificación y reconocimiento a través de motores de búsqueda'
    }
    OTG_INFO_002 = 2, 'OTG-INFO-002', 'Fingerprint Web Server', {
        Language.English: 'Fingerprint Web Server',
        Language.Spanish: 'Identificación del servidor Web'
    }
    OTG_INFO_003 = 3, 'OTG-INFO-003', 'Review Webserver Metafiles for Information Leakage', {
        Language.English: 'Review Webserver Metafiles for Information Leakage',
        Language.Spanish: 'Identificación de fugas de información en metaficheros'
    }
    OTG_INFO_004 = 4, 'OTG-INFO-004', 'Enumerate Applications on Webserver', {
        Language.English: 'Enumerate Applications on Webserver',
        Language.Spanish: 'Enumeración de aplicaciones en el servidor web'
    }
    OTG_INFO_005 = 5, 'OTG-INFO-005', 'Review Webpage Comments and Metadata for Information Leakage', {
        Language.English: 'Review Webpage Comments and Metadata for Information Leakage',
        Language.Spanish: 'Identificación de fugas de información en comentarios y metadatos de las páginas web'
    }
    OTG_INFO_006 = 6, 'OTG-INFO-006', 'Identify application entry points', {
        Language.English: 'Identify application entry points',
        Language.Spanish: 'Identificación de puntos de entrada en la aplicación'
    }
    OTG_INFO_007 = 7, 'OTG-INFO-007', 'Map execution paths through application', {
        Language.English: 'Map execution paths through application',
        Language.Spanish: 'Identificación de rutas de la aplicación'
    }
    OTG_INFO_008 = 8, 'OTG-INFO-008', 'Fingerprint Web Application Framework', {
        Language.English: 'Fingerprint Web Application Framework',
        Language.Spanish: 'Identificación del framework de la aplicación Web'
    }
    OTG_INFO_009 = 9, 'OTG-INFO-009', 'Fingerprint Web Application', {
        Language.English: 'Fingerprint Web Application',
        Language.Spanish: 'Identificación de la aplicación Web'
    }
    OTG_INFO_010 = 10, 'OTG-INFO-010', 'Map Application Architecture', {
        Language.English: 'Map Application Architecture',
        Language.Spanish: 'Mapeo de arquitectura de red y de aplicación'
    }
    OTG_CONFIG_001 = 11, 'OTG-CONFIG-001', 'Test Network/Infrastructure Configuration', {
        Language.English: 'Test Network/Infrastructure Configuration',
        Language.Spanish: 'Pruebas de configuración de red y de infraestructura'
    }
    OTG_CONFIG_002 = 12, 'OTG-CONFIG-002', 'Test Application Platform Configuration', {
        Language.English: 'Test Application Platform Configuration',
        Language.Spanish: 'Pruebas de configuración de la plataforma de la aplicación'
    }
    OTG_CONFIG_003 = 13, 'OTG-CONFIG-003', 'Test File Extensions Handling for Sensitive Information', {
        Language.English: 'Test File Extensions Handling for Sensitive Information',
        Language.Spanish: 'Extracción de información sensible en la gestión de extensiones'
    }
    OTG_CONFIG_004 = 14, 'OTG-CONFIG-004', 'Backup and Unreferenced Files for Sensitive Information', {
        Language.English: 'Backup and Unreferenced Files for Sensitive Information',
        Language.Spanish: 'Búsqueda de información sensible en ficheros no referenciados, antiguos y copias de seguridad'
    }
    OTG_CONFIG_005 = 15, 'OTG-CONFIG-005', 'Enumerate Infrastructure and Application Admin Interfaces', {
        Language.English: 'Enumerate Infrastructure and Application Admin Interfaces',
        Language.Spanish: 'Enumeración de interfaces administrativas de aplicación y la infraestructura'
    }
    OTG_CONFIG_006 = 16, 'OTG-CONFIG-006', 'Test HTTP Methods', {
        Language.English: 'Test HTTP Methods',
        Language.Spanish: 'Análisis de métodos HTTP'
    }
    OTG_CONFIG_007 = 17, 'OTG-CONFIG-007', 'Test HTTP Strict Transport Security', {
        Language.English: 'Test HTTP Strict Transport Security',
        Language.Spanish: 'Pruebas sobre políticas de seguridad (HTTP Strict Transport Security)'
    }
    OTG_CONFIG_008 = 18, 'OTG-CONFIG-008', 'Test RIA cross domain policy', {
        Language.English: 'Test RIA cross domain policy',
        Language.Spanish: 'Pruebas de políticas cross domain RIA (Rich Internet Applications)'
    }
    OTG_CONFIG_009 = 90, 'OTG-CONFIG-009', 'Test file permissions', {
        Language.English: 'Test file permissions',
        Language.Spanish: 'Pruebas de permisos de ficheros'
    }
    OTG_IDENT_001 = 19, 'OTG-IDENT-001', 'Test Role Definitions', {
        Language.English: 'Test Role Definitions',
        Language.Spanish: 'Análisis de definición de roles'
    }
    OTG_IDENT_002 = 20, 'OTG-IDENT-002', 'Test User Registration Process', {
        Language.English: 'Test User Registration Process',
        Language.Spanish: 'Análisis del proceso de registro de usuario'
    }
    OTG_IDENT_003 = 21, 'OTG-IDENT-003', 'Test Account Provisioning Process', {
        Language.English: 'Test Account Provisioning Process',
        Language.Spanish: 'Pruebas sobre procesos de aprovisionamiento de cuentas'
    }
    OTG_IDENT_004 = 22, 'OTG-IDENT-004', 'Testing for Account Enumeration and Guessable User Account', {
        Language.English: 'Testing for Account Enumeration and Guessable User Account',
        Language.Spanish: 'Pruebas de identificación y enumeración de cuentas de usuario'
    }
    OTG_IDENT_005 = 23, 'OTG-IDENT-005', 'Testing for Weak or unenforced username policy', {
        Language.English: 'Testing for Weak or unenforced username policy',
        Language.Spanish: 'Pruebas sobre identificadores de usuario débiles'
    }
    OTG_IDENT_006 = 24, 'OTG-IDENT-006', 'Test Permissions of Guest/Training Accounts', {
        Language.English: 'Test Permissions of Guest/Training Accounts',
        Language.Spanish: 'Pruebas de permisos de cuentas de prueba o invitado'
    }
    OTG_IDENT_007 = 25, 'OTG-IDENT-007', 'Test Account Suspension/Resumption Process', {
        Language.English: 'Test Account Suspension/Resumption Process',
        Language.Spanish: 'Pruebas en el proceso de suspensión y reanudación'
    }
    OTG_AUTHN_001 = 26, 'OTG-AUTHN-001', 'Testing for Credentials Transported over an Encrypted Channel', {
        Language.English: 'Testing for Credentials Transported over an Encrypted Channel',
        Language.Spanish: 'Pruebas transmisión de credenciales por un canal sin cifrado'
    }
    OTG_AUTHN_002 = 27, 'OTG-AUTHN-002', 'Testing for default credentials', {
        Language.English: 'Testing for default credentials',
        Language.Spanish: 'Pruebas de credenciales por defecto'
    }
    OTG_AUTHN_003 = 28, 'OTG-AUTHN-003', 'Testing for Weak lock out mechanism', {
        Language.English: 'Testing for Weak lock out mechanism',
        Language.Spanish: 'Pruebas sobre sistemas de bloqueo de cuentas débil'
    }
    OTG_AUTHN_004 = 29, 'OTG-AUTHN-004', 'Testing for bypassing authentication schema', {
        Language.English: 'Testing for bypassing authentication schema',
        Language.Spanish: 'Pruebas de evitar los mecanismos de autenticación'
    }
    OTG_AUTHN_005 = 30, 'OTG-AUTHN-005', 'Test remember password functionality', {
        Language.English: 'Test remember password functionality',
        Language.Spanish: 'Pruebas sobre los mecanismos de recordatorio de contraseña'
    }
    OTG_AUTHN_006 = 31, 'OTG-AUTHN-006', 'Testing for Browser cache weakness', {
        Language.English: 'Testing for Browser cache weakness',
        Language.Spanish: 'Pruebas de debilidades en la cache del navegador'
    }
    OTG_AUTHN_007 = 32, 'OTG-AUTHN-007', 'Testing for Weak password policy', {
        Language.English: 'Testing for Weak password policy',
        Language.Spanish: 'Pruebas sobre políticas de contraseñas débiles'
    }
    OTG_AUTHN_008 = 33, 'OTG-AUTHN-008', 'Testing for Weak security question/answer', {
        Language.English: 'Testing for Weak security question/answer',
        Language.Spanish: 'Pruebas sobre preguntas y respuestas de seguridad'
    }
    OTG_AUTHN_009 = 34, 'OTG-AUTHN-009', 'Testing for weak password change or reset functionalities', {
        Language.English: 'Testing for weak password change or reset functionalities',
        Language.Spanish: 'Pruebas sobre mecanismos de cambio y recuperación de contraseña'
    }
    OTG_AUTHN_010 = 35, 'OTG-AUTHN-010', 'Testing for Weaker authentication in alternative channel', {
        Language.English: 'Testing for Weaker authentication in alternative channel',
        Language.Spanish: 'Pruebas de autenticación débil en canales alternativos'
    }
    OTG_AUTHZ_001 = 36, 'OTG-AUTHZ-001', 'Testing Directory traversal/file include', {
        Language.English: 'Testing Directory traversal/file include',
        Language.Spanish: 'Pruebas de directorio transversal e inclusión de ficheros'
    }
    OTG_AUTHZ_002 = 37, 'OTG-AUTHZ-002', 'Testing for bypassing authorization schema', {
        Language.English: 'Testing for bypassing authorization schema',
        Language.Spanish: 'Pruebas para evitar el esquema de autorización'
    }
    OTG_AUTHZ_003 = 38, 'OTG-AUTHZ-003', 'Testing for Privilege Escalation', {
        Language.English: 'Testing for Privilege Escalation',
        Language.Spanish: 'Pruebas de elevación de privilegios'
    }
    OTG_AUTHZ_004 = 39, 'OTG-AUTHZ-004', 'Testing for Insecure Direct Object References', {
        Language.English: 'Testing for Insecure Direct Object References',
        Language.Spanish: 'Pruebas de referencias directas inseguras a objetos'
    }
    OTG_SESS_001 = 40, 'OTG-SESS-001', 'Testing for Bypassing Session Management Schema', {
        Language.English: 'Testing for Bypassing Session Management Schema',
        Language.Spanish: 'Pruebas de evitar el mecanismo de gestión de sesiones'
    }
    OTG_SESS_002 = 41, 'OTG-SESS-002', 'Testing for Cookies attributes', {
        Language.English: 'Testing for Cookies attributes',
        Language.Spanish: 'Pruebas de los atributos de cookies de sesión'
    }
    OTG_SESS_003 = 42, 'OTG-SESS-003', 'Testing for Session Fixation', {
        Language.English: 'Testing for Session Fixation',
        Language.Spanish: 'Pruebas de fijación de sesiones'
    }
    OTG_SESS_004 = 43, 'OTG-SESS-004', 'Testing for Exposed Session Variables', {
        Language.English: 'Testing for Exposed Session Variables',
        Language.Spanish: 'Pruebas sobre la exposición de variables de sesión'
    }
    OTG_SESS_005 = 44, 'OTG-SESS-005', 'Testing for Cross Site Request Forgery', {
        Language.English: 'Testing for Cross Site Request Forgery',
        Language.Spanish: 'Pruebas de Cross Site Request forgery (CSRF)'
    }
    OTG_SESS_006 = 45, 'OTG-SESS-006', 'Testing for logout functionality', {
        Language.English: 'Testing for logout functionality',
        Language.Spanish: 'Pruebas sobre la funcionalidad de cierre de sesión'
    }
    OTG_SESS_007 = 46, 'OTG-SESS-007', 'Test Session Timeout', {
        Language.English: 'Test Session Timeout',
        Language.Spanish: 'Pruebas sobre la caducidad de la sesión'
    }
    OTG_SESS_008 = 47, 'OTG-SESS-008', 'Testing for Session puzzling', {
        Language.English: 'Testing for Session puzzling',
        Language.Spanish: 'Pruebas de puzzling de sesión'
    }
    OTG_INPVAL_001 = 48, 'OTG-INPVAL-001', 'Testing for Reflected Cross Site Scripting', {
        Language.English: 'Testing for Reflected Cross Site Scripting',
        Language.Spanish: 'Pruebas de Cross Site Scripting reflejado'
    }
    OTG_INPVAL_002 = 49, 'OTG-INPVAL-002', 'Testing for Stored Cross Site Scripting', {
        Language.English: 'Testing for Stored Cross Site Scripting',
        Language.Spanish: 'Pruebas de Cross Site Scripting almacenado'
    }
    OTG_INPVAL_003 = 50, 'OTG-INPVAL-003', 'Testing for HTTP Verb Tampering', {
        Language.English: 'Testing for HTTP Verb Tampering',
        Language.Spanish: 'Pruebas de manipulación de verbos en HTTP'
    }
    OTG_INPVAL_004 = 51, 'OTG-INPVAL-004', 'Testing for HTTP Parameter pollution', {
        Language.English: 'Testing for HTTP Parameter pollution',
        Language.Spanish: 'Pruebas de polución de parámetros en HTTP'
    }
    OTG_INPVAL_005 = 52, 'OTG-INPVAL-005', 'Testing for SQL Injection', {
        Language.English: 'Testing for SQL Injection',
        Language.Spanish: 'Pruebas de inyección SQL'
    }
    OTG_INPVAL_006 = 53, 'OTG-INPVAL-006', 'Testing for LDAP Injection', {
        Language.English: 'Testing for LDAP Injection',
        Language.Spanish: 'Pruebas de inyección LDAP'
    }
    OTG_INPVAL_007 = 54, 'OTG-INPVAL-007', 'Testing for ORM Injection', {
        Language.English: 'Testing for ORM Injection',
        Language.Spanish: 'Pruebas de inyección ORM'
    }
    OTG_INPVAL_008 = 55, 'OTG-INPVAL-008', 'Testing for XML Injection', {
        Language.English: 'Testing for XML Injection',
        Language.Spanish: 'Pruebas de inyección XML'
    }
    OTG_INPVAL_009 = 56, 'OTG-INPVAL-009', 'Testing for SSI Injection', {
        Language.English: 'Testing for SSI Injection',
        Language.Spanish: 'Pruebas de inyección SSI'
    }
    OTG_INPVAL_010 = 57, 'OTG-INPVAL-010', 'Testing for XPath Injection', {
        Language.English: 'Testing for XPath Injection',
        Language.Spanish: 'Pruebas de inyección XPATH'
    }
    OTG_INPVAL_011 = 58, 'OTG-INPVAL-011', 'IMAP/SMTP Injection', {
        Language.English: 'IMAP/SMTP Injection',
        Language.Spanish: 'Pruebas de inyección IMAP/SMTP'
    }
    OTG_INPVAL_012 = 59, 'OTG-INPVAL-012', 'Testing for Code Injection', {
        Language.English: 'Testing for Code Injection',
        Language.Spanish: 'Pruebas de inyección de código (LFI/RFI)'
    }
    OTG_INPVAL_013 = 60, 'OTG-INPVAL-013', 'Testing for Command Injection', {
        Language.English: 'Testing for Command Injection',
        Language.Spanish: 'Pruebas de inyección de comandos'
    }
    OTG_INPVAL_014 = 61, 'OTG-INPVAL-014', 'Testing for Buffer overflow', {
        Language.English: 'Testing for Buffer overflow',
        Language.Spanish: 'Pruebas de desbordamiento de buffer'
    }
    OTG_INPVAL_015 = 62, 'OTG-INPVAL-015', 'Testing for incubated vulnerabilities', {
        Language.English: 'Testing for incubated vulnerabilities',
        Language.Spanish: 'Pruebas de vulnerabilidad incubada'
    }
    OTG_INPVAL_016 = 63, 'OTG-INPVAL-016', 'Testing for HTTP Splitting/Smuggling', {
        Language.English: 'Testing for HTTP Splitting/Smuggling',
        Language.Spanish: 'Pruebas de HTTP Splitting/Smuggling'
    }
    OTG_INPVAL_017 = 91, 'OTG-INPVAL-017', 'Testing for HTTP Incomming Requests', {
        Language.English: 'Testing for HTTP Incomming Requests',
        Language.Spanish: 'Pruebas de peticiones HTTP entrantes'
    }
    OTG_ERR_001 = 64, 'OTG-ERR-001', 'Analysis of Error Codes', {
        Language.English: 'Analysis of Error Codes',
        Language.Spanish: 'Análisis de códigos de error'
    }
    OTG_ERR_002 = 65, 'OTG-ERR-002', 'Analysis of Stack Traces', {
        Language.English: 'Analysis of Stack Traces',
        Language.Spanish: 'Análisis de las trazas de depuración'
    }
    OTG_CRYPST_001 = 66, 'OTG-CRYPST-001', 'Testing for Weak SSL/TLS Ciphers, Insufficient Transport Layer Protection', {
        Language.English: 'Testing for Weak SSL/TLS Ciphers, Insufficient Transport Layer Protection',
        Language.Spanish: 'Pruebas de uso de esquemas cifrado débiles o protección insuficiente de la capa de transporte'
    }
    OTG_CRYPST_002 = 67, 'OTG-CRYPST-002', 'Testing for Padding Oracle', {
        Language.English: 'Testing for Padding Oracle',
        Language.Spanish: 'Pruebas de padding en Oracle'
    }
    OTG_CRYPST_003 = 68, 'OTG-CRYPST-003', 'Testing for Sensitive information sent via unencrypted channels', {
        Language.English: 'Testing for Sensitive information sent via unencrypted channels',
        Language.Spanish: 'Pruebas de transmisión de información sensible a través de canales sin cifrar'
    }
    OTG_CRYPST_004 = 92, 'OTG-CRYPST-004', 'Testing for Weak Encryption', {
        Language.English: 'Testing for Weak Encryption',
        Language.Spanish: 'Pruebas de cifrado débil'
    }
    OTG_BUSLOGIC_001 = 69, 'OTG-BUSLOGIC-001', 'Test Business Logic Data Validation', {
        Language.English: 'Test Business Logic Data Validation',
        Language.Spanish: 'Pruebas de validación de datos según la lógica de negocio'
    }
    OTG_BUSLOGIC_002 = 70, 'OTG-BUSLOGIC-002', 'Test Ability to Forge Requests', {
        Language.English: 'Test Ability to Forge Requests',
        Language.Spanish: 'Pruebas de la viabilidad de construir peticiones'
    }
    OTG_BUSLOGIC_003 = 71, 'OTG-BUSLOGIC-003', 'Test Integrity Checks', {
        Language.English: 'Test Integrity Checks',
        Language.Spanish: 'Pruebas sobre los controles de integridad'
    }
    OTG_BUSLOGIC_004 = 72, 'OTG-BUSLOGIC-004', 'Test for Process Timing', {
        Language.English: 'Test for Process Timing',
        Language.Spanish: 'Pruebas sobre “timing” de procesos'
    }
    OTG_BUSLOGIC_005 = 73, 'OTG-BUSLOGIC-005', 'Test Number of Times a Function Can be Used Limits', {
        Language.English: 'Test Number of Times a Function Can be Used Limits',
        Language.Spanish: 'Pruebas sobre número de veces que una funcionalidad puede ser llamada/utilizada.'
    }
    OTG_BUSLOGIC_006 = 74, 'OTG-BUSLOGIC-006', 'Testing for the Circumvention of Work Flows', {
        Language.English: 'Testing for the Circumvention of Work Flows',
        Language.Spanish: 'Pruebas de evitar la secuencia correcta de operaciones'
    }
    OTG_BUSLOGIC_007 = 75, 'OTG-BUSLOGIC-007', 'Test Defenses Against Application Mis-use', {
        Language.English: 'Test Defenses Against Application Mis-use',
        Language.Spanish: 'Pruebas de defensas contra uso fraudulento de la aplicación'
    }
    OTG_BUSLOGIC_008 = 76, 'OTG-BUSLOGIC-008', 'Test Upload of Unexpected File Types', {
        Language.English: 'Test Upload of Unexpected File Types',
        Language.Spanish: 'Pruebas sobre la subida de ficheros con formato no esperado'
    }
    OTG_BUSLOGIC_009 = 77, 'OTG-BUSLOGIC-009', 'Test Upload of Malicious Files', {
        Language.English: 'Test Upload of Malicious Files',
        Language.Spanish: 'Pruebas de subida de ficheros maliciosos'
    }
    OTG_CLIENT_001 = 78, 'OTG-CLIENT-001', 'Testing for DOM based Cross Site Scripting', {
        Language.English: 'Testing for DOM based Cross Site Scripting',
        Language.Spanish: 'Pruebas de Cross Site Scripting basado en DOM'
    }
    OTG_CLIENT_002 = 79, 'OTG-CLIENT-002', 'Testing for JavaScript Execution', {
        Language.English: 'Testing for JavaScript Execution',
        Language.Spanish: 'Pruebas para la ejecución de código Javascript'
    }
    OTG_CLIENT_003 = 80, 'OTG-CLIENT-003', 'Testing for HTML Injection', {
        Language.English: 'Testing for HTML Injection',
        Language.Spanish: 'Pruebas de inyección HTML'
    }
    OTG_CLIENT_004 = 81, 'OTG-CLIENT-004', 'Testing for Client Side URL Redirect', {
        Language.English: 'Testing for Client Side URL Redirect',
        Language.Spanish: 'Pruebas sobre redirecciones en el lado del cliente'
    }
    OTG_CLIENT_005 = 82, 'OTG-CLIENT-005', 'Testing for CSS Injection', {
        Language.English: 'Testing for CSS Injection',
        Language.Spanish: 'Pruebas de inyección de código CSS'
    }
    OTG_CLIENT_006 = 83, 'OTG-CLIENT-006', 'Testing for Client Side Resource Manipulation', {
        Language.English: 'Testing for Client Side Resource Manipulation',
        Language.Spanish: 'Manipulación de recursos en el lado del cliente'
    }
    OTG_CLIENT_007 = 84, 'OTG-CLIENT-007', 'Test Cross Origin Resource Sharing', {
        Language.English: 'Test Cross Origin Resource Sharing',
        Language.Spanish: 'Pruebas de Cross Origin Resource Sharing'
    }
    OTG_CLIENT_008 = 85, 'OTG-CLIENT-008', 'Testing for Cross Site Flashing', {
        Language.English: 'Testing for Cross Site Flashing',
        Language.Spanish: 'Pruebas de Cross Site Flashing'
    }
    OTG_CLIENT_009 = 86, 'OTG-CLIENT-009', 'Testing for Clickjacking', {
        Language.English: 'Testing for Clickjacking',
        Language.Spanish: 'Pruebas de Clickjacking'
    }
    OTG_CLIENT_010 = 87, 'OTG-CLIENT-010', 'Testing WebSockets', {
        Language.English: 'Testing WebSockets',
        Language.Spanish: 'Pruebas sobre WebSockets'
    }
    OTG_CLIENT_011 = 88, 'OTG-CLIENT-011', 'Test Web Messaging', {
        Language.English: 'Test Web Messaging',
        Language.Spanish: 'Pruebas sobre mensajería web'
    }
    OTG_CLIENT_012 = 89, 'OTG-CLIENT-012', 'Test Local Storage', {
        Language.English: 'Test Local Storage',
        Language.Spanish: 'Pruebas de almacenamiento local'
    }
