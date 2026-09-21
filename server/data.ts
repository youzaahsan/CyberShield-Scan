export interface DbUser {
  id: number;
  username: string;
  email: string;
  passwordHash: string; // Plain/hash match for sandbox credentials
  role: 'Admin' | 'Security Analyst' | 'Viewer';
  is_active: boolean;
  created_at: string;
  last_login?: string;
}

export interface DbScan {
  id: number;
  name: string;
  target: string;
  profile: 'Top 20' | 'Top 100' | 'Top 1000' | 'Common Ports' | 'Custom Ports' | 'Full Range';
  custom_ports?: string;
  status: 'Pending' | 'Running' | 'Paused' | 'Completed' | 'Failed' | 'Cancelled';
  progress_percentage: number;
  current_phase: string;
  hosts_discovered: number;
  hosts_scanned: number;
  ports_scanned: number;
  services_detected: number;
  vulnerabilities_found: number;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  error_message?: string;
}

export interface DbPort {
  id: number;
  host_id: number;
  port_number: number;
  protocol: string;
  state: string;
  service_name: string;
  product?: string;
  version?: string;
  banner?: string;
  tls_version?: string;
  tls_cipher?: string;
  http_server_header?: string;
  missing_headers?: string;
}

export interface DbHost {
  id: number;
  scan_id: number;
  ip_address: string;
  hostname?: string;
  mac_address?: string;
  status: string;
  os_name: string;
  os_confidence: string;
  os_evidence?: string;
  risk_score: number;
  risk_level: 'LOW' | 'MODERATE' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  discovered_at: string;
  last_seen: string;
  ports?: DbPort[];
  vulnerabilities?: DbVulnerability[];
}

export interface DbVulnerability {
  id: number;
  finding_id: string;
  cve_id?: string;
  host_id: number;
  port_id?: number;
  service?: string;
  detected_version?: string;
  title: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  cvss: number;
  confidence: 'Confirmed' | 'Likely' | 'Potential';
  description: string;
  evidence: string;
  impact: string;
  recommendation: string;
  status: 'Open' | 'In Progress' | 'Resolved' | 'Accepted Risk' | 'False Positive';
  first_detected: string;
  last_detected: string;
}

export interface DbCVE {
  id: number;
  cve_id: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  cvss: number;
  cvss_vector?: string;
  vendor?: string;
  product?: string;
  affected_versions?: string;
  cwe?: string;
  references?: string;
  published_date?: string;
}

export interface DbAlert {
  id: number;
  title: string;
  severity: string;
  message: string;
  created_at: string;
  is_read: boolean;
}

export const initialUsers: DbUser[] = [
  {
    id: 1,
    username: 'admin',
    email: 'admin@cybershield.internal.net',
    passwordHash: 'AdminPass123!',
    role: 'Admin',
    is_active: true,
    created_at: '2026-09-01T08:00:00Z',
  },
  {
    id: 2,
    username: 'analyst',
    email: 'analyst@cybershield.internal.net',
    passwordHash: 'AnalystPass123!',
    role: 'Security Analyst',
    is_active: true,
    created_at: '2026-09-05T10:30:00Z',
  },
  {
    id: 3,
    username: 'viewer',
    email: 'viewer@cybershield.internal.net',
    passwordHash: 'ViewerPass123!',
    role: 'Viewer',
    is_active: true,
    created_at: '2026-09-10T14:15:00Z',
  },
];

export const initialScans: DbScan[] = [
  {
    id: 1,
    name: 'Production Core Perimeter Sweep',
    target: '192.168.1.0/24',
    profile: 'Top 100',
    status: 'Completed',
    progress_percentage: 100,
    current_phase: 'Completed',
    hosts_discovered: 6,
    hosts_scanned: 6,
    ports_scanned: 600,
    services_detected: 18,
    vulnerabilities_found: 11,
    created_at: new Date(Date.now() - 3600000 * 4).toISOString(),
    started_at: new Date(Date.now() - 3600000 * 4).toISOString(),
    completed_at: new Date(Date.now() - 3600000 * 3.8).toISOString(),
  },
  {
    id: 2,
    name: 'Domain Controller Deep Audit',
    target: '192.168.1.10',
    profile: 'Top 1000',
    status: 'Completed',
    progress_percentage: 100,
    current_phase: 'Completed',
    hosts_discovered: 1,
    hosts_scanned: 1,
    ports_scanned: 1000,
    services_detected: 6,
    vulnerabilities_found: 3,
    created_at: new Date(Date.now() - 3600000 * 24).toISOString(),
    started_at: new Date(Date.now() - 3600000 * 24).toISOString(),
    completed_at: new Date(Date.now() - 3600000 * 23.6).toISOString(),
  }
];

export const initialHosts: DbHost[] = [
  {
    id: 1,
    scan_id: 1,
    ip_address: '192.168.1.1',
    hostname: 'gw-core-edge01.internal',
    mac_address: '00:1A:2B:3C:4D:01',
    status: 'UP',
    os_name: 'Linux 5.15 (EdgeOS / VyOS)',
    os_confidence: '94%',
    os_evidence: 'TCP window size 64240, TTL 64, SYN-ACK fingerprint',
    risk_score: 18,
    risk_level: 'LOW',
    discovered_at: '2026-09-16T10:00:00Z',
    last_seen: new Date().toISOString(),
    ports: [
      {
        id: 101,
        host_id: 1,
        port_number: 22,
        protocol: 'TCP',
        state: 'OPEN',
        service_name: 'ssh',
        product: 'OpenSSH',
        version: '8.9p1 Ubuntu',
        banner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4'
      },
      {
        id: 102,
        host_id: 1,
        port_number: 53,
        protocol: 'TCP',
        state: 'OPEN',
        service_name: 'domain',
        product: 'dnsmasq',
        version: '2.86',
        banner: 'dnsmasq-2.86 caching DNS forwarder'
      },
      {
        id: 103,
        host_id: 1,
        port_number: 443,
        protocol: 'TCP',
        state: 'OPEN',
        service_name: 'https',
        product: 'nginx',
        version: '1.22.1',
        tls_version: 'TLSv1.3',
        tls_cipher: 'TLS_AES_256_GCM_SHA384',
        http_server_header: 'nginx/1.22.1'
      }
    ]
  },
  {
    id: 2,
    scan_id: 1,
    ip_address: '192.168.1.10',
    hostname: 'ad-dc01.corp.internal',
    mac_address: '00:50:56:A1:B2:10',
    status: 'UP',
    os_name: 'Windows Server 2019 Datacenter',
    os_confidence: '98%',
    os_evidence: 'MSRPC endpoint UUID, SMB dialect 3.1.1, TTL 128',
    risk_score: 92,
    risk_level: 'CRITICAL',
    discovered_at: '2026-09-16T10:02:00Z',
    last_seen: new Date().toISOString(),
    ports: [
      { id: 201, host_id: 2, port_number: 53, protocol: 'TCP', state: 'OPEN', service_name: 'domain', product: 'Microsoft DNS', version: '2019' },
      { id: 202, host_id: 2, port_number: 88, protocol: 'TCP', state: 'OPEN', service_name: 'kerberos-sec', product: 'Microsoft Windows Kerberos', version: 'v5' },
      { id: 203, host_id: 2, port_number: 135, protocol: 'TCP', state: 'OPEN', service_name: 'msrpc', product: 'Microsoft Windows RPC', banner: 'ncacn_ip_tcp endpoint mapper' },
      { id: 204, host_id: 2, port_number: 389, protocol: 'TCP', state: 'OPEN', service_name: 'ldap', product: 'Microsoft Windows Active Directory LDAP', banner: 'NTLMSSP supported' },
      { id: 205, host_id: 2, port_number: 445, protocol: 'TCP', state: 'OPEN', service_name: 'microsoft-ds', product: 'Windows Server 2019 SMB', banner: 'SMBv2/SMBv3 signing enabled' },
      { id: 206, host_id: 2, port_number: 3389, protocol: 'TCP', state: 'OPEN', service_name: 'ms-wbt-server', product: 'Microsoft Terminal Services', tls_version: 'TLSv1.0 / TLSv1.2', tls_cipher: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA' }
    ]
  },
  {
    id: 3,
    scan_id: 1,
    ip_address: '192.168.1.45',
    hostname: 'web-prod-api.corp.internal',
    mac_address: '00:50:56:B2:C3:45',
    status: 'UP',
    os_name: 'Ubuntu 22.04 LTS',
    os_confidence: '96%',
    os_evidence: 'Linux 5.15 kernel TCP response, OpenSSH banner string',
    risk_score: 85,
    risk_level: 'CRITICAL',
    discovered_at: '2026-09-16T10:03:00Z',
    last_seen: new Date().toISOString(),
    ports: [
      { id: 301, host_id: 3, port_number: 80, protocol: 'TCP', state: 'OPEN', service_name: 'http', product: 'Apache httpd', version: '2.4.49', banner: 'Apache/2.4.49 (Unix)' },
      { id: 302, host_id: 3, port_number: 443, protocol: 'TCP', state: 'OPEN', service_name: 'https', product: 'Apache httpd', version: '2.4.49', banner: 'Apache/2.4.49 OpenSSL/1.1.1n', tls_version: 'TLSv1.2 / TLSv1.3', missing_headers: 'Strict-Transport-Security, Content-Security-Policy, X-Frame-Options' },
      { id: 303, host_id: 3, port_number: 8080, protocol: 'TCP', state: 'OPEN', service_name: 'http-proxy', product: 'Node.js Express Gateway', version: '4.18.2' }
    ]
  },
  {
    id: 4,
    scan_id: 1,
    ip_address: '192.168.1.88',
    hostname: 'elastic-log-analytics.corp.internal',
    mac_address: '00:50:56:C3:D4:88',
    status: 'UP',
    os_name: 'Debian 11 (Bullseye)',
    os_confidence: '92%',
    os_evidence: 'TTL 64, TCP window scaling 7, JVM response footprint',
    risk_score: 95,
    risk_level: 'CRITICAL',
    discovered_at: '2026-09-16T10:04:00Z',
    last_seen: new Date().toISOString(),
    ports: [
      { id: 401, host_id: 4, port_number: 22, protocol: 'TCP', state: 'OPEN', service_name: 'ssh', product: 'OpenSSH', version: '8.4p1 Debian-5+deb11u1' },
      { id: 402, host_id: 4, port_number: 9200, protocol: 'TCP', state: 'OPEN', service_name: 'wap-wsp', product: 'Elasticsearch REST API', version: '7.15.2', banner: 'You Know, for Search (Lucene 8.9.0)' },
      { id: 403, host_id: 4, port_number: 9300, protocol: 'TCP', state: 'OPEN', service_name: 'vrace', product: 'Elasticsearch Internal Node Transport', version: '7.15.2' }
    ]
  },
  {
    id: 5,
    scan_id: 1,
    ip_address: '192.168.1.120',
    hostname: 'db-cluster-node1.corp.internal',
    mac_address: '00:50:56:D4:E5:20',
    status: 'UP',
    os_name: 'Debian 12 (Bookworm)',
    os_confidence: '95%',
    os_evidence: 'Linux 6.1 kernel fingerprint, strict TCP timestamping',
    risk_score: 20,
    risk_level: 'LOW',
    discovered_at: '2026-09-16T10:05:00Z',
    last_seen: new Date().toISOString(),
    ports: [
      { id: 501, host_id: 5, port_number: 22, protocol: 'TCP', state: 'OPEN', service_name: 'ssh', product: 'OpenSSH', version: '9.2p1 Debian-2+deb12u2' },
      { id: 502, host_id: 5, port_number: 5432, protocol: 'TCP', state: 'OPEN', service_name: 'postgresql', product: 'PostgreSQL Database', version: '15.4', banner: 'PostgreSQL 15.4 TLS enforced' }
    ]
  },
  {
    id: 6,
    scan_id: 1,
    ip_address: '192.168.1.205',
    hostname: 'cam-hub-lobby.internal',
    mac_address: 'AC:DE:48:00:11:22',
    status: 'UP',
    os_name: 'Embedded Linux (BusyBox / ARM)',
    os_confidence: '88%',
    os_evidence: 'Boa/0.94.14rc21 webserver banner, RTSP streaming signature',
    risk_score: 48,
    risk_level: 'MODERATE',
    discovered_at: '2026-09-16T10:06:00Z',
    last_seen: new Date().toISOString(),
    ports: [
      { id: 601, host_id: 6, port_number: 80, protocol: 'TCP', state: 'OPEN', service_name: 'http', product: 'Boa HTTPd', version: '0.94.14rc21', banner: 'Boa/0.94.14rc21' },
      { id: 602, host_id: 6, port_number: 554, protocol: 'TCP', state: 'OPEN', service_name: 'rtsp', product: 'LIVE555 Streaming Media', version: '2019.03.05', banner: 'RTSP/1.0 200 OK' }
    ]
  }
];

export const initialVulnerabilities: DbVulnerability[] = [
  {
    id: 1,
    finding_id: 'VULN-2026-001',
    cve_id: 'CVE-2021-44228',
    host_id: 4,
    port_id: 402,
    service: 'Elasticsearch / Log4j',
    detected_version: '2.14.1',
    title: 'Apache Log4j2 JNDI Remote Code Execution (Log4Shell)',
    severity: 'CRITICAL',
    cvss: 10.0,
    confidence: 'Confirmed',
    description: 'Apache Log4j2 versions 2.0-beta9 through 2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints.',
    evidence: 'Elasticsearch query response exposes embedded org.apache.logging.log4j.core version 2.14.1 via classloader inspection.',
    impact: 'Full remote unauthenticated arbitrary code execution with root system privileges.',
    recommendation: 'Upgrade log4j2 to version 2.17.1 or newer immediately, or apply -Dlog4j2.formatMsgNoLookups=true mitigation.',
    status: 'Open',
    first_detected: '2026-09-16T10:04:12Z',
    last_detected: new Date().toISOString()
  },
  {
    id: 2,
    finding_id: 'VULN-2026-002',
    cve_id: 'CVE-2020-1472',
    host_id: 2,
    port_id: 204,
    service: 'Netlogon / Active Directory',
    detected_version: 'MS-NRPC 2019',
    title: 'Zerologon: Netlogon Elevation of Privilege Vulnerability',
    severity: 'CRITICAL',
    cvss: 10.0,
    confidence: 'Confirmed',
    description: 'An unauthenticated attacker with network access to a domain controller can establish a vulnerable Netlogon secure channel connection to obtain domain administrator credentials.',
    evidence: 'DC accepts insecure Netlogon session negotiation with null credentials on MS-NRPC endpoint.',
    impact: 'Complete compromise of Active Directory domain identity and infrastructure.',
    recommendation: 'Apply Microsoft Security Update KB4557222 and enforce secure RPC channel binding.',
    status: 'Open',
    first_detected: '2026-09-16T10:02:40Z',
    last_detected: new Date().toISOString()
  },
  {
    id: 3,
    finding_id: 'VULN-2026-003',
    cve_id: 'CVE-2021-41773',
    host_id: 3,
    port_id: 301,
    service: 'Apache httpd',
    detected_version: '2.4.49',
    title: 'Apache HTTP Server 2.4.49 Path Traversal and Remote Code Execution',
    severity: 'CRITICAL',
    cvss: 9.8,
    confidence: 'Confirmed',
    description: 'A flaw in path normalization in Apache HTTP Server 2.4.49 allows attackers to map URLs to files outside the expected document root using dot-dot path traversal.',
    evidence: 'Server banner reports Apache/2.4.49 (Unix). URI /icons/.%%32%65/.%%32%65/ response confirmed traversal vulnerability.',
    impact: 'Arbitrary file disclosure and potential CGI execution under the web server user context.',
    recommendation: 'Upgrade Apache HTTP Server to version 2.4.51 or later.',
    status: 'Open',
    first_detected: '2026-09-16T10:03:15Z',
    last_detected: new Date().toISOString()
  },
  {
    id: 4,
    finding_id: 'VULN-2026-004',
    cve_id: 'CVE-2023-44487',
    host_id: 3,
    port_id: 302,
    service: 'HTTP/2 Protocol',
    detected_version: 'h2 enabled',
    title: 'HTTP/2 Rapid Reset Attack (Denial of Service)',
    severity: 'HIGH',
    cvss: 7.5,
    confidence: 'Confirmed',
    description: 'The HTTP/2 protocol allows a denial of service (server resource exhaustion) because request cancellation can reset many streams rapidly.',
    evidence: 'ALPN negotiation offers h2 on port 443 with default unlimited max_concurrent_streams configuration.',
    impact: 'Service degradation and complete unavailability due to CPU and socket saturation.',
    recommendation: 'Apply vendor patches limiting concurrent stream resets and update web server binaries.',
    status: 'Open',
    first_detected: '2026-09-16T10:03:22Z',
    last_detected: new Date().toISOString()
  },
  {
    id: 5,
    finding_id: 'VULN-2026-005',
    cve_id: 'CVE-2022-26923',
    host_id: 2,
    port_id: 204,
    service: 'Active Directory Domain Services',
    detected_version: 'Windows Server 2019',
    title: 'Active Directory Domain Services Privilege Escalation',
    severity: 'HIGH',
    cvss: 8.8,
    confidence: 'Likely',
    description: 'An authenticated domain user can manipulate dNSHostName attribute on computer objects to impersonate Domain Controllers against Active Directory Certificate Services.',
    evidence: 'ADCS enrollment endpoints detected without RPC packet integrity requirements.',
    impact: 'Privilege escalation from standard domain account to Enterprise Admin.',
    recommendation: 'Install Microsoft KB5014754 and enforce Certificate Mapping hardening.',
    status: 'In Progress',
    first_detected: '2026-09-16T10:02:45Z',
    last_detected: new Date().toISOString()
  },
  {
    id: 6,
    finding_id: 'VULN-2026-006',
    host_id: 4,
    port_id: 402,
    service: 'Elasticsearch REST',
    detected_version: '7.15.2',
    title: 'Unauthenticated Cluster REST API Exposure',
    severity: 'HIGH',
    cvss: 7.5,
    confidence: 'Confirmed',
    description: 'Elasticsearch REST API on port 9200 is accessible without authentication or IP whitelisting.',
    evidence: 'HTTP GET /_cat/indices returned 200 OK with full cluster index schema.',
    impact: 'Direct exfiltration, modification, or destruction of sensitive enterprise index data.',
    recommendation: 'Enable Elasticsearch Security features (X-Pack Basic) and require basic auth or mTLS.',
    status: 'Open',
    first_detected: '2026-09-16T10:04:18Z',
    last_detected: new Date().toISOString()
  },
  {
    id: 7,
    finding_id: 'VULN-2026-007',
    host_id: 2,
    port_id: 206,
    service: 'RDP / Terminal Services',
    detected_version: 'RDP 10.0',
    title: 'Weak TLS Cipher Suites and Protocol on Remote Desktop (RDP)',
    severity: 'MEDIUM',
    cvss: 5.3,
    confidence: 'Confirmed',
    description: 'RDP service negotiation permits legacy CBC mode ciphers (3DES-EDE-CBC) and TLS 1.0 protocols.',
    evidence: 'TLS handshake succeeded using cipher suite TLS_RSA_WITH_3DES_EDE_CBC_SHA.',
    impact: 'Potential eavesdropping and Sweet32 plaintext recovery attacks on internal communications.',
    recommendation: 'Disable TLS 1.0/1.1 and legacy 3DES cipher suites via Windows Schannel registry policies.',
    status: 'Open',
    first_detected: '2026-09-16T10:02:55Z',
    last_detected: new Date().toISOString()
  },
  {
    id: 8,
    finding_id: 'VULN-2026-008',
    host_id: 6,
    port_id: 601,
    service: 'Boa Web Server',
    detected_version: '0.94.14rc21',
    title: 'Outdated Boa Web Server Information Disclosure',
    severity: 'MEDIUM',
    cvss: 5.3,
    confidence: 'Confirmed',
    description: 'Boa web server version 0.94 is an unmaintained legacy embedded web server containing unpatched path handling and denial of service flaws.',
    evidence: 'Server header banner returned "Boa/0.94.14rc21".',
    impact: 'Sensitive camera system configuration and stream metadata disclosure.',
    recommendation: 'Migrate camera management interface to a hardened, maintained embedded web stack.',
    status: 'Open',
    first_detected: '2026-09-16T10:06:10Z',
    last_detected: new Date().toISOString()
  },
  {
    id: 9,
    finding_id: 'VULN-2026-009',
    host_id: 6,
    port_id: 602,
    service: 'RTSP Streaming',
    detected_version: 'LIVE555',
    title: 'Unencrypted RTSP Video Feed Broadcast',
    severity: 'MEDIUM',
    cvss: 5.0,
    confidence: 'Confirmed',
    description: 'RTSP video stream on port 554 transmits surveillance frames across the local network without encryption.',
    evidence: 'RTSP DESCRIBE query returned SDP descriptor without TLS transport.',
    impact: 'Unauthorized interception and eavesdropping on physical security camera feeds.',
    recommendation: 'Enforce RTSPS (RTSP over TLS) or isolate camera traffic into a dedicated private VLAN.',
    status: 'Open',
    first_detected: '2026-09-16T10:06:18Z',
    last_detected: new Date().toISOString()
  },
  {
    id: 10,
    finding_id: 'VULN-2026-010',
    host_id: 3,
    port_id: 302,
    service: 'HTTPS Web Server',
    detected_version: 'Apache 2.4.49',
    title: 'Missing HTTP Defensive Security Headers',
    severity: 'LOW',
    cvss: 3.7,
    confidence: 'Confirmed',
    description: 'Web server responses on port 443 omit essential browser hardening headers: HSTS, Content-Security-Policy, and X-Frame-Options.',
    evidence: 'HTTP response headers inspect missing Strict-Transport-Security, Content-Security-Policy, and X-Content-Type-Options.',
    impact: 'Increased susceptibility to MIME-sniffing, clickjacking, and protocol downgrade attacks.',
    recommendation: 'Configure Apache Header always set directives for HSTS, CSP, and X-Frame-Options.',
    status: 'Open',
    first_detected: '2026-09-16T10:03:30Z',
    last_detected: new Date().toISOString()
  }
];

export const initialCVEs: DbCVE[] = [
  {
    id: 1,
    cve_id: 'CVE-2021-44228',
    description: 'Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI endpoints.',
    severity: 'CRITICAL',
    cvss: 10.0,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    vendor: 'Apache',
    product: 'Log4j',
    affected_versions: '2.0-beta9 <= 2.14.1',
    cwe: 'CWE-502',
    references: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
    published_date: '2021-12-10'
  },
  {
    id: 2,
    cve_id: 'CVE-2020-1472',
    description: 'An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller.',
    severity: 'CRITICAL',
    cvss: 10.0,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    vendor: 'Microsoft',
    product: 'Windows Server',
    affected_versions: '2008 <= 2019',
    cwe: 'CWE-269',
    references: 'https://nvd.nist.gov/vuln/detail/CVE-2020-1472',
    published_date: '2020-08-17'
  },
  {
    id: 3,
    cve_id: 'CVE-2021-41773',
    description: 'A flaw was found in path normalization in Apache HTTP Server 2.4.49 allowing path traversal and arbitrary command execution.',
    severity: 'CRITICAL',
    cvss: 9.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    vendor: 'Apache',
    product: 'HTTP Server',
    affected_versions: '2.4.49',
    cwe: 'CWE-22',
    references: 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773',
    published_date: '2021-10-05'
  },
  {
    id: 4,
    cve_id: 'CVE-2023-44487',
    description: 'The HTTP/2 protocol allows a denial of service via stream reset flooding (Rapid Reset attack).',
    severity: 'HIGH',
    cvss: 7.5,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    vendor: 'IETF / Web Servers',
    product: 'HTTP/2 Protocol',
    affected_versions: 'Multiple',
    cwe: 'CWE-400',
    references: 'https://nvd.nist.gov/vuln/detail/CVE-2023-44487',
    published_date: '2023-10-10'
  },
  {
    id: 5,
    cve_id: 'CVE-2022-26923',
    description: 'Active Directory Domain Services Elevation of Privilege Vulnerability in certificate mapping.',
    severity: 'HIGH',
    cvss: 8.8,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
    vendor: 'Microsoft',
    product: 'Active Directory',
    affected_versions: 'Windows Server 2012-2022',
    cwe: 'CWE-269',
    references: 'https://nvd.nist.gov/vuln/detail/CVE-2022-26923',
    published_date: '2022-05-10'
  },
  {
    id: 6,
    cve_id: 'CVE-2023-38606',
    description: 'OpenSSH before 9.3p2 allows remote code execution in PKCS#11 provider parsing logic under specific constraints.',
    severity: 'HIGH',
    cvss: 8.1,
    cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
    vendor: 'OpenSSH',
    product: 'OpenSSH',
    affected_versions: '< 9.3p2',
    cwe: 'CWE-74',
    references: 'https://nvd.nist.gov/vuln/detail/CVE-2023-38606',
    published_date: '2023-07-20'
  }
];

export const initialAlerts: DbAlert[] = [
  {
    id: 1,
    title: 'Critical CVE-2021-44228 Detected',
    severity: 'CRITICAL',
    message: 'Log4Shell remote code execution detected on elastic-log-analytics (192.168.1.88:402). Immediate isolation advised.',
    created_at: new Date(Date.now() - 3600000 * 2).toISOString(),
    is_read: false
  },
  {
    id: 2,
    title: 'Domain Controller Zerologon Exposure',
    severity: 'CRITICAL',
    message: 'Active Directory DC ad-dc01 (192.168.1.10) susceptible to Netlogon privilege escalation.',
    created_at: new Date(Date.now() - 3600000 * 3).toISOString(),
    is_read: false
  },
  {
    id: 3,
    title: 'Scan "Production Core Perimeter Sweep" Completed',
    severity: 'INFO',
    message: 'Audit finished. 6 hosts identified, 11 vulnerabilities flagged, composite risk score: 78.4.',
    created_at: new Date(Date.now() - 3600000 * 3.8).toISOString(),
    is_read: true
  }
];
