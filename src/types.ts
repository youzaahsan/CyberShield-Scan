export interface User {
  id: number;
  username: string;
  email: string;
  role: 'Admin' | 'Security Analyst' | 'Viewer';
  is_active: boolean;
  created_at: string;
  last_login?: string;
}

export type ScanProfile = 'Top 20' | 'Top 100' | 'Top 1000' | 'Common Ports' | 'Custom Ports' | 'Full Range';
export type ScanStatus = 'Pending' | 'Running' | 'Paused' | 'Completed' | 'Failed' | 'Cancelled';

export interface Scan {
  id: number;
  name: string;
  target: string;
  profile: ScanProfile;
  custom_ports?: string;
  status: ScanStatus;
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

export interface Port {
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

export interface Host {
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
  ports?: Port[];
  vulnerabilities?: Vulnerability[];
}

export type VulnSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type VulnConfidence = 'Confirmed' | 'Likely' | 'Potential';
export type VulnStatus = 'Open' | 'In Progress' | 'Resolved' | 'Accepted Risk' | 'False Positive';

export interface Vulnerability {
  id: number;
  finding_id: string;
  cve_id?: string;
  host_id: number;
  port_id?: number;
  service?: string;
  detected_version?: string;
  title: string;
  severity: VulnSeverity;
  cvss: number;
  confidence: VulnConfidence;
  description: string;
  evidence: string;
  impact: string;
  recommendation: string;
  status: VulnStatus;
  first_detected: string;
  last_detected: string;
}

export interface CVE {
  id: number;
  cve_id: string;
  description: string;
  severity: VulnSeverity;
  cvss: number;
  cvss_vector?: string;
  vendor?: string;
  product?: string;
  affected_versions?: string;
  cwe?: string;
  references?: string;
  published_date?: string;
}

export interface RiskFactor {
  name: string;
  weight: string;
  impact: string;
}

export interface RecommendationPriority {
  priority: number;
  action: string;
  impact: string;
}

export interface RiskAssessment {
  overall_score: number;
  overall_level: string;
  high_risk_hosts_count: number;
  medium_risk_hosts_count: number;
  low_risk_hosts_count: number;
  factors: RiskFactor[];
  recommendations_priority: RecommendationPriority[];
}

export interface TopologyNode {
  id: string;
  label: string;
  type: 'internet' | 'gateway' | 'host' | 'vulnerable_host';
  ip?: string;
  risk_score?: number;
}

export interface TopologyEdge {
  source: string;
  target: string;
  label?: string;
}

export interface TopologyData {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}

export interface SecurityAlert {
  id: number;
  title: string;
  severity: string;
  message: string;
  created_at: string;
  is_read: boolean;
}
