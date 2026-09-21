import { Router, Request, Response } from 'express';
import {
  initialUsers,
  initialScans,
  initialHosts,
  initialVulnerabilities,
  initialCVEs,
  initialAlerts,
  DbScan,
  DbVulnerability,
  DbHost,
  DbAlert,
  DbUser
} from './data';

export const apiRouter = Router();

// In-memory application state
let users = [...initialUsers];
let scans: DbScan[] = [...initialScans];
let hosts: DbHost[] = JSON.parse(JSON.stringify(initialHosts));
let vulnerabilities: DbVulnerability[] = JSON.parse(JSON.stringify(initialVulnerabilities));
let cves = [...initialCVEs];
let alerts: DbAlert[] = [...initialAlerts];
const activeScanTimers: Map<number, NodeJS.Timeout[]> = new Map();

// Helper: Calculate risk scores
function calculateRisk() {
  const activeVulns = vulnerabilities.filter(
    (v) => v.status !== 'Resolved' && v.status !== 'False Positive'
  );

  const critVulns = activeVulns.filter((v) => v.severity === 'CRITICAL').length;
  const highVulns = activeVulns.filter((v) => v.severity === 'HIGH').length;
  const medVulns = activeVulns.filter((v) => v.severity === 'MEDIUM').length;

  const openPortsCount = hosts.reduce((acc, h) => acc + (h.ports?.length || 0), 0);

  // Update individual host risk scores based on active vulnerabilities
  hosts.forEach((h) => {
    const hostVulns = activeVulns.filter((v) => v.host_id === h.id);
    const hostCrit = hostVulns.filter((v) => v.severity === 'CRITICAL').length;
    const hostHigh = hostVulns.filter((v) => v.severity === 'HIGH').length;
    const hostMed = hostVulns.filter((v) => v.severity === 'MEDIUM').length;

    let score = Math.min(100, Math.round((hostCrit * 30) + (hostHigh * 18) + (hostMed * 8) + ((h.ports?.length || 0) * 2)));
    if (score < 15 && (h.ports?.length || 0) > 0) score = 18;
    h.risk_score = score;
    if (score >= 80) h.risk_level = 'CRITICAL';
    else if (score >= 60) h.risk_level = 'HIGH';
    else if (score >= 40) h.risk_level = 'MEDIUM';
    else if (score >= 20) h.risk_level = 'MODERATE';
    else h.risk_level = 'LOW';
  });

  const highRiskHosts = hosts.filter((h) => h.risk_score >= 60).length;
  const medRiskHosts = hosts.filter((h) => h.risk_score >= 20 && h.risk_score < 60).length;
  const lowRiskHosts = hosts.filter((h) => h.risk_score < 20).length;

  let baseScore = 0;
  if (hosts.length > 0) {
    const avgHostScore = hosts.reduce((acc, h) => acc + h.risk_score, 0) / hosts.length;
    const vulnPressure = Math.min(45, (critVulns * 14) + (highVulns * 7) + (medVulns * 2));
    baseScore = Math.min(100, Math.round((avgHostScore * 0.55) + vulnPressure));
  }

  let overallLevel = 'LOW';
  if (baseScore >= 80) overallLevel = 'CRITICAL';
  else if (baseScore >= 60) overallLevel = 'HIGH';
  else if (baseScore >= 40) overallLevel = 'MEDIUM';
  else if (baseScore >= 20) overallLevel = 'MODERATE';

  return {
    overall_score: baseScore,
    overall_level: overallLevel,
    high_risk_hosts_count: highRiskHosts,
    medium_risk_hosts_count: medRiskHosts,
    low_risk_hosts_count: lowRiskHosts,
    factors: [
      { name: 'Critical Vulnerabilities', weight: '35%', impact: `${critVulns} active critical findings requiring immediate triage` },
      { name: 'High Severity CVEs', weight: '25%', impact: `${highVulns} high-impact security vulnerabilities` },
      { name: 'Exposed Attack Surface', weight: '20%', impact: `${openPortsCount} active network listening sockets identified` },
      { name: 'Unpatched Host Density', weight: '20%', impact: `${highRiskHosts} high-risk systems on monitored subnet` },
    ],
    recommendations_priority: [
      { priority: 1, action: 'Patch Log4Shell (CVE-2021-44228) and Zerologon (CVE-2020-1472)', impact: 'Mitigates remote privilege escalation on Domain Controller and Analytics servers' },
      { priority: 2, action: 'Upgrade Apache HTTP server 2.4.49 to resolve Path Traversal (CVE-2021-41773)', impact: 'Prevents arbitrary filesystem extraction on public API gateway' },
      { priority: 3, action: 'Enforce HSTS, CSP, and X-Frame-Options headers on Web services', impact: 'Eliminates clickjacking and cryptographic downgrade exposure' },
      { priority: 4, action: 'Isolate IoT camera feeds and require TLS for RTSP video streams', impact: 'Prevents unauthorized cleartext surveillance monitoring' }
    ]
  };
}

// Token helper
function extractUserFromToken(authHeader?: string): DbUser | null {
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.split(' ')[1];
  try {
    const decoded = Buffer.from(token, 'base64').toString('utf-8');
    const [username] = decoded.split(':');
    return users.find((u) => u.username === username) || null;
  } catch {
    return null;
  }
}

// -------------------------------------------------------------
// 1. Health
// -------------------------------------------------------------
apiRouter.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    service: 'CyberShield Scan Defense Engine',
    version: '1.0.0',
    defensive_mode: 'ACTIVE',
    active_monitored_hosts: hosts.length,
    active_vulnerabilities: vulnerabilities.length
  });
});

// -------------------------------------------------------------
// 2. Authentication
// -------------------------------------------------------------
apiRouter.post('/auth/login', (req: Request, res: Response) => {
  const identifier = req.body.username_or_email || req.body.username;
  const password = req.body.password;

  if (!identifier || !password) {
    res.status(400).json({ error: 'Username/email and password are required.' });
    return;
  }

  const user = users.find(
    (u) => (u.username.toLowerCase() === identifier.toLowerCase() || u.email.toLowerCase() === identifier.toLowerCase())
  );

  if (!user || user.passwordHash !== password) {
    res.status(401).json({ error: 'Invalid credentials. Please verify username and password.' });
    return;
  }

  // Update last login
  user.last_login = new Date().toISOString();

  // Create secure base64 bearer token
  const tokenPayload = `${user.username}:${user.role}:${Date.now()}`;
  const accessToken = Buffer.from(tokenPayload).toString('base64');

  res.json({
    access_token: accessToken,
    token_type: 'bearer',
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      is_active: user.is_active,
      created_at: user.created_at,
      last_login: user.last_login,
    }
  });
});

apiRouter.get('/auth/me', (req: Request, res: Response) => {
  const user = extractUserFromToken(req.headers.authorization);
  if (!user) {
    res.status(401).json({ error: 'Unauthorized: Valid Bearer token is required.' });
    return;
  }

  res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
    is_active: user.is_active,
    created_at: user.created_at,
    last_login: user.last_login,
  });
});

// -------------------------------------------------------------
// 3. Scans
// -------------------------------------------------------------
apiRouter.get('/scans', (_req: Request, res: Response) => {
  res.json(scans);
});

apiRouter.post('/scans', (req: Request, res: Response) => {
  const { name, target, profile, custom_ports } = req.body;
  if (!target) {
    res.status(400).json({ error: 'Target specification (IP, CIDR, or range) is required.' });
    return;
  }

  const scanId = scans.length > 0 ? Math.max(...scans.map((s) => s.id)) + 1 : 1;
  const newScan: DbScan = {
    id: scanId,
    name: name || `Perimeter Audit #${scanId}`,
    target,
    profile: profile || 'Top 100',
    custom_ports: custom_ports || undefined,
    status: 'Running',
    progress_percentage: 10,
    current_phase: 'Initializing Host Sweep',
    hosts_discovered: 1,
    hosts_scanned: 0,
    ports_scanned: 0,
    services_detected: 0,
    vulnerabilities_found: 0,
    created_at: new Date().toISOString(),
    started_at: new Date().toISOString(),
  };

  scans.unshift(newScan);

  // Add system alert for scan launch
  alerts.unshift({
    id: Date.now(),
    title: `Scan Launched: ${newScan.name}`,
    severity: 'INFO',
    message: `Network audit initiated targeting ${newScan.target} using profile ${newScan.profile}.`,
    created_at: new Date().toISOString(),
    is_read: false
  });

  // Advance scan simulation asynchronously
  const timers: NodeJS.Timeout[] = [];

  // Phase 1: Host sweep (1.5s)
  timers.push(setTimeout(() => {
    const s = scans.find((item) => item.id === scanId);
    if (s && s.status === 'Running') {
      s.progress_percentage = 30;
      s.current_phase = 'SYN Socket Probing & TCP Handshake';
      s.hosts_discovered = Math.max(s.hosts_discovered, target.includes('/') ? 4 : 1);
      s.ports_scanned = 120;
    }
  }, 1500));

  // Phase 2: Service discovery (3.5s)
  timers.push(setTimeout(() => {
    const s = scans.find((item) => item.id === scanId);
    if (s && s.status === 'Running') {
      s.progress_percentage = 65;
      s.current_phase = 'Service Fingerprinting & Banner Grabbing';
      s.hosts_scanned = s.hosts_discovered;
      s.ports_scanned = 480;
      s.services_detected = 6;
    }
  }, 3500));

  // Phase 3: Vulnerability correlation (6.0s)
  timers.push(setTimeout(() => {
    const s = scans.find((item) => item.id === scanId);
    if (s && s.status === 'Running') {
      s.progress_percentage = 85;
      s.current_phase = 'Correlating CVE Signatures & Weak Ciphers';
      s.vulnerabilities_found = 2;
    }
  }, 6000));

  // Phase 4: Completion (8.0s)
  timers.push(setTimeout(() => {
    const s = scans.find((item) => item.id === scanId);
    if (s && s.status === 'Running') {
      s.progress_percentage = 100;
      s.current_phase = 'Completed';
      s.status = 'Completed';
      s.completed_at = new Date().toISOString();

      alerts.unshift({
        id: Date.now(),
        title: `Scan Completed: ${s.name}`,
        severity: 'INFO',
        message: `Assessment completed for ${s.target}. ${s.hosts_scanned} hosts scanned, ${s.vulnerabilities_found} security findings detected.`,
        created_at: new Date().toISOString(),
        is_read: false
      });
    }
    activeScanTimers.delete(scanId);
  }, 8000));

  activeScanTimers.set(scanId, timers);

  res.status(201).json(newScan);
});

apiRouter.post('/scans/:id/cancel', (req: Request, res: Response) => {
  const scanId = parseInt(req.params.id, 10);
  const scan = scans.find((s) => s.id === scanId);

  if (!scan) {
    res.status(404).json({ error: 'Scan not found.' });
    return;
  }

  // Clear timers
  const timers = activeScanTimers.get(scanId);
  if (timers) {
    timers.forEach(clearTimeout);
    activeScanTimers.delete(scanId);
  }

  scan.status = 'Cancelled';
  scan.current_phase = 'Cancelled by user';
  scan.completed_at = new Date().toISOString();

  res.json(scan);
});

// -------------------------------------------------------------
// 4. Hosts
// -------------------------------------------------------------
apiRouter.get('/hosts', (_req: Request, res: Response) => {
  // Attach vulnerabilities to hosts
  const hostList = hosts.map((h) => ({
    ...h,
    vulnerabilities: vulnerabilities.filter((v) => v.host_id === h.id),
  }));
  res.json(hostList);
});

// -------------------------------------------------------------
// 5. Vulnerabilities
// -------------------------------------------------------------
apiRouter.get('/vulnerabilities', (_req: Request, res: Response) => {
  res.json(vulnerabilities);
});

apiRouter.patch('/vulnerabilities/:id/status', (req: Request, res: Response) => {
  const vulnId = parseInt(req.params.id, 10);
  const { status } = req.body;

  const validStatuses = ['Open', 'In Progress', 'Resolved', 'Accepted Risk', 'False Positive'];
  if (!status || !validStatuses.includes(status)) {
    res.status(400).json({ error: `Invalid status. Must be one of: ${validStatuses.join(', ')}` });
    return;
  }

  const vuln = vulnerabilities.find((v) => v.id === vulnId);
  if (!vuln) {
    res.status(404).json({ error: 'Vulnerability finding not found.' });
    return;
  }

  vuln.status = status;
  vuln.last_detected = new Date().toISOString();

  // Add notification if resolved
  if (status === 'Resolved') {
    alerts.unshift({
      id: Date.now(),
      title: `Vulnerability Resolved: ${vuln.finding_id}`,
      severity: 'LOW',
      message: `${vuln.title} marked as resolved. Perimeter risk score adjusted downward.`,
      created_at: new Date().toISOString(),
      is_read: false
    });
  }

  // Trigger risk recalculation
  calculateRisk();

  res.json(vuln);
});

// -------------------------------------------------------------
// 6. Risk Assessment
// -------------------------------------------------------------
apiRouter.get('/risk', (_req: Request, res: Response) => {
  const risk = calculateRisk();
  res.json(risk);
});

// -------------------------------------------------------------
// 7. Subnet Topology
// -------------------------------------------------------------
apiRouter.get('/topology', (_req: Request, res: Response) => {
  const nodes = [
    { id: 'internet', label: 'External Internet', type: 'internet' },
    { id: 'gw-1', label: '192.168.1.1 (Edge Gateway)', type: 'gateway', ip: '192.168.1.1', risk_score: 18 },
    ...hosts.map((h) => ({
      id: `host-${h.id}`,
      label: `${h.hostname || h.ip_address} (${h.ip_address})`,
      type: (h.risk_score >= 60 ? 'vulnerable_host' : 'host') as 'vulnerable_host' | 'host',
      ip: h.ip_address,
      risk_score: h.risk_score
    }))
  ];

  const edges = [
    { source: 'internet', target: 'gw-1', label: 'WAN Uplink' },
    ...hosts.map((h) => ({
      source: 'gw-1',
      target: `host-${h.id}`,
      label: `VLAN 100 (${h.ip_address})`
    }))
  ];

  res.json({ nodes, edges });
});

// -------------------------------------------------------------
// 8. Alerts
// -------------------------------------------------------------
apiRouter.get('/alerts', (_req: Request, res: Response) => {
  res.json(alerts);
});

apiRouter.patch('/alerts/:id/read', (req: Request, res: Response) => {
  const alertId = parseInt(req.params.id, 10);
  const alert = alerts.find((a) => a.id === alertId);
  if (alert) {
    alert.is_read = true;
  }
  res.json({ success: true, id: alertId });
});

// -------------------------------------------------------------
// 9. CVE Intelligence
// -------------------------------------------------------------
apiRouter.get('/cves', (req: Request, res: Response) => {
  const query = (req.query.q as string || '').toLowerCase();
  const severity = (req.query.severity as string || '').toUpperCase();

  let results = cves;
  if (query) {
    results = results.filter(
      (c) =>
        c.cve_id.toLowerCase().includes(query) ||
        c.description.toLowerCase().includes(query) ||
        (c.vendor && c.vendor.toLowerCase().includes(query)) ||
        (c.product && c.product.toLowerCase().includes(query))
    );
  }

  if (severity && severity !== 'ALL') {
    results = results.filter((c) => c.severity === severity);
  }

  res.json(results);
});

// -------------------------------------------------------------
// 10. API Catch-all (Ensures API NEVER returns HTML on 404)
// -------------------------------------------------------------
apiRouter.all('*', (req: Request, res: Response) => {
  res.status(404).json({
    error: 'NotFound',
    message: `API endpoint '${req.originalUrl}' does not exist on CyberShield Scan service.`,
  });
});
