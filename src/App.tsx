import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { DashboardOverview } from './components/DashboardOverview';
import { ScanManager } from './components/ScanManager';
import { HostExplorer } from './components/HostExplorer';
import { VulnerabilityHub } from './components/VulnerabilityHub';
import { CVEIntelligence } from './components/CVEIntelligence';
import { TopologyViewer } from './components/TopologyViewer';
import { ComplianceReports } from './components/ComplianceReports';
import { SecurityAlertsView } from './components/SecurityAlertsView';
import { apiFetch, getAuthToken, setAuthToken, clearAuthToken } from './api/client';
import {
  User,
  Scan,
  Host,
  Vulnerability,
  RiskAssessment,
  TopologyData,
  SecurityAlert,
  ScanProfile,
  VulnStatus,
} from './types';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [authLoading, setAuthLoading] = useState(true);

  // Auth Form State (if not logged in)
  const [loginUsername, setLoginUsername] = useState('admin');
  const [loginPassword, setLoginPassword] = useState('AdminPass123!');
  const [authError, setAuthError] = useState('');
  const [authSubmitting, setAuthSubmitting] = useState(false);

  // Core App State
  const [scans, setScans] = useState<Scan[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [riskData, setRiskData] = useState<RiskAssessment | null>(null);
  const [topology, setTopology] = useState<TopologyData | null>(null);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);

  // Authenticate & Verify Session
  const checkAuth = async () => {
    setAuthLoading(true);
    try {
      const token = getAuthToken();
      if (!token) {
        // Automatically attempt default admin login for seamless preview
        await handleAutoLogin();
        return;
      }
      const user = await apiFetch<User>('/auth/me');
      setCurrentUser(user);
    } catch {
      await handleAutoLogin();
    } finally {
      setAuthLoading(false);
    }
  };

  const handleAutoLogin = async () => {
    try {
      const res = await apiFetch<{ access_token: string; user: User }>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username_or_email: 'admin', password: 'AdminPass123!' }),
      });
      setAuthToken(res.access_token);
      setCurrentUser(res.user);
    } catch (err: any) {
      setAuthError(err.message || 'Authentication required');
    }
  };

  const handleManualLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthSubmitting(true);
    setAuthError('');
    try {
      const res = await apiFetch<{ access_token: string; user: User }>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username_or_email: loginUsername, password: loginPassword }),
      });
      setAuthToken(res.access_token);
      setCurrentUser(res.user);
    } catch (err: any) {
      setAuthError(err.message || 'Invalid credentials');
    } finally {
      setAuthSubmitting(false);
    }
  };

  const handleLogout = () => {
    clearAuthToken();
    setCurrentUser(null);
  };

  // Data Fetching
  const refreshAllData = async () => {
    if (!currentUser) return;
    try {
      const [scansRes, hostsRes, vulnsRes, riskRes, topoRes, alertsRes] = await Promise.allSettled([
        apiFetch<Scan[]>('/scans'),
        apiFetch<Host[]>('/hosts'),
        apiFetch<Vulnerability[]>('/vulnerabilities'),
        apiFetch<RiskAssessment>('/risk'),
        apiFetch<TopologyData>('/topology'),
        apiFetch<SecurityAlert[]>('/alerts'),
      ]);

      if (scansRes.status === 'fulfilled') setScans(scansRes.value);
      if (hostsRes.status === 'fulfilled') setHosts(hostsRes.value);
      if (vulnsRes.status === 'fulfilled') setVulnerabilities(vulnsRes.value);
      if (riskRes.status === 'fulfilled') setRiskData(riskRes.value);
      if (topoRes.status === 'fulfilled') setTopology(topoRes.value);
      if (alertsRes.status === 'fulfilled') setAlerts(alertsRes.value);
    } catch (err) {
      console.error('Failed to load dashboard metrics', err);
    }
  };

  useEffect(() => {
    checkAuth();
  }, []);

  useEffect(() => {
    if (currentUser) {
      refreshAllData();
      // Poll active status every 4 seconds if scans are running
      const interval = setInterval(() => {
        refreshAllData();
      }, 4000);
      return () => clearInterval(interval);
    }
  }, [currentUser]);

  // Handlers
  const handleLaunchScan = async (name: string, target: string, profile: ScanProfile, customPorts?: string) => {
    const newScan = await apiFetch<Scan>('/scans', {
      method: 'POST',
      body: JSON.stringify({
        name,
        target,
        profile,
        custom_ports: customPorts || undefined,
      }),
    });
    setScans([newScan, ...scans]);
    refreshAllData();
  };

  const handleCancelScan = async (scanId: number) => {
    await apiFetch<Scan>(`/scans/${scanId}/cancel`, { method: 'POST' });
    refreshAllData();
  };

  const handleUpdateVulnStatus = async (vulnId: number, newStatus: VulnStatus) => {
    await apiFetch<Vulnerability>(`/vulnerabilities/${vulnId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status: newStatus }),
    });
    refreshAllData();
  };

  const handleMarkAlertRead = async (alertId: number) => {
    await apiFetch(`/alerts/${alertId}/read`, { method: 'PATCH' });
    refreshAllData();
  };

  if (authLoading) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center p-4 text-slate-300">
        <div className="w-10 h-10 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin mb-4" />
        <div className="text-sm font-semibold tracking-wide">Initializing CyberShield Scan Environment...</div>
      </div>
    );
  }

  if (!currentUser) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4 text-slate-200">
        <div className="max-w-md w-full bg-slate-900 border border-slate-800 rounded-2xl p-8 shadow-2xl space-y-6">
          <div className="text-center space-y-2">
            <div className="inline-block p-3 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 mb-2">
              <span className="font-extrabold text-xl tracking-wider">CYBERSHIELD</span>
            </div>
            <h1 className="text-xl font-bold text-white tracking-tight">Authorized Personnel Login</h1>
            <p className="text-xs text-slate-400">
              Defensive Network Security Assessment Console. Pre-configured admin credentials provided below.
            </p>
          </div>

          {authError && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl text-xs text-rose-400">
              {authError}
            </div>
          )}

          <form onSubmit={handleManualLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                Username
              </label>
              <input
                type="text"
                value={loginUsername}
                onChange={(e) => setLoginUsername(e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:border-cyan-500"
                required
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                Password
              </label>
              <input
                type="password"
                value={loginPassword}
                onChange={(e) => setLoginPassword(e.target.value)}
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:border-cyan-500"
                required
              />
            </div>

            <button
              type="submit"
              disabled={authSubmitting}
              className="w-full py-2.5 rounded-xl text-xs font-bold uppercase tracking-wider text-slate-950 bg-gradient-to-r from-cyan-400 to-teal-400 hover:from-cyan-300 hover:to-teal-300 transition shadow-lg shadow-cyan-500/20"
            >
              {authSubmitting ? 'Authenticating...' : 'Sign In to Console'}
            </button>
          </form>

          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/80 text-[11px] text-slate-400 space-y-1">
            <div className="font-semibold text-slate-300">Default Sandbox Credentials:</div>
            <div>Admin: <code className="text-cyan-300">admin</code> / <code className="text-cyan-300">AdminPass123!</code></div>
            <div>Analyst: <code className="text-cyan-300">analyst</code> / <code className="text-cyan-300">AnalystPass123!</code></div>
          </div>
        </div>
      </div>
    );
  }

  const activeScanCount = scans.filter((s) => s.status === 'Running' || s.status === 'Pending').length;
  const unreadAlertCount = alerts.filter((a) => !a.is_read).length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans antialiased selection:bg-cyan-500/20 selection:text-cyan-300">
      {/* Navigation Bar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        currentUser={currentUser}
        onLogout={handleLogout}
        activeScanCount={activeScanCount}
        alertCount={unreadAlertCount}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'dashboard' && (
          <DashboardOverview
            riskData={riskData}
            scans={scans}
            hosts={hosts}
            vulnerabilities={vulnerabilities}
            onNavigate={(tab) => setActiveTab(tab)}
            onNewScan={() => setActiveTab('scans')}
          />
        )}

        {activeTab === 'scans' && (
          <ScanManager
            scans={scans}
            onRefresh={refreshAllData}
            onLaunchScan={handleLaunchScan}
            onCancelScan={handleCancelScan}
          />
        )}

        {activeTab === 'hosts' && <HostExplorer hosts={hosts} />}

        {activeTab === 'vulnerabilities' && (
          <VulnerabilityHub
            vulnerabilities={vulnerabilities}
            onUpdateStatus={handleUpdateVulnStatus}
          />
        )}

        {activeTab === 'cve' && <CVEIntelligence />}

        {activeTab === 'topology' && (
          <TopologyViewer topology={topology} onRefresh={refreshAllData} />
        )}

        {activeTab === 'reports' && (
          <ComplianceReports
            scans={scans}
            hosts={hosts}
            vulnerabilities={vulnerabilities}
            riskData={riskData}
          />
        )}

        {activeTab === 'alerts' && (
          <SecurityAlertsView alerts={alerts} onMarkRead={handleMarkAlertRead} />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-4 text-center text-xs text-slate-500">
        CyberShield Scan • Defensive Network Security & Vulnerability Assessment Platform • Production FYP Edition
      </footer>
    </div>
  );
}
