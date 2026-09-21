import React from 'react';
import { Shield, ShieldAlert, Server, Network, AlertCircle, ArrowUpRight, Activity, CheckCircle2 } from 'lucide-react';
import { RiskAssessment, Scan, Host, Vulnerability } from '../types';

interface DashboardOverviewProps {
  riskData: RiskAssessment | null;
  scans: Scan[];
  hosts: Host[];
  vulnerabilities: Vulnerability[];
  onNavigate: (tab: string) => void;
  onNewScan: () => void;
}

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  riskData,
  scans,
  hosts,
  vulnerabilities,
  onNavigate,
  onNewScan,
}) => {
  const activeScans = scans.filter((s) => s.status === 'Running' || s.status === 'Pending');
  const criticalVulns = vulnerabilities.filter((v) => v.severity === 'CRITICAL');
  const highVulns = vulnerabilities.filter((v) => v.severity === 'HIGH');
  const openPortsCount = hosts.reduce((acc, h) => acc + (h.ports?.length || 0), 0);

  const riskScore = riskData ? Math.round(riskData.overall_score) : 0;
  const riskLevel = riskData ? riskData.overall_level : 'LOW';

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return 'text-rose-500 border-rose-500/30 bg-rose-500/10';
      case 'HIGH':
        return 'text-orange-400 border-orange-500/30 bg-orange-500/10';
      case 'MEDIUM':
        return 'text-amber-400 border-amber-500/30 bg-amber-500/10';
      default:
        return 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Action Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900 to-indigo-950/40 border border-slate-800 rounded-2xl p-6 relative overflow-hidden shadow-xl">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold tracking-wide bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                ACTIVE DEFENSE
              </span>
              <span className="text-xs text-slate-400">Continuous Security Posture</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
              Enterprise Network Security Command
            </h1>
            <p className="text-sm text-slate-400 mt-1 max-w-2xl">
              Real-time vulnerability assessment engine detecting perimeter exposure, missing cryptographic controls, and critical CVE signatures.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => onNavigate('scans')}
              className="px-4 py-2.5 rounded-xl text-sm font-medium text-slate-300 hover:text-white bg-slate-800/80 hover:bg-slate-800 border border-slate-700 transition"
            >
              Scan History
            </button>
            <button
              onClick={onNewScan}
              className="px-5 py-2.5 rounded-xl text-sm font-semibold text-slate-950 bg-gradient-to-r from-cyan-400 to-teal-400 hover:from-cyan-300 hover:to-teal-300 shadow-lg shadow-cyan-500/25 transition transform active:scale-95 flex items-center gap-2"
            >
              <Activity className="w-4 h-4" />
              <span>Launch Scan</span>
            </button>
          </div>
        </div>
      </div>

      {/* KPI Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Risk Score Gauge */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 relative overflow-hidden flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Perimeter Risk Score</span>
            <Shield className="w-5 h-5 text-indigo-400" />
          </div>
          <div className="my-4 flex items-baseline gap-3">
            <span className="text-4xl font-extrabold tracking-tight text-white">{riskScore}</span>
            <span className="text-xs text-slate-500 font-mono">/ 100</span>
            <span className={`text-xs px-2 py-0.5 rounded-full font-bold uppercase border ${getRiskColor(riskLevel)}`}>
              {riskLevel}
            </span>
          </div>
          {/* Progress gauge bar */}
          <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-700 ${
                riskScore > 60 ? 'bg-rose-500' : riskScore > 35 ? 'bg-amber-500' : 'bg-emerald-500'
              }`}
              style={{ width: `${Math.min(100, Math.max(5, riskScore))}%` }}
            />
          </div>
        </div>

        {/* Live Attack Surface */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Hosts & Services</span>
            <Server className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="my-4 flex items-baseline gap-3">
            <span className="text-4xl font-extrabold tracking-tight text-white">{hosts.length}</span>
            <span className="text-xs text-slate-400">hosts active</span>
          </div>
          <div className="flex items-center justify-between text-xs text-slate-400 border-t border-slate-800/80 pt-3">
            <span>Open Ports Detected</span>
            <span className="font-semibold text-cyan-400 font-mono">{openPortsCount}</span>
          </div>
        </div>

        {/* Critical & High Findings */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Vulnerability Threat</span>
            <ShieldAlert className="w-5 h-5 text-rose-400" />
          </div>
          <div className="my-4 flex items-baseline gap-3">
            <span className="text-4xl font-extrabold tracking-tight text-white">{criticalVulns.length}</span>
            <span className="text-xs text-rose-400 font-medium">Critical</span>
            <span className="text-xl font-bold text-orange-400 ml-1">{highVulns.length}</span>
            <span className="text-xs text-orange-400 font-medium">High</span>
          </div>
          <div className="flex items-center justify-between text-xs text-slate-400 border-t border-slate-800/80 pt-3">
            <span>Total Findings</span>
            <span className="font-semibold text-white font-mono">{vulnerabilities.length}</span>
          </div>
        </div>

        {/* Engine Activity */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Scan Operations</span>
            <Activity className="w-5 h-5 text-teal-400" />
          </div>
          <div className="my-4 flex items-baseline gap-3">
            <span className="text-4xl font-extrabold tracking-tight text-white">{activeScans.length}</span>
            <span className="text-xs text-teal-400 font-medium">{activeScans.length > 0 ? 'running now' : 'idle'}</span>
          </div>
          <div className="flex items-center justify-between text-xs text-slate-400 border-t border-slate-800/80 pt-3">
            <span>Total Scans Logged</span>
            <span className="font-semibold text-slate-300 font-mono">{scans.length}</span>
          </div>
        </div>
      </div>

      {/* Main Two-Column Layout: Priority Findings & Risk Explainability */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Priority Vulnerability Feed */}
        <div className="lg:col-span-2 bg-slate-900/80 border border-slate-800 rounded-xl p-6 flex flex-col justify-between shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-base font-bold text-white tracking-tight">Priority Vulnerability Findings</h2>
              <p className="text-xs text-slate-400">High & Critical findings requiring immediate administrative remediation</p>
            </div>
            <button
              onClick={() => onNavigate('vulnerabilities')}
              className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition"
            >
              <span>View all findings</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-3">
            {vulnerabilities.length === 0 ? (
              <div className="text-center py-10 border border-dashed border-slate-800 rounded-xl">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
                <p className="text-sm font-medium text-slate-300">No active vulnerability findings</p>
                <p className="text-xs text-slate-500 mt-1">Launch a scan against your perimeter to inspect live targets.</p>
              </div>
            ) : (
              vulnerabilities.slice(0, 5).map((vuln) => (
                <div
                  key={vuln.id}
                  className="bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 rounded-lg p-3.5 transition flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase border ${
                          vuln.severity === 'CRITICAL'
                            ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                            : vuln.severity === 'HIGH'
                            ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                            : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                        }`}
                      >
                        {vuln.severity}
                      </span>
                      {vuln.cve_id && (
                        <span className="text-xs font-mono font-semibold text-indigo-300 bg-indigo-500/10 px-1.5 py-0.5 rounded border border-indigo-500/20">
                          {vuln.cve_id}
                        </span>
                      )}
                      <span className="text-xs font-mono text-slate-400">CVSS {vuln.cvss}</span>
                    </div>
                    <h3 className="text-sm font-semibold text-white tracking-tight">{vuln.title}</h3>
                    <p className="text-xs text-slate-400 line-clamp-1">{vuln.impact}</p>
                  </div>
                  <div className="flex items-center gap-2 self-start sm:self-center">
                    <span className="text-[11px] font-mono px-2 py-1 rounded bg-slate-900 text-slate-300 border border-slate-800">
                      {vuln.status}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right Col: Explainable Risk Factors & Action Priorities */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 space-y-6">
          <div>
            <h2 className="text-base font-bold text-white tracking-tight">Risk Scoring Breakdown</h2>
            <p className="text-xs text-slate-400">Mathematical weighting formulation</p>
          </div>

          <div className="space-y-3">
            {riskData?.factors.map((factor, idx) => (
              <div key={idx} className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-3">
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="font-semibold text-slate-200">{factor.name}</span>
                  <span className="font-mono text-cyan-400">{factor.weight}</span>
                </div>
                <p className="text-[11px] text-slate-400">{factor.impact}</p>
              </div>
            ))}
          </div>

          <div className="pt-2 border-t border-slate-800/80">
            <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Priority Remediation</h3>
            <div className="space-y-2">
              {riskData?.recommendations_priority.map((rec) => (
                <div key={rec.priority} className="flex items-start gap-2.5 text-xs">
                  <span className="w-4 h-4 rounded-full bg-cyan-500/20 text-cyan-300 font-bold flex items-center justify-center text-[10px] shrink-0 mt-0.5">
                    {rec.priority}
                  </span>
                  <div>
                    <span className="font-medium text-slate-200">{rec.action}</span>
                    <p className="text-[11px] text-slate-400 mt-0.5">{rec.impact}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
