import React, { useState } from 'react';
import { Radio, Plus, Play, XCircle, Clock, CheckCircle, AlertCircle, RefreshCw } from 'lucide-react';
import { Scan, ScanProfile } from '../types';

interface ScanManagerProps {
  scans: Scan[];
  onRefresh: () => void;
  onLaunchScan: (name: string, target: string, profile: ScanProfile, customPorts?: string) => Promise<void>;
  onCancelScan: (scanId: number) => Promise<void>;
}

export const ScanManager: React.FC<ScanManagerProps> = ({
  scans,
  onRefresh,
  onLaunchScan,
  onCancelScan,
}) => {
  const [showModal, setShowModal] = useState(false);
  const [scanName, setScanName] = useState('');
  const [target, setTarget] = useState('127.0.0.1');
  const [profile, setProfile] = useState<ScanProfile>('Top 100');
  const [customPorts, setCustomPorts] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!scanName.trim() || !target.trim()) {
      setErrorMsg('Scan name and target specification are required.');
      return;
    }
    setErrorMsg('');
    setSubmitting(true);
    try {
      await onLaunchScan(scanName, target, profile, customPorts);
      setShowModal(false);
      setScanName('');
      setTarget('127.0.0.1');
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to trigger scan');
    } finally {
      setSubmitting(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'Running':
        return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30 animate-pulse';
      case 'Completed':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'Cancelled':
        return 'bg-slate-800 text-slate-400 border-slate-700';
      case 'Failed':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      default:
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-slate-900/80 border border-slate-800 rounded-xl p-5">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">Vulnerability Scan Operations</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Configure target IP addresses, CIDR network blocks, and port profiles for automated inspection.
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <button
            onClick={onRefresh}
            className="p-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition"
            title="Refresh Scans"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            onClick={() => setShowModal(true)}
            className="px-4 py-2.5 rounded-lg text-xs font-semibold text-slate-950 bg-gradient-to-r from-cyan-400 to-teal-400 hover:from-cyan-300 hover:to-teal-300 transition shadow-md shadow-cyan-500/20 flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            <span>New Security Scan</span>
          </button>
        </div>
      </div>

      {/* Scans Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                <th className="py-3.5 px-4">Scan Name</th>
                <th className="py-3.5 px-4">Target / CIDR</th>
                <th className="py-3.5 px-4">Profile</th>
                <th className="py-3.5 px-4">Status & Phase</th>
                <th className="py-3.5 px-4">Progress</th>
                <th className="py-3.5 px-4">Hosts / Findings</th>
                <th className="py-3.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {scans.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400">
                    <Radio className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                    No vulnerability scans executed yet. Click "New Security Scan" to run your first assessment.
                  </td>
                </tr>
              ) : (
                scans.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3.5 px-4">
                      <div className="font-semibold text-white">{s.name}</div>
                      <div className="text-[11px] text-slate-500 font-mono">
                        {new Date(s.created_at).toLocaleString()}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-cyan-300 font-medium">
                      {s.target}
                    </td>
                    <td className="py-3.5 px-4 text-slate-300">
                      {s.profile}
                      {s.custom_ports && (
                        <div className="text-[10px] text-slate-500 truncate max-w-[120px]">
                          {s.custom_ports}
                        </div>
                      )}
                    </td>
                    <td className="py-3.5 px-4">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold uppercase border ${getStatusBadge(s.status)}`}>
                        {s.status}
                      </span>
                      <div className="text-[11px] text-slate-400 mt-1 truncate max-w-[150px]">
                        {s.current_phase}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 w-40">
                      <div className="flex items-center justify-between text-[10px] text-slate-400 mb-1">
                        <span>{Math.round(s.progress_percentage)}%</span>
                      </div>
                      <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-300 ${
                            s.status === 'Completed'
                              ? 'bg-emerald-400'
                              : s.status === 'Failed'
                              ? 'bg-rose-500'
                              : 'bg-cyan-400'
                          }`}
                          style={{ width: `${s.progress_percentage}%` }}
                        />
                      </div>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="text-slate-300">
                        <span className="font-semibold text-white">{s.hosts_scanned}</span> hosts scanned
                      </div>
                      <div className="text-[11px] text-rose-400 font-mono mt-0.5">
                        {s.vulnerabilities_found} vulnerabilities
                      </div>
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      {s.status === 'Running' || s.status === 'Pending' ? (
                        <button
                          onClick={() => onCancelScan(s.id)}
                          className="px-2.5 py-1 rounded bg-rose-500/10 text-rose-400 hover:bg-rose-500/20 border border-rose-500/30 transition text-[11px] font-semibold"
                        >
                          Cancel
                        </button>
                      ) : (
                        <span className="text-slate-500 text-[11px]">Finalized</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* New Scan Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-lg font-bold text-white tracking-tight">Configure New Security Scan</h3>
              <button
                onClick={() => setShowModal(false)}
                className="text-slate-400 hover:text-white transition"
              >
                <XCircle className="w-5 h-5" />
              </button>
            </div>

            {errorMsg && (
              <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-xs text-rose-400 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{errorMsg}</span>
              </div>
            )}

            <form onSubmit={handleLaunch} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                  Scan Name / Audit Reference
                </label>
                <input
                  type="text"
                  value={scanName}
                  onChange={(e) => setScanName(e.target.value)}
                  placeholder="e.g. DMZ Perimeter Audit"
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:border-cyan-500 transition"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                  Target (Single IP, CIDR, Range, or Hostname)
                </label>
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="127.0.0.1 or 192.168.1.0/24 or 10.0.0.1-10.0.0.20"
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-cyan-300 font-mono text-sm focus:outline-none focus:border-cyan-500 transition"
                  required
                />
                <span className="text-[11px] text-slate-500 mt-1 block">
                  Defaults to local loopback 127.0.0.1 for defensive assessment.
                </span>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                  Port Inspection Profile
                </label>
                <select
                  value={profile}
                  onChange={(e) => setProfile(e.target.value as ScanProfile)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:border-cyan-500 transition"
                >
                  <option value="Top 20">Top 20 Ports (Fastest Probe)</option>
                  <option value="Top 100">Top 100 Common Services (Recommended)</option>
                  <option value="Common Ports">Common Enterprise Ports</option>
                  <option value="Top 1000">Top 1000 Extended Range</option>
                  <option value="Custom Ports">Custom Port Range Definition</option>
                </select>
              </div>

              {profile === 'Custom Ports' && (
                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                    Custom Port Range
                  </label>
                  <input
                    type="text"
                    value={customPorts}
                    onChange={(e) => setCustomPorts(e.target.value)}
                    placeholder="e.g. 80, 443, 8000-8085, 9000"
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-cyan-300 font-mono text-sm focus:outline-none focus:border-cyan-500 transition"
                  />
                </div>
              )}

              <div className="pt-3 flex items-center justify-end gap-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 rounded-xl text-xs font-medium text-slate-400 hover:text-white bg-slate-800/80 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-5 py-2.5 rounded-xl text-xs font-semibold text-slate-950 bg-gradient-to-r from-cyan-400 to-teal-400 hover:from-cyan-300 hover:to-teal-300 disabled:opacity-50 transition flex items-center gap-2"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>{submitting ? 'Initiating Scan...' : 'Start Audit'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
