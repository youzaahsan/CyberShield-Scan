import React, { useState } from 'react';
import { Server, Shield, Globe, Terminal, Lock, ChevronRight, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { Host, Port } from '../types';

interface HostExplorerProps {
  hosts: Host[];
}

export const HostExplorer: React.FC<HostExplorerProps> = ({ hosts }) => {
  const [selectedHost, setSelectedHost] = useState<Host | null>(hosts.length > 0 ? hosts[0] : null);
  const [filterIp, setFilterIp] = useState('');

  const filteredHosts = hosts.filter(
    (h) =>
      h.ip_address.toLowerCase().includes(filterIp.toLowerCase()) ||
      (h.hostname && h.hostname.toLowerCase().includes(filterIp.toLowerCase())) ||
      (h.os_name && h.os_name.toLowerCase().includes(filterIp.toLowerCase()))
  );

  const getRiskBadge = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'HIGH':
        return 'bg-orange-500/10 text-orange-400 border-orange-500/30';
      case 'MEDIUM':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      default:
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-slate-900/80 border border-slate-800 rounded-xl p-5">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">Discovered Host Inventory</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Detailed asset breakdown with operating system fingerprints, open TCP/UDP sockets, and TLS cipher evaluations.
          </p>
        </div>
        <div className="w-full sm:w-64">
          <input
            type="text"
            placeholder="Filter IP, hostname, OS..."
            value={filterIp}
            onChange={(e) => setFilterIp(e.target.value)}
            className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-white text-xs focus:outline-none focus:border-cyan-500 transition"
          />
        </div>
      </div>

      {hosts.length === 0 ? (
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-12 text-center text-slate-400">
          <Server className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <h3 className="text-sm font-semibold text-white">No hosts discovered yet</h3>
          <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
            Execute a network scan in the Scan Operations tab to inspect perimeter devices and populate inventory.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Host List (1 Col) */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-2 max-h-[700px] overflow-y-auto">
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider px-2 mb-2">
              Discovered Assets ({filteredHosts.length})
            </div>
            {filteredHosts.map((h) => {
              const isSelected = selectedHost?.id === h.id;
              return (
                <button
                  key={h.id}
                  onClick={() => setSelectedHost(h)}
                  className={`w-full text-left p-3.5 rounded-xl border transition flex items-center justify-between gap-2 ${
                    isSelected
                      ? 'bg-slate-800 border-cyan-500/50 shadow-md shadow-cyan-500/10'
                      : 'bg-slate-950/60 border-slate-800/80 hover:border-slate-700'
                  }`}
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm font-bold text-white tracking-tight">
                        {h.ip_address}
                      </span>
                      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase ${getRiskBadge(h.risk_level)}`}>
                        {h.risk_level} ({Math.round(h.risk_score)})
                      </span>
                    </div>
                    <div className="text-xs text-slate-400 truncate max-w-[200px]">
                      {h.hostname || 'No reverse DNS PTR'}
                    </div>
                    <div className="text-[11px] text-cyan-400/90 font-medium truncate max-w-[200px]">
                      {h.os_name}
                    </div>
                  </div>
                  <ChevronRight className={`w-4 h-4 transition ${isSelected ? 'text-cyan-400' : 'text-slate-600'}`} />
                </button>
              );
            })}
          </div>

          {/* Host Deep-Dive Details (2 Cols) */}
          <div className="lg:col-span-2 space-y-6">
            {selectedHost ? (
              <>
                {/* Host Metadata Card */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 shadow-sm space-y-5">
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
                    <div>
                      <div className="flex items-center gap-3">
                        <span className="text-2xl font-extrabold font-mono text-white tracking-tight">
                          {selectedHost.ip_address}
                        </span>
                        <span className={`text-xs font-bold px-2 py-0.5 rounded-full border uppercase ${getRiskBadge(selectedHost.risk_level)}`}>
                          Risk: {selectedHost.risk_level} ({Math.round(selectedHost.risk_score)}/100)
                        </span>
                      </div>
                      <span className="text-xs text-slate-400 mt-1 block font-mono">
                        Hostname: {selectedHost.hostname || 'None resolved'}
                      </span>
                    </div>
                    <div className="text-right text-xs text-slate-400">
                      <div>Discovered: {new Date(selectedHost.discovered_at).toLocaleTimeString()}</div>
                      <div className="text-emerald-400 font-semibold mt-0.5">● Status: {selectedHost.status}</div>
                    </div>
                  </div>

                  {/* OS Fingerprint Box */}
                  <div className="bg-slate-950/70 border border-slate-800/80 rounded-xl p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                        <Globe className="w-4 h-4 text-cyan-400" />
                        OS Fingerprint & Detection
                      </span>
                      <span className="text-[11px] font-mono text-cyan-300 font-semibold">
                        Confidence: {selectedHost.os_confidence}
                      </span>
                    </div>
                    <div className="text-sm font-semibold text-white">{selectedHost.os_name}</div>
                    {selectedHost.os_evidence && (
                      <p className="text-xs text-slate-400 mt-1 font-mono bg-slate-900/60 p-2 rounded border border-slate-800/50">
                        Evidence: {selectedHost.os_evidence}
                      </p>
                    )}
                  </div>
                </div>

                {/* Ports & Services Inspection Table */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 shadow-sm space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-base font-bold text-white tracking-tight">
                        Open Ports & Active Services ({selectedHost.ports?.length || 0})
                      </h3>
                      <p className="text-xs text-slate-400">
                        Service banners, cryptographic suites, and missing HTTP headers
                      </p>
                    </div>
                  </div>

                  {(!selectedHost.ports || selectedHost.ports.length === 0) ? (
                    <div className="py-8 text-center text-slate-400 text-xs">
                      No open ports detected on this host.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {selectedHost.ports.map((p) => (
                        <div
                          key={p.id}
                          className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4 space-y-3"
                        >
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/50 pb-2">
                            <div className="flex items-center gap-2.5">
                              <span className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 font-mono font-bold flex items-center justify-center text-xs">
                                {p.port_number}
                              </span>
                              <div>
                                <span className="text-sm font-bold text-white tracking-tight">
                                  {p.service_name.toUpperCase()}
                                </span>
                                <span className="text-xs text-slate-500 font-mono ml-2">({p.protocol})</span>
                              </div>
                            </div>
                            <span className="text-xs font-semibold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 self-start sm:self-center">
                              {p.state}
                            </span>
                          </div>

                          {/* Banner & Product info */}
                          {p.banner && (
                            <div className="text-xs font-mono bg-slate-900/80 text-slate-300 p-2.5 rounded border border-slate-800 overflow-x-auto">
                              <span className="text-slate-500 select-none">Banner: </span>
                              {p.banner}
                            </div>
                          )}

                          {/* TLS & HTTP Security Breakdown */}
                          {(p.tls_version || p.missing_headers) && (
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs pt-1">
                              {p.tls_version && (
                                <div className="bg-slate-900/60 p-2.5 rounded border border-slate-800 space-y-1">
                                  <div className="flex items-center gap-1.5 text-cyan-400 font-semibold">
                                    <Lock className="w-3.5 h-3.5" />
                                    <span>TLS Inspection</span>
                                  </div>
                                  <div className="font-mono text-slate-300">{p.tls_version}</div>
                                  {p.tls_cipher && (
                                    <div className="text-[11px] text-slate-400 truncate">
                                      Cipher: {p.tls_cipher}
                                    </div>
                                  )}
                                </div>
                              )}

                              {p.missing_headers && (
                                <div className="bg-slate-900/60 p-2.5 rounded border border-slate-800 space-y-1">
                                  <div className="flex items-center gap-1.5 text-amber-400 font-semibold">
                                    <AlertTriangle className="w-3.5 h-3.5" />
                                    <span>Missing Web Headers</span>
                                  </div>
                                  <div className="text-[11px] text-slate-400">
                                    {p.missing_headers}
                                  </div>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </>
            ) : (
              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-12 text-center text-slate-400">
                Select a host from the list to view its open sockets and security posture.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
