import React from 'react';
import { Network, Server, Globe, Shield, RefreshCw } from 'lucide-react';
import { TopologyData } from '../types';

interface TopologyViewerProps {
  topology: TopologyData | null;
  onRefresh: () => void;
}

export const TopologyViewer: React.FC<TopologyViewerProps> = ({ topology, onRefresh }) => {
  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-slate-900/80 border border-slate-800 rounded-xl p-5">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">Interactive Subnet & Perimeter Topology</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Network architectural graph visualizing the gateway ingress, active nodes, and vulnerable perimeter boundaries.
          </p>
        </div>
        <button
          onClick={onRefresh}
          className="p-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition flex items-center gap-2 text-xs"
        >
          <RefreshCw className="w-4 h-4" />
          <span>Reload Topology</span>
        </button>
      </div>

      {/* Topology Canvas Container */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-8 min-h-[500px] flex flex-col items-center justify-center relative overflow-hidden">
        {/* Subtle SVG Grid Background */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:3rem_3rem] opacity-20 pointer-events-none" />

        {(!topology || topology.nodes.length === 0) ? (
          <div className="text-center text-slate-400 relative z-10">
            <Network className="w-12 h-12 text-slate-600 mx-auto mb-3" />
            <h3 className="text-base font-semibold text-white">No active network topology mapped</h3>
            <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
              Run a scan across your local subnet or target IPs to automatically populate and connect nodes.
            </p>
          </div>
        ) : (
          <div className="w-full max-w-4xl space-y-12 relative z-10">
            {/* Level 1: Internet / External Ingress */}
            <div className="flex justify-center">
              <div className="bg-slate-950/90 border border-indigo-500/40 rounded-2xl p-4 flex items-center gap-3 shadow-lg shadow-indigo-500/10">
                <div className="w-10 h-10 rounded-xl bg-indigo-500/20 border border-indigo-500/40 flex items-center justify-center">
                  <Globe className="w-5 h-5 text-indigo-400" />
                </div>
                <div>
                  <div className="text-xs font-bold text-white uppercase tracking-wider">Perimeter Gateway</div>
                  <div className="text-[11px] font-mono text-indigo-300">0.0.0.0/0 (Internet Ingress)</div>
                </div>
              </div>
            </div>

            {/* Connecting Visual Divider Line */}
            <div className="w-0.5 h-8 bg-gradient-to-b from-indigo-500 to-cyan-500 mx-auto" />

            {/* Level 2: Subnet Host Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
              {topology.nodes
                .filter((n) => n.type !== 'internet' && n.type !== 'gateway')
                .map((node) => {
                  const isHighRisk = (node.risk_score || 0) >= 60;
                  const isMedRisk = (node.risk_score || 0) >= 25 && !isHighRisk;

                  return (
                    <div
                      key={node.id}
                      className={`bg-slate-950/90 border rounded-xl p-4 transition-all shadow-md relative ${
                        isHighRisk
                          ? 'border-rose-500/50 shadow-rose-500/10'
                          : isMedRisk
                          ? 'border-amber-500/40 shadow-amber-500/10'
                          : 'border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2.5">
                          <Server className={`w-4 h-4 ${isHighRisk ? 'text-rose-400' : 'text-cyan-400'}`} />
                          <span className="font-mono text-xs font-bold text-white">{node.ip || node.label}</span>
                        </div>
                        {node.risk_score !== undefined && (
                          <span
                            className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${
                              isHighRisk
                                ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                                : isMedRisk
                                ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                                : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                            }`}
                          >
                            Risk {Math.round(node.risk_score)}
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-slate-400 truncate">{node.label}</div>
                    </div>
                  );
                })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
