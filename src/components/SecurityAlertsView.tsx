import React from 'react';
import { Bell, CheckCircle2, AlertTriangle, Info, Clock } from 'lucide-react';
import { SecurityAlert } from '../types';

interface SecurityAlertsViewProps {
  alerts: SecurityAlert[];
  onMarkRead: (id: number) => Promise<void>;
}

export const SecurityAlertsView: React.FC<SecurityAlertsViewProps> = ({ alerts, onMarkRead }) => {
  return (
    <div className="space-y-6">
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
        <h2 className="text-xl font-bold text-white tracking-tight">Security Notifications & Audit Logs</h2>
        <p className="text-xs text-slate-400 mt-0.5">
          System integrity notifications, audit events, and anomalous perimeter triggers.
        </p>
      </div>

      <div className="bg-slate-900/80 border border-slate-800 rounded-xl divide-y divide-slate-800/80 overflow-hidden shadow-sm">
        {alerts.length === 0 ? (
          <div className="py-12 text-center text-slate-400 text-xs">
            No system security alerts logged.
          </div>
        ) : (
          alerts.map((a) => (
            <div
              key={a.id}
              className={`p-4 flex items-start justify-between gap-4 transition ${
                a.is_read ? 'opacity-60 bg-slate-950/30' : 'bg-slate-900/60'
              }`}
            >
              <div className="flex items-start gap-3">
                <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 flex items-center justify-center shrink-0 mt-0.5">
                  <Bell className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold text-white tracking-tight">{a.title}</span>
                    <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300">
                      {a.severity}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 mt-1">{a.message}</p>
                  <div className="text-[11px] text-slate-500 mt-1 flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    <span>{new Date(a.created_at).toLocaleString()}</span>
                  </div>
                </div>
              </div>

              {!a.is_read && (
                <button
                  onClick={() => onMarkRead(a.id)}
                  className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-semibold shrink-0 transition"
                >
                  Mark Read
                </button>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
};
