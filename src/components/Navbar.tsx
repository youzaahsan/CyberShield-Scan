import React from 'react';
import { Shield, Radio, Activity, Search, AlertTriangle, Network, FileText, Bell, LogOut, User as UserIcon } from 'lucide-react';
import { User } from '../types';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  currentUser: User | null;
  onLogout: () => void;
  activeScanCount: number;
  alertCount: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  currentUser,
  onLogout,
  activeScanCount,
  alertCount
}) => {
  const navItems = [
    { id: 'dashboard', label: 'Executive Overview', icon: Activity },
    { id: 'scans', label: 'Scan Operations', icon: Radio, badge: activeScanCount > 0 ? activeScanCount : undefined },
    { id: 'hosts', label: 'Host Inventory', icon: Search },
    { id: 'vulnerabilities', label: 'Vulnerability Hub', icon: AlertTriangle },
    { id: 'cve', label: 'CVE Intelligence', icon: Shield },
    { id: 'topology', label: 'Network Topology', icon: Network },
    { id: 'reports', label: 'Compliance Reports', icon: FileText },
  ];

  return (
    <header className="bg-slate-900/90 border-b border-slate-800 backdrop-blur sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-indigo-600 to-cyan-500 p-0.5 shadow-lg shadow-indigo-500/20 flex items-center justify-center">
              <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
                <Shield className="w-5 h-5 text-cyan-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-lg font-bold tracking-tight text-white">CyberShield</span>
                <span className="text-xs px-2 py-0.5 rounded-full font-semibold uppercase tracking-wider bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                  SCAN
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">Defensive Network Vulnerability Assessment</p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="hidden md:flex items-center gap-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`px-3 py-2 rounded-lg text-sm font-medium flex items-center gap-2 transition-all relative ${
                    isActive
                      ? 'bg-slate-800 text-cyan-400 border border-slate-700 shadow-sm'
                      : 'text-slate-300 hover:text-white hover:bg-slate-800/50'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                  {item.badge !== undefined && (
                    <span className="w-5 h-5 flex items-center justify-center rounded-full text-xs font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40 animate-pulse">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          {/* User profile & controls */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => setActiveTab('alerts')}
              className={`p-2 rounded-lg text-slate-300 hover:bg-slate-800 transition relative ${
                activeTab === 'alerts' ? 'bg-slate-800 text-cyan-400' : ''
              }`}
              title="Security Alerts"
            >
              <Bell className="w-5 h-5" />
              {alertCount > 0 && (
                <span className="absolute top-1 right-1 w-2.5 h-2.5 bg-rose-500 rounded-full ring-2 ring-slate-900" />
              )}
            </button>

            <div className="h-6 w-px bg-slate-800 hidden sm:block" />

            {currentUser ? (
              <div className="flex items-center gap-3">
                <div className="hidden sm:flex flex-col text-right">
                  <span className="text-xs font-semibold text-white">{currentUser.username}</span>
                  <span className="text-[10px] text-cyan-400 font-mono">{currentUser.role}</span>
                </div>
                <button
                  onClick={onLogout}
                  className="p-2 text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded-lg transition"
                  title="Sign out"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <UserIcon className="w-4 h-4 text-slate-400" />
                <span className="text-xs text-slate-400">Authorized Session</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Mobile navigation bar */}
      <div className="md:hidden flex overflow-x-auto px-4 py-2 gap-1 border-t border-slate-800/80 bg-slate-950/60 no-scrollbar">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`px-2.5 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap flex items-center gap-1.5 transition ${
                isActive
                  ? 'bg-slate-800 text-cyan-400 border border-slate-700'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{item.label}</span>
            </button>
          );
        })}
      </div>
    </header>
  );
};
