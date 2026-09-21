import React, { useState } from 'react';
import { FileText, Download, CheckCircle2, Shield, AlertTriangle, Printer } from 'lucide-react';
import { Scan, Host, Vulnerability, RiskAssessment } from '../types';

interface ComplianceReportsProps {
  scans: Scan[];
  hosts: Host[];
  vulnerabilities: Vulnerability[];
  riskData: RiskAssessment | null;
}

export const ComplianceReports: React.FC<ComplianceReportsProps> = ({
  scans,
  hosts,
  vulnerabilities,
  riskData,
}) => {
  const [reportTitle, setReportTitle] = useState('CyberShield Network Security Assessment');
  const [assessorName, setAssessorName] = useState('CyberShield Defense Team');

  const handlePrint = () => {
    window.print();
  };

  const handleExportJSON = () => {
    const reportObj = {
      title: reportTitle,
      assessor: assessorName,
      generated_at: new Date().toISOString(),
      overall_risk_score: riskData?.overall_score,
      overall_risk_level: riskData?.overall_level,
      summary: {
        total_hosts: hosts.length,
        total_open_ports: hosts.reduce((a, b) => a + (b.ports?.length || 0), 0),
        total_vulnerabilities: vulnerabilities.length,
        critical_vulnerabilities: vulnerabilities.filter((v) => v.severity === 'CRITICAL').length,
        high_vulnerabilities: vulnerabilities.filter((v) => v.severity === 'HIGH').length,
      },
      hosts,
      vulnerabilities,
      recommendations: riskData?.recommendations_priority,
    };

    const blob = new Blob([JSON.stringify(reportObj, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cybershield-security-audit-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Configuration Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-slate-900/80 border border-slate-800 rounded-xl p-5">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">Executive Compliance & Audit Reports</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Export comprehensive vulnerability assessments formatted for C-level presentation and compliance audits.
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <button
            onClick={handleExportJSON}
            className="px-4 py-2.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition flex items-center gap-2"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
          <button
            onClick={handlePrint}
            className="px-5 py-2.5 rounded-lg text-xs font-semibold text-slate-950 bg-gradient-to-r from-cyan-400 to-teal-400 hover:from-cyan-300 hover:to-teal-300 transition shadow-md shadow-cyan-500/20 flex items-center gap-2"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print / PDF</span>
          </button>
        </div>
      </div>

      {/* Printable Report Document Card */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-8 max-w-4xl mx-auto shadow-2xl space-y-8 print:bg-white print:text-black print:border-none print:shadow-none">
        {/* Document Header */}
        <div className="flex items-start justify-between border-b border-slate-800 pb-6 print:border-black">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Shield className="w-6 h-6 text-cyan-400 print:text-black" />
              <span className="text-xs font-bold uppercase tracking-widest text-cyan-400 print:text-black">
                DEFENSIVE AUDIT REPORT
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white print:text-black tracking-tight">
              {reportTitle}
            </h1>
            <p className="text-xs text-slate-400 print:text-gray-600 mt-1">
              Prepared by: {assessorName} • Generated: {new Date().toLocaleDateString()}
            </p>
          </div>
          <div className="text-right">
            <span className="text-xs font-mono uppercase font-bold px-2.5 py-1 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/30 print:border-black print:text-black">
              RESTRICTED / DEFENSIVE
            </span>
          </div>
        </div>

        {/* Executive Summary Section */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold text-white print:text-black uppercase tracking-wider">
            1. Executive Summary & Composite Risk
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-slate-950/60 print:bg-gray-100 p-4 rounded-xl border border-slate-800 print:border-gray-300">
              <div className="text-[11px] font-semibold text-slate-400 uppercase">Composite Risk Score</div>
              <div className="text-2xl font-extrabold text-cyan-400 print:text-black mt-1">
                {riskData ? Math.round(riskData.overall_score) : 0} / 100
              </div>
              <div className="text-[10px] text-slate-500 uppercase font-mono">{riskData?.overall_level}</div>
            </div>

            <div className="bg-slate-950/60 print:bg-gray-100 p-4 rounded-xl border border-slate-800 print:border-gray-300">
              <div className="text-[11px] font-semibold text-slate-400 uppercase">Perimeter Assets</div>
              <div className="text-2xl font-extrabold text-white print:text-black mt-1">
                {hosts.length}
              </div>
              <div className="text-[10px] text-slate-500 uppercase font-mono">Discovered Hosts</div>
            </div>

            <div className="bg-slate-950/60 print:bg-gray-100 p-4 rounded-xl border border-slate-800 print:border-gray-300">
              <div className="text-[11px] font-semibold text-slate-400 uppercase">Open Sockets</div>
              <div className="text-2xl font-extrabold text-white print:text-black mt-1">
                {hosts.reduce((a, b) => a + (b.ports?.length || 0), 0)}
              </div>
              <div className="text-[10px] text-slate-500 uppercase font-mono">Active Ports</div>
            </div>

            <div className="bg-slate-950/60 print:bg-gray-100 p-4 rounded-xl border border-slate-800 print:border-gray-300">
              <div className="text-[11px] font-semibold text-slate-400 uppercase">Critical Findings</div>
              <div className="text-2xl font-extrabold text-rose-400 print:text-red-600 mt-1">
                {vulnerabilities.filter((v) => v.severity === 'CRITICAL').length}
              </div>
              <div className="text-[10px] text-slate-500 uppercase font-mono">Urgent Patching</div>
            </div>
          </div>
        </div>

        {/* Priority Remediation Roadmap */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold text-white print:text-black uppercase tracking-wider">
            2. Strategic Remediation Roadmap
          </h2>
          <div className="space-y-2.5">
            {riskData?.recommendations_priority.map((r) => (
              <div
                key={r.priority}
                className="bg-slate-950/60 print:bg-gray-50 border border-slate-800 print:border-gray-200 rounded-xl p-3.5 flex items-start gap-3"
              >
                <div className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-300 font-bold flex items-center justify-center text-xs shrink-0 mt-0.5 print:bg-black print:text-white">
                  {r.priority}
                </div>
                <div>
                  <div className="text-xs font-bold text-white print:text-black">{r.action}</div>
                  <div className="text-[11px] text-slate-400 print:text-gray-600 mt-0.5">{r.impact}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Vulnerability Findings Catalog */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold text-white print:text-black uppercase tracking-wider">
            3. Detailed Vulnerability Inventory ({vulnerabilities.length})
          </h2>
          <div className="space-y-2">
            {vulnerabilities.map((v) => (
              <div
                key={v.id}
                className="bg-slate-950/60 print:bg-gray-50 border border-slate-800 print:border-gray-200 rounded-xl p-4 space-y-1.5"
              >
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-white print:text-black">{v.title}</span>
                  <span className="font-mono text-cyan-300 print:text-black font-semibold">
                    {v.severity} • CVSS {v.cvss}
                  </span>
                </div>
                <div className="text-[11px] text-slate-400 print:text-gray-600">
                  <span className="font-semibold text-slate-300 print:text-black">Impact: </span>
                  {v.impact}
                </div>
                <div className="text-[11px] text-emerald-400 print:text-green-800">
                  <span className="font-semibold">Remediation: </span>
                  {v.recommendation}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
