import React, { useState, useEffect } from 'react';
import { Shield, Search, ExternalLink, Database, AlertCircle } from 'lucide-react';
import { CVE } from '../types';
import { apiFetch } from '../api/client';

export const CVEIntelligence: React.FC = () => {
  const [cves, setCves] = useState<CVE[]>([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(false);
  const [selectedCve, setSelectedCve] = useState<CVE | null>(null);

  const fetchCves = async (query = '') => {
    setLoading(true);
    try {
      const endpoint = query ? `/cves?query=${encodeURIComponent(query)}` : '/cves?limit=50';
      const data = await apiFetch<CVE[]>(endpoint);
      setCves(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCves();
  }, []);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchCves(search);
  };

  return (
    <div className="space-y-6">
      {/* Search Header */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-xl font-bold text-white tracking-tight">CVE Intelligence Database</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Authoritative Common Vulnerabilities and Exposures dictionary with CVSS v3.1 metrics and exploit references.
            </p>
          </div>
        </div>

        <form onSubmit={handleSearch} className="flex gap-2.5">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
            <input
              type="text"
              placeholder="Search CVE ID (e.g. CVE-2021-44228), vendor, product, or keyword..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-white text-sm focus:outline-none focus:border-cyan-500 transition"
            />
          </div>
          <button
            type="submit"
            className="px-5 py-2.5 rounded-xl text-xs font-semibold text-slate-950 bg-gradient-to-r from-cyan-400 to-teal-400 hover:from-cyan-300 hover:to-teal-300 transition"
          >
            Search
          </button>
        </form>
      </div>

      {/* CVE Grid / List */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {loading ? (
          <div className="col-span-2 py-12 text-center text-slate-400 text-xs">
            Querying local CVE threat database...
          </div>
        ) : cves.length === 0 ? (
          <div className="col-span-2 py-12 text-center text-slate-400 text-xs">
            No CVE records found matching query.
          </div>
        ) : (
          cves.map((cve) => (
            <div
              key={cve.id}
              className="bg-slate-900/80 border border-slate-800 hover:border-slate-700 rounded-xl p-5 space-y-3 transition flex flex-col justify-between"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold text-sm text-cyan-300 tracking-tight">
                    {cve.cve_id}
                  </span>
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase border ${
                        cve.severity === 'CRITICAL'
                          ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                          : 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                      }`}
                    >
                      {cve.severity}
                    </span>
                    <span className="font-mono font-bold text-white text-xs">
                      CVSS {cve.cvss}
                    </span>
                  </div>
                </div>

                <div className="text-xs text-slate-400">
                  <span className="font-semibold text-slate-300">{cve.vendor} / {cve.product}</span>
                  {cve.cwe && <span className="ml-2 font-mono text-indigo-400">({cve.cwe})</span>}
                </div>

                <p className="text-xs text-slate-300 line-clamp-3 leading-relaxed">
                  {cve.description}
                </p>
              </div>

              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs">
                <span className="text-slate-500 text-[11px]">
                  Published: {cve.published_date || 'NVD Verified'}
                </span>
                {cve.references && (
                  <a
                    href={cve.references}
                    target="_blank"
                    rel="noreferrer"
                    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium transition"
                  >
                    <span>NVD Advisory</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
