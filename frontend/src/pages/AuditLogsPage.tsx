import React, { useState, useEffect } from 'react';
import {
  ScrollText, RefreshCw, Filter, ShieldCheck, User,
  Calendar, Lock, Terminal
} from 'lucide-react';
import { api } from '../services/api';
import { AuditEvent } from '../types';

export const AuditLogsPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterType, setFilterType] = useState('');

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const data = await api.getAuditLogs(filterType || undefined);
      setLogs(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [filterType]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-100 flex items-center">
            Security Audit Trail & Compliance Ledger
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Tamper-resistant append-only event stream recording all assessments, validations, and approvals
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="px-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          >
            <option value="">All Event Streams</option>
            <option value="auth">Authentication</option>
            <option value="assessment">Assessment</option>
            <option value="validation">Validation Runs</option>
            <option value="remediation">Remediation Approvals</option>
            <option value="twin">Digital Twins</option>
          </select>
          <button
            onClick={fetchLogs}
            className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-cyan-400 text-xs flex items-center space-x-1.5 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Refresh</span>
          </button>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="cyber-card bg-[#0c1222] border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#090d19] border-b border-slate-800 text-slate-400 uppercase text-[10px]">
              <tr>
                <th className="px-5 py-3.5">Timestamp (UTC)</th>
                <th className="px-5 py-3.5">Stream Category</th>
                <th className="px-5 py-3.5">Security Action</th>
                <th className="px-5 py-3.5">Operator</th>
                <th className="px-5 py-3.5">Origin IP</th>
                <th className="px-5 py-3.5">Structured Event Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {loading ? (
                <tr>
                  <td colSpan={6} className="px-5 py-12 text-center text-slate-500">
                    <RefreshCw className="w-5 h-5 mx-auto animate-spin text-cyan-400 mb-2" />
                    Querying audit log ledger...
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-5 py-12 text-center text-slate-500">
                    No audit records found matching the criteria.
                  </td>
                </tr>
              ) : (
                logs.map((ev) => (
                  <tr key={ev.id} className="hover:bg-slate-900/60">
                    <td className="px-5 py-3.5 text-slate-400 text-[11px]">
                      {new Date(ev.created_at).toISOString().replace('T', ' ').slice(0, 19)}
                    </td>
                    <td className="px-5 py-3.5">
                      <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-slate-800 text-cyan-400 border border-slate-700">
                        {ev.event_type}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 text-slate-200 font-bold">{ev.action}</td>
                    <td className="px-5 py-3.5 text-slate-300">{ev.user_email}</td>
                    <td className="px-5 py-3.5 text-slate-400">{ev.ip_address}</td>
                    <td className="px-5 py-3.5">
                      <span className="text-slate-400 text-[11px] truncate max-w-xs block" title={JSON.stringify(ev.details)}>
                        {JSON.stringify(ev.details)}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
