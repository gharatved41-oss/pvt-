import React, { useState, useEffect } from 'react';
import { Server, CheckCircle2, AlertTriangle, RefreshCw, X, Radio, ArrowRight, ShieldCheck } from 'lucide-react';
import { API_BASE, DEFAULT_LOCAL_API, DEFAULT_LIVE_TUNNEL_API, setCustomApiBase, checkBackendHealth } from '../config/api';

export default function BackendStatusModal({ isOpen, onClose, onEndpointChanged }) {
  const [currentBase, setCurrentBase] = useState(API_BASE);
  const [customInput, setCustomInput] = useState(API_BASE);
  const [status, setStatus] = useState('checking'); // 'checking' | 'connected' | 'error'
  const [latency, setLatency] = useState(null);
  const [healthData, setHealthData] = useState(null);
  const [errorDetails, setErrorDetails] = useState('');
  const [isTesting, setIsTesting] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setCurrentBase(API_BASE);
      setCustomInput(API_BASE);
      runHealthCheck(API_BASE);
    }
  }, [isOpen]);

  const runHealthCheck = async (targetUrl) => {
    setIsTesting(true);
    setStatus('checking');
    setErrorDetails('');
    const res = await checkBackendHealth(targetUrl);
    setIsTesting(false);
    if (res.ok) {
      setStatus('connected');
      setLatency(res.latencyMs);
      setHealthData(res.data);
    } else {
      setStatus('error');
      setLatency(res.latencyMs);
      setErrorDetails(res.error);
      setHealthData(null);
    }
  };

  const handleApplyUrl = (targetUrl) => {
    const url = targetUrl.trim();
    setCustomApiBase(url);
    setCurrentBase(url);
    setCustomInput(url);
    runHealthCheck(url);
    if (onEndpointChanged) onEndpointChanged(url);
  };

  const handleResetDefault = () => {
    setCustomApiBase('');
    const newBase = API_BASE;
    setCurrentBase(newBase);
    setCustomInput(newBase);
    runHealthCheck(newBase);
    if (onEndpointChanged) onEndpointChanged(newBase);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-white border border-slate-200 rounded-lg shadow-xl w-full max-w-lg overflow-hidden">
        
        {/* Header */}
        <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between bg-slate-50">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 bg-[#0B1F44] text-white rounded">
              <Server className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-slate-900">Backend Gateway Diagnostics</h3>
              <p className="text-xs text-slate-500">Configure and verify connection to VulnTwin AI Engine</p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-slate-600 rounded hover:bg-slate-200/50 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-5 text-sm">
          
          {/* Active Status Banner */}
          <div className={`p-3.5 rounded border flex items-center justify-between ${
            status === 'connected'
              ? 'bg-emerald-50/70 border-emerald-200 text-emerald-900'
              : status === 'checking'
              ? 'bg-amber-50/70 border-amber-200 text-amber-900'
              : 'bg-rose-50/70 border-rose-200 text-rose-900'
          }`}>
            <div className="flex items-center gap-2.5">
              {status === 'connected' ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0" />
              ) : status === 'checking' ? (
                <RefreshCw className="w-5 h-5 text-amber-600 animate-spin shrink-0" />
              ) : (
                <AlertTriangle className="w-5 h-5 text-rose-600 shrink-0" />
              )}
              <div>
                <div className="font-medium text-xs">
                  {status === 'connected' && 'Backend Connected & Operational'}
                  {status === 'checking' && 'Testing Connection...'}
                  {status === 'error' && 'Backend Unreachable'}
                </div>
                <div className="text-[11px] font-mono text-slate-600 truncate max-w-xs mt-0.5">
                  {currentBase}
                </div>
              </div>
            </div>

            <div className="text-right">
              {latency !== null && (
                <div className="text-xs font-mono font-semibold">
                  {latency} ms
                </div>
              )}
              <div className="text-[10px] uppercase font-bold tracking-wider text-slate-500">
                {status === 'connected' ? healthData?.version || 'v3.0.0' : 'Offline'}
              </div>
            </div>
          </div>

          {errorDetails && (
            <div className="p-2.5 bg-rose-50 border border-rose-200 rounded text-xs text-rose-700 font-mono">
              Error: {errorDetails}
            </div>
          )}

          {/* Quick Preset Buttons */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-slate-700 block">
              Connection Presets
            </label>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => handleApplyUrl(DEFAULT_LIVE_TUNNEL_API)}
                className={`p-2.5 text-left border rounded text-xs transition-colors ${
                  currentBase === DEFAULT_LIVE_TUNNEL_API
                    ? 'border-[#0B1F44] bg-slate-50 font-medium ring-1 ring-[#0B1F44]'
                    : 'border-slate-200 hover:border-slate-300'
                }`}
              >
                <div className="font-semibold text-slate-800 flex items-center justify-between">
                  <span>Live HTTPS Tunnel</span>
                  <span className="text-[10px] bg-emerald-100 text-emerald-800 px-1 rounded">Cloud</span>
                </div>
                <div className="text-[11px] text-slate-500 font-mono truncate mt-1">
                  {DEFAULT_LIVE_TUNNEL_API}
                </div>
              </button>

              <button
                type="button"
                onClick={() => handleApplyUrl(DEFAULT_LOCAL_API)}
                className={`p-2.5 text-left border rounded text-xs transition-colors ${
                  currentBase === DEFAULT_LOCAL_API
                    ? 'border-[#0B1F44] bg-slate-50 font-medium ring-1 ring-[#0B1F44]'
                    : 'border-slate-200 hover:border-slate-300'
                }`}
              >
                <div className="font-semibold text-slate-800 flex items-center justify-between">
                  <span>Localhost Server</span>
                  <span className="text-[10px] bg-slate-100 text-slate-700 px-1 rounded">Dev</span>
                </div>
                <div className="text-[11px] text-slate-500 font-mono truncate mt-1">
                  {DEFAULT_LOCAL_API}
                </div>
              </button>
            </div>
          </div>

          {/* Custom URL Input */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-slate-700 block">
              Custom API Base URL
            </label>
            <div className="flex gap-2">
              <input
                type="url"
                value={customInput}
                onChange={(e) => setCustomInput(e.target.value)}
                placeholder="https://..."
                className="flex-1 px-3 py-1.5 text-xs font-mono border border-slate-300 rounded focus:outline-none focus:border-[#0B1F44]"
              />
              <button
                type="button"
                onClick={() => handleApplyUrl(customInput)}
                className="px-3 py-1.5 bg-[#0B1F44] hover:bg-[#152e61] text-white text-xs font-medium rounded transition-colors"
              >
                Apply
              </button>
            </div>
          </div>

        </div>

        {/* Footer Actions */}
        <div className="px-5 py-3 bg-slate-50 border-t border-slate-100 flex items-center justify-between">
          <button
            type="button"
            onClick={handleResetDefault}
            className="text-xs text-slate-600 hover:text-slate-900 underline"
          >
            Reset to Auto-Detect
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={isTesting}
              onClick={() => runHealthCheck(currentBase)}
              className="px-3 py-1.5 border border-slate-300 hover:bg-slate-100 text-slate-700 rounded text-xs font-medium flex items-center gap-1.5 transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isTesting ? 'animate-spin' : ''}`} />
              Ping
            </button>
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-1.5 bg-slate-800 hover:bg-slate-900 text-white rounded text-xs font-medium transition-colors"
            >
              Done
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
