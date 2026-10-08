"use client";

import React, { useState } from 'react';
import ModuleWrapper from '@/components/layout/ModuleWrapper';
import { FileText, Download, FileJson, Calendar, Loader2 } from 'lucide-react';

interface Report {
  name: string;
  date: string;
  size: string;
  type: 'PDF' | 'CSV';
}

export default function ReportsPage() {
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [isGenerating, setIsGenerating] = useState<string | null>(null);

  const mockReports: Report[] = [
    { name: 'Executive_Risk_Summary_Q4.pdf', date: '2026-10-01', size: '2.4 MB', type: 'PDF' },
    { name: 'Telemetry_Dump_Commerce_Node.csv', date: '2026-09-28', size: '14.1 MB', type: 'CSV' },
    { name: 'Remediation_Audit_Trail.pdf', date: '2026-09-15', size: '1.1 MB', type: 'PDF' },
  ];

  const handleGenerate = (type: 'PDF' | 'CSV') => {
    setIsGenerating(type);
    
    // Simulate generation delay
    setTimeout(() => {
      setIsGenerating(null);
      alert(`[SYSTEM] Successfully exported ${type} report for selected date range.`);
    }, 2000);
  };

  const handleDownload = (reportName: string) => {
    alert(`[SYSTEM] Initiating secure download stream for: ${reportName}`);
  };

  return (
    <ModuleWrapper 
      title="Executive Reporting" 
      description="Generate compliance-ready documentation and raw data exports from twin telemetry."
    >
      <div className="flex flex-col gap-8 font-mono text-xs">
        
        {/* Top Control Panel */}
        <div className="bg-zinc-900 border border-zinc-800 p-6 flex flex-col gap-6">
          
          {/* Date Range Picker */}
          <div className="flex flex-col md:flex-row gap-4 items-center justify-between border-b border-zinc-800 pb-6">
            <div className="flex items-center gap-2 text-zinc-400">
              <Calendar className="w-4 h-4" />
              <span className="uppercase tracking-widest font-bold">Reporting Window</span>
            </div>
            
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <span className="text-zinc-600 uppercase text-[10px]">Start</span>
                <input 
                  type="date"
                  value={startDate}
                  onChange={(e) => setStartDate(e.target.value)}
                  className="bg-zinc-950 border border-zinc-800 p-2 text-zinc-300 focus:outline-none focus:border-zinc-500 uppercase cursor-pointer"
                />
              </div>
              <span className="text-zinc-600">-</span>
              <div className="flex items-center gap-2">
                <span className="text-zinc-600 uppercase text-[10px]">End</span>
                <input 
                  type="date"
                  value={endDate}
                  onChange={(e) => setEndDate(e.target.value)}
                  className="bg-zinc-950 border border-zinc-800 p-2 text-zinc-300 focus:outline-none focus:border-zinc-500 uppercase cursor-pointer"
                />
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <button 
              onClick={() => handleGenerate('PDF')}
              disabled={isGenerating !== null}
              className="bg-zinc-950 border border-zinc-700 hover:border-red-900 hover:bg-zinc-900 p-6 flex flex-col items-center justify-center gap-3 transition-colors group disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <div className="p-3 bg-red-950/30 text-red-500 rounded-none border border-red-900/50 group-hover:bg-red-900/40 transition-colors">
                {isGenerating === 'PDF' ? <Loader2 className="w-6 h-6 animate-spin" /> : <FileText className="w-6 h-6" />}
              </div>
              <span className="text-zinc-200 font-bold uppercase tracking-widest text-xs">
                {isGenerating === 'PDF' ? 'Generating...' : '[ GENERATE PDF REPORT ]'}
              </span>
              <span className="text-zinc-500 text-[10px] text-center px-4 uppercase">Synthesize Executive Summary & Topology Map</span>
            </button>
            
            <button 
              onClick={() => handleGenerate('CSV')}
              disabled={isGenerating !== null}
              className="bg-zinc-950 border border-zinc-700 hover:border-blue-900 hover:bg-zinc-900 p-6 flex flex-col items-center justify-center gap-3 transition-colors group disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <div className="p-3 bg-blue-950/30 text-blue-500 rounded-none border border-blue-900/50 group-hover:bg-blue-900/40 transition-colors">
                {isGenerating === 'CSV' ? <Loader2 className="w-6 h-6 animate-spin" /> : <FileJson className="w-6 h-6" />}
              </div>
              <span className="text-zinc-200 font-bold uppercase tracking-widest text-xs">
                {isGenerating === 'CSV' ? 'Exporting...' : '[ EXPORT CSV ]'}
              </span>
              <span className="text-zinc-500 text-[10px] text-center px-4 uppercase">Extract full telemetry logs for SIEM ingestion</span>
            </button>
          </div>
        </div>

        {/* Report History */}
        <div>
          <h2 className="text-[10px] text-zinc-500 uppercase tracking-widest mb-3 font-bold border-b border-zinc-800 pb-2">
            Document Archive
          </h2>
          <div className="border border-zinc-800 bg-zinc-950 divide-y divide-zinc-800">
            {mockReports.map((report, idx) => (
              <div key={idx} className="flex items-center justify-between p-4 hover:bg-zinc-900 transition-colors group">
                <div className="flex items-center gap-4">
                  <div className={`p-2 border ${report.type === 'PDF' ? 'border-red-900/50 bg-red-950/20 text-red-500' : 'border-blue-900/50 bg-blue-950/20 text-blue-500'}`}>
                    {report.type === 'PDF' ? <FileText className="w-4 h-4" /> : <FileJson className="w-4 h-4" />}
                  </div>
                  <div>
                    <div className="text-zinc-300 font-bold mb-1 group-hover:text-white transition-colors">{report.name}</div>
                    <div className="text-[10px] text-zinc-600 uppercase tracking-wider">{report.date} • {report.size}</div>
                  </div>
                </div>
                <button 
                  onClick={() => handleDownload(report.name)}
                  className="px-4 py-2 bg-zinc-900 border border-zinc-700 text-zinc-400 hover:text-white hover:border-zinc-500 transition-colors text-[10px] uppercase font-bold tracking-widest flex items-center gap-2"
                >
                  <Download className="w-3 h-3" />
                  [ DOWNLOAD ]
                </button>
              </div>
            ))}
          </div>
        </div>

      </div>
    </ModuleWrapper>
  );
}
