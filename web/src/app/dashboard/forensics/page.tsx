"use client";

import React, { useState, useRef } from 'react';
import ModuleWrapper from '@/components/layout/ModuleWrapper';
import { UploadCloud, FileSearch, Loader2, File, CheckCircle } from 'lucide-react';

type UploadStatus = 'idle' | 'analyzing' | 'complete';

export default function ForensicsPage() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadStatus, setUploadStatus] = useState<UploadStatus>('idle');
  const [isDragging, setIsDragging] = useState(false);
  
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileSelection(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFileSelection(e.target.files[0]);
    }
  };

  const handleFileSelection = (file: File) => {
    setSelectedFile(file);
    setUploadStatus('idle');
  };

  const initiateAnalysis = () => {
    if (!selectedFile) return;
    setUploadStatus('analyzing');
    
    // Simulate backend sandboxing delay
    setTimeout(() => {
      setUploadStatus('complete');
    }, 2500);
  };

  // Mock SHA256 based on filename length (just for visual representation)
  const getMockHash = (name: string) => {
    const chars = 'abcdef0123456789';
    let hash = '';
    for (let i = 0; i < 64; i++) {
      hash += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return hash;
  };

  return (
    <ModuleWrapper 
      title="File & OS Forensics" 
      description="Static and dynamic analysis engine for suspect binaries, configurations, and memory dumps."
    >
      <div className="flex flex-col gap-6 font-mono text-xs">
        
        {/* Hidden File Input */}
        <input 
          type="file" 
          ref={fileInputRef} 
          onChange={handleFileChange} 
          className="hidden" 
          accept=".exe,.elf,.pcap,.dmp,.txt,.log"
        />

        {/* Drag and Drop Zone */}
        <div 
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => !selectedFile && fileInputRef.current?.click()}
          className={`border-2 border-dashed h-64 flex flex-col items-center justify-center text-center transition-colors ${
            isDragging 
              ? 'border-blue-500 bg-blue-950/20' 
              : selectedFile 
                ? 'border-zinc-700 bg-zinc-900/50' 
                : 'border-zinc-700 bg-zinc-900/30 hover:bg-zinc-900 cursor-pointer'
          }`}
        >
          {!selectedFile ? (
            <>
              <div className="bg-zinc-950 p-4 rounded-full border border-zinc-800 mb-4 pointer-events-none">
                <UploadCloud className={`w-8 h-8 ${isDragging ? 'text-blue-500' : 'text-zinc-400'}`} />
              </div>
              <h3 className="text-zinc-200 font-bold uppercase tracking-widest mb-2 pointer-events-none">
                {isDragging ? 'Drop Artifact Here' : 'Upload Suspect Artifact'}
              </h3>
              <p className="text-zinc-500 text-xs font-mono max-w-md mx-auto leading-relaxed pointer-events-none">
                Drag and drop executables (.exe, .elf), PCAP files, or memory dumps here. 
                Automated static unpacking and Yara rule processing will commence immediately.
              </p>
              <div className="mt-6 pointer-events-none">
                <span className="bg-zinc-800 text-zinc-300 px-4 py-2 text-xs uppercase tracking-widest transition-colors font-bold">
                  Browse Files
                </span>
              </div>
            </>
          ) : (
            <div className="flex flex-col items-center w-full max-w-lg px-8">
              <div className="bg-emerald-950/30 border border-emerald-900/50 p-4 rounded-full mb-4">
                <File className="w-8 h-8 text-emerald-500" />
              </div>
              <div className="w-full bg-zinc-950 border border-zinc-800 p-4 text-left mb-6">
                <div className="flex justify-between border-b border-zinc-800 pb-2 mb-2">
                  <span className="text-zinc-500 uppercase tracking-wider text-[10px] font-bold">Filename</span>
                  <span className="text-zinc-200 font-bold truncate ml-4">{selectedFile.name}</span>
                </div>
                <div className="flex justify-between border-b border-zinc-800 pb-2 mb-2">
                  <span className="text-zinc-500 uppercase tracking-wider text-[10px] font-bold">Size</span>
                  <span className="text-zinc-400">{(selectedFile.size / 1024).toFixed(2)} KB</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500 uppercase tracking-wider text-[10px] font-bold">SHA-256 (Calc)</span>
                  <span className="text-zinc-500 truncate ml-4 text-[10px]">{getMockHash(selectedFile.name)}</span>
                </div>
              </div>
              
              {uploadStatus === 'idle' && (
                <div className="flex gap-4 w-full">
                  <button 
                    onClick={(e) => { e.stopPropagation(); setSelectedFile(null); }}
                    className="flex-1 border border-zinc-700 bg-zinc-900 text-zinc-400 py-2 hover:bg-zinc-800 hover:text-white transition-colors uppercase tracking-widest font-bold"
                  >
                    Cancel
                  </button>
                  <button 
                    onClick={(e) => { e.stopPropagation(); initiateAnalysis(); }}
                    className="flex-1 bg-zinc-200 text-zinc-950 py-2 hover:bg-white transition-colors uppercase tracking-widest font-bold"
                  >
                    Initiate Binary Analysis
                  </button>
                </div>
              )}

              {uploadStatus === 'analyzing' && (
                <div className="flex items-center justify-center gap-3 w-full border border-blue-900 bg-blue-950/30 text-blue-400 py-2 font-bold uppercase tracking-widest">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Decompiling Artifact...
                </div>
              )}

              {uploadStatus === 'complete' && (
                <div className="flex items-center justify-center gap-3 w-full border border-emerald-900 bg-emerald-950/30 text-emerald-400 py-2 font-bold uppercase tracking-widest">
                  <CheckCircle className="w-4 h-4" />
                  Analysis Complete
                </div>
              )}
            </div>
          )}
        </div>

        {/* Sandboxing Queue */}
        <div>
          <h2 className="text-[10px] text-zinc-500 uppercase tracking-widest mb-3 font-bold border-b border-zinc-800 pb-2">
            Automated Sandboxing Queue
          </h2>
          <div className="border border-zinc-800 bg-zinc-900/50">
            {uploadStatus === 'complete' && selectedFile ? (
              <div className="p-4 flex items-center justify-between hover:bg-zinc-900 transition-colors border-b border-zinc-800 last:border-0">
                <div className="flex items-center gap-4">
                  <FileSearch className="w-5 h-5 text-emerald-500" />
                  <div>
                    <div className="text-zinc-200 font-bold mb-1">{selectedFile.name}</div>
                    <div className="text-zinc-500 text-[10px]">Analysis ID: SAND-9912</div>
                  </div>
                </div>
                <div className="text-right">
                  <span className="px-2 py-1 bg-emerald-950 border border-emerald-900 text-emerald-500 text-[10px] uppercase font-bold">Clean</span>
                </div>
              </div>
            ) : (
              <div className="p-6 flex flex-col items-center justify-center text-center">
                <FileSearch className="w-6 h-6 text-zinc-700 mb-2" />
                <span className="text-zinc-600 text-xs italic">Forensic processing queue is currently empty.</span>
              </div>
            )}
          </div>
        </div>

      </div>
    </ModuleWrapper>
  );
}
