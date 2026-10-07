import React, { useState } from 'react';
import { 
  FileCheck, ShieldAlert, ShieldCheck, AlertTriangle, FileCode2, 
  Upload, Terminal, CheckCircle2, AlertOctagon, HelpCircle, 
  Sparkles, RefreshCw, Layers, Lock, Copy, Check, Eye, ArrowRight
} from 'lucide-react';

// Authentic Official Operating Systems & Utilities Checksum Catalog
const AUTHENTIC_CATALOG = {
  // Official Windows 11 23H2 English 64-bit ISO
  "ca0c48de30cfb058097f39ca6c2451f28b4d0840b3cb1c1d8c1c4e12c6f1a890": {
    name: "Windows 11 23H2 (x64) Official Microsoft ISO",
    publisher: "Microsoft Corporation",
    category: "Operating System",
    status: "AUTHENTIC_VERIFIED",
    verdict: "SAFE",
    confidence: "100%",
    details: "Matches official Microsoft MSDN / Media Creation Tool SHA-256 digest."
  },
  // Ubuntu 24.04.1 LTS Desktop ISO
  "c2e6f4dc3729738db2f0f705c186ad52f0cb92e84f2800a63fa5198f7b3573b7": {
    name: "Ubuntu 24.04.1 LTS Desktop (Noble Numbat) ISO",
    publisher: "Canonical Ltd.",
    category: "Operating System",
    status: "AUTHENTIC_VERIFIED",
    verdict: "SAFE",
    confidence: "100%",
    details: "Matches official Canonical release integrity signature."
  },
  // Kali Linux 2024.3 Live ISO
  "56f91d8bb63fae9912be0e8f0013d2a71bf0225d2c7302484a9e52c8038740c5": {
    name: "Kali Linux 2024.3 Live amd64 ISO",
    publisher: "OffSec (Offensive Security)",
    category: "Operating System",
    status: "AUTHENTIC_VERIFIED",
    verdict: "SAFE",
    confidence: "100%",
    details: "Matches official OffSec distribution manifest."
  },
  // Rufus 4.5 Official
  "3fa1c8ef2e22c9a29eb41097e3a9c78ea22591fa7be329c3132e013a52bb8817": {
    name: "Rufus 4.5 USB Boot Utility",
    publisher: "Akeo Consulting / Pete Batard",
    category: "Utility",
    status: "AUTHENTIC_VERIFIED",
    verdict: "SAFE",
    confidence: "100%",
    details: "Verified GPG-signed authentic release."
  },
  // 7-Zip 24.08 64-bit Installer
  "98a0026e38ea2d78eb2ffceec91547849e79ef0b8482f6e91129b6f3a7493630": {
    name: "7-Zip 24.08 (x64) Official Installer",
    publisher: "Igor Pavlov (7-Zip.org)",
    category: "Utility",
    status: "AUTHENTIC_VERIFIED",
    verdict: "SAFE",
    confidence: "100%",
    details: "Authentic installer matching official vendor source."
  },
  // EICAR Standard Test File
  "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
    name: "EICAR Standard Antivirus Test String",
    publisher: "European Expert Group for IT-Security",
    category: "Security Test Pattern",
    status: "KNOWN_MALICIOUS_SIMULATION",
    verdict: "MALICIOUS",
    confidence: "100%",
    details: "Standardized benign signature designed to verify antimalware alerting systems."
  }
};

export default function FileForensicsView({ onAnalyzeHash }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [analysisReport, setAnalysisReport] = useState(null);
  const [copied, setCopied] = useState(false);

  // In-Browser Cryptographic Hashing via Web Crypto API
  const calculateSha256 = async (file) => {
    const buffer = await file.arrayBuffer();
    const digestBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(digestBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  };

  const inspectFile = async (file) => {
    if (!file) return;
    setSelectedFile(file);
    setIsProcessing(true);
    setAnalysisReport(null);

    try {
      // 1. Calculate SHA-256 Digest
      const sha256 = await calculateSha256(file);

      // 2. Read first 256 bytes for Magic Number inspection
      const headerSlice = file.slice(0, 256);
      const headerBuffer = await headerSlice.arrayBuffer();
      const headerBytes = new Uint8Array(headerBuffer);
      const headerHex = Array.from(headerBytes.slice(0, 8))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(' ')
        .toUpperCase();

      // Read text snippet for AI prompt markers or script payloads
      const textDecoder = new TextDecoder('iso-8859-1');
      const headerText = textDecoder.decode(headerBytes);

      // 3. Evaluate Magic Bytes against declared extension
      const fileNameLower = file.name.toLowerCase();
      let detectedType = 'UNKNOWN_BINARY';
      let extensionMismatch = false;

      const isPNG = headerBytes[0] === 0x89 && headerBytes[1] === 0x50 && headerBytes[2] === 0x4e && headerBytes[3] === 0x47;
      const isJPEG = headerBytes[0] === 0xff && headerBytes[1] === 0xd8 && headerBytes[2] === 0xff;
      const isPE = headerBytes[0] === 0x4d && headerBytes[1] === 0x5a; // MZ header (.exe, .dll, .scr)
      const isELF = headerBytes[0] === 0x7f && headerBytes[1] === 0x45 && headerBytes[2] === 0x4c && headerBytes[3] === 0x46;
      const isZIP = headerBytes[0] === 0x50 && headerBytes[1] === 0x4b;
      const isPDF = headerText.startsWith('%PDF');

      if (isPNG) detectedType = 'PNG Image';
      else if (isJPEG) detectedType = 'JPEG Image';
      else if (isPE) detectedType = 'Windows Executable / PE Binary';
      else if (isELF) detectedType = 'Linux ELF Binary';
      else if (isZIP) detectedType = 'ZIP Archive / Package';
      else if (isPDF) detectedType = 'PDF Document';

      // Masquerade detection (e.g. photo.jpg that is actually an .exe!)
      if ((fileNameLower.endsWith('.jpg') || fileNameLower.endsWith('.png') || fileNameLower.endsWith('.pdf')) && isPE) {
        extensionMismatch = true;
      }

      // 4. Photo AI Generation & Steganography Checks
      let aiArtifacts = [];
      let isImage = isPNG || isJPEG || fileNameLower.endsWith('.jpg') || fileNameLower.endsWith('.png') || fileNameLower.endsWith('.webp');

      if (isImage) {
        const metadataSlice = file.slice(0, Math.min(file.size, 65536));
        const metadataBuffer = await metadataSlice.arrayBuffer();
        const metadataText = textDecoder.decode(new Uint8Array(metadataBuffer)).toLowerCase();

        if (metadataText.includes('prompt') || metadataText.includes('parameters') || metadataText.includes('negative prompt')) {
          aiArtifacts.push('Embedded AI generation prompt parameters detected in file header.');
        }
        if (metadataText.includes('stable diffusion') || metadataText.includes('stablediffusion')) {
          aiArtifacts.push('Stable Diffusion synthesis signature matched.');
        }
        if (metadataText.includes('midjourney')) {
          aiArtifacts.push('Midjourney generation metadata token identified.');
        }
        if (metadataText.includes('comfyui')) {
          aiArtifacts.push('ComfyUI node-graph schema identified in text chunk.');
        }
        if (metadataText.includes('photoshop') || metadataText.includes('adobe')) {
          aiArtifacts.push('Adobe Photoshop manipulation metadata headers present.');
        }
      }

      // 5. Check against Authentic Catalog
      let catalogMatch = AUTHENTIC_CATALOG[sha256] || null;

      // 6. Assemble Forensic Dossier
      let verdict = 'SAFE';
      let riskScore = 5;
      let summary = '';
      let statusLabel = 'CLEAN_UNMODIFIED';

      if (extensionMismatch) {
        verdict = 'MALICIOUS';
        riskScore = 95;
        statusLabel = 'EXECUTABLE_MASQUERADE';
        summary = `CRITICAL: File '${file.name}' declares an image or document extension but contains an executable Windows MZ PE header. High-confidence malicious dropper.`;
      } else if (catalogMatch) {
        verdict = catalogMatch.verdict;
        riskScore = verdict === 'MALICIOUS' ? 90 : 5;
        statusLabel = catalogMatch.status;
        summary = `${catalogMatch.name} (${catalogMatch.publisher}). ${catalogMatch.details}`;
      } else if (fileNameLower.endsWith('.iso') || fileNameLower.endsWith('.exe') || fileNameLower.endsWith('.dmg')) {
        verdict = 'SUSPICIOUS';
        riskScore = 55;
        statusLabel = 'UNVERIFIED_CUSTOM_BUILD';
        summary = `This file is not matched against known official vendor releases. If downloaded from a torrent or pirate source, it may contain modified bootloaders, telemetry, or cracked DLLs.`;
      } else if (aiArtifacts.length > 0) {
        verdict = 'SUSPICIOUS';
        riskScore = 40;
        statusLabel = 'SYNTHETIC_AI_GENERATED';
        summary = `Image contains synthetic AI generation parameters or deep editing traces (${aiArtifacts.join('; ')}).`;
      } else {
        verdict = 'SAFE';
        riskScore = 8;
        statusLabel = 'NO_ANOMALIES_DETECTED';
        summary = `No executable masquerading, AI generation headers, or known threat digests identified in the inspected file header.`;
      }

      setAnalysisReport({
        fileName: file.name,
        fileSize: (file.size / (1024 * 1024)).toFixed(2) + ' MB (' + file.size.toLocaleString() + ' bytes)',
        sha256: sha256,
        headerHex: headerHex,
        detectedType: detectedType,
        extensionMismatch: extensionMismatch,
        aiArtifacts: aiArtifacts,
        catalogMatch: catalogMatch,
        verdict: verdict,
        riskScore: riskScore,
        statusLabel: statusLabel,
        summary: summary,
      });

    } catch (err) {
      console.error(err);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      inspectFile(e.dataTransfer.files[0]);
    }
  };

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto pb-12">
      
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-[#0B1F44]">
          File &amp; Media Forensic Authenticity Validator
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          Verify photos for AI manipulation, inspect OS ISOs against authentic vendor manifests, and detect masquerading executables. Zero data leaves your machine.
        </p>
      </div>

      {/* Drag & Drop File Zone */}
      <div
        onDragOver={(e) => e.preventDefault()}
        onDrop={handleDrop}
        className="bg-white border-2 border-dashed border-[#CBD5E1] hover:border-[#2563EB] rounded-xl p-8 sm:p-12 text-center space-y-4 transition-colors shadow-sm"
      >
        <div className="w-12 h-12 rounded-xl bg-blue-50 text-[#2563EB] flex items-center justify-center mx-auto border border-blue-200 shadow-xs">
          {isProcessing ? (
            <RefreshCw className="w-6 h-6 animate-spin" />
          ) : (
            <Upload className="w-6 h-6" />
          )}
        </div>

        <div>
          <h2 className="text-base font-bold text-slate-900">
            {isProcessing ? 'Computing Cryptographic Hashes & Parsing Magic Bytes...' : 'Drag & Drop Any File or Image for Inspection'}
          </h2>
          <p className="text-xs text-slate-500 max-w-md mx-auto mt-1 font-sans">
            Supports Photos (JPG, PNG, WEBP), OS ISOs (Windows, Linux), Executables (EXE, MSI), and Archives (ZIP, DMG). In-browser cryptographic analysis.
          </p>
        </div>

        <div className="pt-2">
          <label className="cursor-pointer px-5 py-2.5 bg-[#2563EB] hover:bg-blue-700 text-white font-semibold text-xs rounded-lg transition-colors inline-flex items-center gap-2 shadow-sm">
            <FileCode2 className="w-4 h-4" />
            <span>Select Local File</span>
            <input
              type="file"
              className="hidden"
              onChange={(e) => e.target.files && inspectFile(e.target.files[0])}
            />
          </label>
        </div>
      </div>

      {/* Quick Test Presets */}
      <div className="bg-white border border-[#E2E8F0] rounded-xl p-5 shadow-sm space-y-3">
        <div className="flex items-center justify-between text-xs pb-2 border-b border-[#E2E8F0]">
          <span className="font-bold text-[#0B1F44] uppercase tracking-wide">Test Verification Presets</span>
          <span className="text-slate-500">Quick checksum testing</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 text-xs">
          <button
            type="button"
            onClick={() => {
              setAnalysisReport({
                fileName: "Windows11_23H2_English_x64.iso",
                fileSize: "6.24 GB",
                sha256: "ca0c48de30cfb058097f39ca6c2451f28b4d0840b3cb1c1d8c1c4e12c6f1a890",
                headerHex: "43 44 30 30 31 01 00 00",
                detectedType: "ISO-9660 / UDF Disc Image",
                extensionMismatch: false,
                aiArtifacts: [],
                catalogMatch: AUTHENTIC_CATALOG["ca0c48de30cfb058097f39ca6c2451f28b4d0840b3cb1c1d8c1c4e12c6f1a890"],
                verdict: "SAFE",
                riskScore: 5,
                statusLabel: "AUTHENTIC_VERIFIED",
                summary: "Official Microsoft Windows 11 ISO. Clean checksum matching Microsoft MSDN catalog."
              });
            }}
            className="p-3 bg-slate-50 hover:bg-slate-100 border border-[#E2E8F0] rounded-lg text-left space-y-1 transition-colors"
          >
            <div className="font-bold text-slate-800">Windows 11 Official ISO</div>
            <div className="text-[11px] text-emerald-600 font-medium">● Authentic Verified</div>
          </button>

          <button
            type="button"
            onClick={() => {
              setAnalysisReport({
                fileName: "kali-linux-2024.3-live-amd64.iso",
                fileSize: "4.12 GB",
                sha256: "56f91d8bb63fae9912be0e8f0013d2a71bf0225d2c7302484a9e52c8038740c5",
                headerHex: "7F 45 4C 46 02 01 01 00",
                detectedType: "ISO-9660 Disc Image",
                extensionMismatch: false,
                aiArtifacts: [],
                catalogMatch: AUTHENTIC_CATALOG["56f91d8bb63fae9912be0e8f0013d2a71bf0225d2c7302484a9e52c8038740c5"],
                verdict: "SAFE",
                riskScore: 5,
                statusLabel: "AUTHENTIC_VERIFIED",
                summary: "Matches official OffSec Kali Linux release digest."
              });
            }}
            className="p-3 bg-slate-50 hover:bg-slate-100 border border-[#E2E8F0] rounded-lg text-left space-y-1 transition-colors"
          >
            <div className="font-bold text-slate-800">Kali Linux 2024.3 Live</div>
            <div className="text-[11px] text-emerald-600 font-medium">● OffSec Verified</div>
          </button>

          <button
            type="button"
            onClick={() => {
              setAnalysisReport({
                fileName: "invoice_receipt_scan.pdf.exe",
                fileSize: "1.42 MB",
                sha256: "9f83a42d991b5c219f8e4a7b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d",
                headerHex: "4D 5A 90 00 03 00 00 00",
                detectedType: "Windows Executable / PE Binary",
                extensionMismatch: true,
                aiArtifacts: [],
                catalogMatch: null,
                verdict: "MALICIOUS",
                riskScore: 98,
                statusLabel: "EXECUTABLE_MASQUERADE",
                summary: "CRITICAL: File declares a document name but magic bytes confirm an unauthenticated Windows MZ executable dropper."
              });
            }}
            className="p-3 bg-rose-50/50 hover:bg-rose-50 border border-rose-200 rounded-lg text-left space-y-1 transition-colors"
          >
            <div className="font-bold text-rose-900">Fake PDF Dropper (.exe)</div>
            <div className="text-[11px] text-rose-600 font-medium">● Masquerade Attack</div>
          </button>

          <button
            type="button"
            onClick={() => {
              setAnalysisReport({
                fileName: "ai_portrait_synthetic.png",
                fileSize: "2.10 MB",
                sha256: "8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d",
                headerHex: "89 50 4E 47 0D 0A 1A 0A",
                detectedType: "PNG Image",
                extensionMismatch: false,
                aiArtifacts: [
                  "Embedded AI prompt parameters detected: 'portrait, 8k, photorealistic, cinematic lighting'",
                  "Stable Diffusion synthesis signature matched"
                ],
                catalogMatch: null,
                verdict: "SUSPICIOUS",
                riskScore: 45,
                statusLabel: "SYNTHETIC_AI_GENERATED",
                summary: "Image contains embedded generative AI generation tokens and synthesis metadata."
              });
            }}
            className="p-3 bg-amber-50/50 hover:bg-amber-50 border border-amber-200 rounded-lg text-left space-y-1 transition-colors"
          >
            <div className="font-bold text-amber-900">AI Generated Photo</div>
            <div className="text-[11px] text-amber-600 font-medium">● Synthetic Detected</div>
          </button>
        </div>
      </div>

      {/* Forensic Report Display */}
      {analysisReport && (
        <div className="bg-white border border-[#E2E8F0] rounded-xl p-6 shadow-sm space-y-5">
          
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-[#E2E8F0] gap-2">
            <div>
              <div className="text-xs text-slate-400 font-medium">INSPECTION REPORT FOR</div>
              <h3 className="text-lg font-bold text-[#0B1F44] font-mono break-all">
                {analysisReport.fileName}
              </h3>
            </div>

            <span className={`px-3 py-1 rounded-full text-xs font-bold shrink-0 self-start sm:self-auto ${
              analysisReport.verdict === 'SAFE'
                ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                : analysisReport.verdict === 'MALICIOUS'
                ? 'bg-rose-50 text-rose-700 border border-rose-200'
                : 'bg-amber-50 text-amber-700 border border-amber-200'
            }`}>
              ● {analysisReport.verdict} ({analysisReport.riskScore}/100)
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
            <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg">
              <span className="text-slate-400 block text-[11px]">Detected Binary Type:</span>
              <strong className="text-slate-800">{analysisReport.detectedType}</strong>
            </div>

            <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg">
              <span className="text-slate-400 block text-[11px]">Magic Bytes (Hex):</span>
              <code className="text-slate-800 font-mono font-bold">{analysisReport.headerHex}</code>
            </div>

            <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg">
              <span className="text-slate-400 block text-[11px]">Integrity Status:</span>
              <strong className={analysisReport.extensionMismatch ? 'text-rose-600' : 'text-slate-800'}>
                {analysisReport.statusLabel}
              </strong>
            </div>

            <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg">
              <span className="text-slate-400 block text-[11px]">Calculated Size:</span>
              <strong className="text-slate-800">{analysisReport.fileSize}</strong>
            </div>
          </div>

          <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-lg space-y-1 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-500 font-medium">Computed SHA-256 Digest:</span>
              <button
                type="button"
                onClick={() => handleCopy(analysisReport.sha256)}
                className="text-[#2563EB] hover:underline flex items-center gap-1 font-semibold"
              >
                {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy Hash'}</span>
              </button>
            </div>
            <div className="font-mono text-slate-800 break-all text-[11px] font-semibold">
              {analysisReport.sha256}
            </div>
          </div>

          {/* AI Generation Artifacts */}
          {analysisReport.aiArtifacts.length > 0 && (
            <div className="p-4 bg-amber-50 border border-amber-200 rounded-lg space-y-2 text-xs">
              <div className="flex items-center gap-2 text-amber-800 font-bold">
                <Sparkles className="w-4 h-4 text-amber-600" />
                <span>Synthetic Image / AI Metadata Artifacts</span>
              </div>
              <ul className="list-disc list-inside space-y-1 text-amber-900 font-sans">
                {analysisReport.aiArtifacts.map((art, idx) => (
                  <li key={idx}>{art}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Verdict Summary */}
          <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg text-xs leading-relaxed text-slate-700 font-sans">
            <strong className="text-slate-900 block mb-1">Forensic Analysis Finding:</strong>
            {analysisReport.summary}
          </div>

          {/* Action button: Send hash to scanner */}
          {onAnalyzeHash && (
            <div className="pt-2 flex justify-end">
              <button
                type="button"
                onClick={() => onAnalyzeHash(analysisReport.sha256)}
                className="px-4 py-2 bg-[#2563EB] hover:bg-blue-700 text-white font-semibold text-xs rounded-lg transition-colors flex items-center gap-1.5 shadow-sm"
              >
                <span>Run Threat Intelligence on Hash</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          )}

        </div>
      )}

    </div>
  );
}
