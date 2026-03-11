import React, { useState, useEffect, useRef } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { open } from '@tauri-apps/api/dialog';
import { useWallet } from '../App';
import { useConfirm } from '../hooks/useConfirm';

interface StorageMetrics {
  storage_allocated_bytes: number;
  space_used_bytes: number;
  space_available_bytes: number;
  availability_status: string;
  last_post_latency_ms?: number;
  last_post_timestamp?: number;
  encrypted_files_count: number;
}

interface StoredFile {
  cid: string;
  name: string;
  original_size: number;
  encrypted_size: number;
  duration_months: number;
  stored_at: number;
  expiry: number;
  status: string;
  key_nonce_hex: string;
  local_path: string;
}

interface StoreFileResult {
  cid: string;
  name: string;
  original_size: number;
  encrypted_size: number;
  duration_months: number;
  expiry_timestamp: number;
  cost_uegoc: number;
  key_nonce_hex: string;
}

interface FilePreview {
  name: string;
  mime_type: string;
  data_base64: string;
  size_bytes: number;
  previewable: boolean;
}

type UploadStep = 'idle' | 'configure' | 'processing' | 'done' | 'error';
type ProcessStage = 'encrypting' | 'coding' | 'placing' | 'anchoring' | 'complete';

function fmtBytes(b: number) {
  if (b >= 1e12) return (b / 1e12).toFixed(2) + ' TB';
  if (b >= 1e9)  return (b / 1e9).toFixed(2) + ' GB';
  if (b >= 1e6)  return (b / 1e6).toFixed(2) + ' MB';
  if (b >= 1e3)  return (b / 1e3).toFixed(1) + ' KB';
  return b + ' B';
}
function fmtExpiry(ts: number) {
  const diff = ts - Date.now() / 1000;
  if (diff < 0) return 'Expired';
  const days = Math.floor(diff / 86400);
  return `${days}d left`;
}
// Earnings rate: 0.5 EGOC per GB per day
function storageEarningsPerDay(allocatedBytes: number) {
  return (allocatedBytes / 1e9) * 0.5;
}

const PROCESS_STAGES: { key: ProcessStage; label: string; detail: string; ms: number }[] = [
  { key: 'encrypting', label: 'AES-256-GCM Encryption',   detail: 'Encrypting file with random key + nonce',        ms: 1200 },
  { key: 'coding',     label: 'Content Addressing (CID)',  detail: 'Computing BLAKE2 hash → egocid1… identifier',   ms: 800  },
  { key: 'placing',    label: 'Writing to Local Storage',  detail: 'Persisting encrypted blob to disk',              ms: 1000 },
  { key: 'anchoring',  label: 'Ledger Commitment',         detail: 'Recording CID + expiry in local testnet ledger', ms: 700  },
];

const StoragePage: React.FC = () => {
  const { wallet } = useWallet();
  const myAddress = wallet?.address ?? '';
  const { confirm, ConfirmDialog } = useConfirm();

  const [metrics, setMetrics] = useState<StorageMetrics | null>(null);
  const [files, setFiles] = useState<StoredFile[]>([]);

  // Upload flow
  const [step, setStep] = useState<UploadStep>('idle');
  const [filePath, setFilePath] = useState('');
  const [fileName, setFileName] = useState('');
  const [duration, setDuration] = useState(3);
  const [processStage, setProcessStage] = useState<ProcessStage>('encrypting');
  const [stageProgress, setStageProgress] = useState(0);
  const [completedStages, setCompletedStages] = useState<Set<ProcessStage>>(new Set());
  const [storeResult, setStoreResult] = useState<StoreFileResult | null>(null);
  const [storeError, setStoreError] = useState('');

  // Storage provision config
  const [showProvConfig, setShowProvConfig] = useState(false);
  const [allocGb, setAllocGb] = useState(50);
  const [configuring, setConfiguring] = useState(false);

  // File detail / preview
  const [selectedFile, setSelectedFile] = useState<StoredFile | null>(null);
  const [preview, setPreview] = useState<FilePreview | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const storeResultRef = useRef<StoreFileResult | null>(null);
  const storeErrorRef  = useRef<string>('');

  useEffect(() => { loadData(); }, []);
  useEffect(() => () => { if (timerRef.current) clearTimeout(timerRef.current); }, []);

  async function loadData() {
    try {
      const [m, f] = await Promise.all([
        invoke<StorageMetrics>('get_storage_metrics'),
        invoke<StoredFile[]>('get_stored_files'),
      ]);
      setMetrics(m);
      setFiles(f);
    } catch (e) { console.error(e); }
  }

  // ── Storage provision config ──────────────────────────────────────────────

  async function handleConfigureStorage() {
    setConfiguring(true);
    try {
      await invoke('configure_storage', { gb: allocGb });
      await loadData();
      setShowProvConfig(false);
    } catch (e: any) {
      alert('Failed to configure: ' + String(e));
    } finally {
      setConfiguring(false);
    }
  }

  // ── File upload flow ──────────────────────────────────────────────────────

  async function pickFile() {
    try {
      const selected = await open({ multiple: false, title: 'Select file to store on Ego Network' });
      if (selected && typeof selected === 'string') {
        const parts = selected.replace(/\\/g, '/').split('/');
        setFileName(parts[parts.length - 1]);
        setFilePath(selected);
        setStep('configure');
      }
    } catch (e) { console.error('File dialog error:', e); }
  }

  function startUpload() {
    setStep('processing');
    setCompletedStages(new Set());
    setStageProgress(0);
    setStoreResult(null);
    setStoreError('');
    storeResultRef.current = null;
    storeErrorRef.current  = '';

    invoke<StoreFileResult>('store_file', {
      request: { file_path: filePath, duration_months: duration },
    })
      .then(result => {
        storeResultRef.current = result;
        setStoreResult(result);
        invoke<StoredFile[]>('get_stored_files').then(f => setFiles(f)).catch(() => {});
        invoke<StorageMetrics>('get_storage_metrics').then(m => setMetrics(m)).catch(() => {});
      })
      .catch((e: any) => {
        storeErrorRef.current = String(e);
        setStoreError(String(e));
      });

    runStages(0);
  }

  function runStages(idx: number) {
    if (idx >= PROCESS_STAGES.length) {
      setProcessStage('complete');
      if (storeResultRef.current) {
        setStep('done');
      } else if (storeErrorRef.current) {
        setStep('error');
      } else {
        timerRef.current = setTimeout(() => runStages(PROCESS_STAGES.length), 300);
      }
      return;
    }
    const stage = PROCESS_STAGES[idx];
    setProcessStage(stage.key);
    setStageProgress(0);
    const steps    = 20;
    const interval = stage.ms / steps;
    let count = 0;
    function tick() {
      count++;
      setStageProgress(Math.min(100, Math.floor((count / steps) * 100)));
      if (count < steps) {
        timerRef.current = setTimeout(tick, interval);
      } else {
        setCompletedStages(prev => new Set([...prev, stage.key]));
        timerRef.current = setTimeout(() => runStages(idx + 1), 200);
      }
    }
    tick();
  }

  function resetUpload() {
    if (timerRef.current) clearTimeout(timerRef.current);
    setStep('idle'); setFilePath(''); setFileName(''); setDuration(3);
    setStoreResult(null); setStoreError('');
    storeResultRef.current = null; storeErrorRef.current = '';
  }

  // ── Delete file ───────────────────────────────────────────────────────────

  async function handleDelete(cid: string) {
    if (!await confirm('Permanently delete this file?', { detail: 'This also removes the encryption key. This cannot be undone.', confirmLabel: 'Delete' })) return;
    try {
      await invoke('delete_stored_file', { cid });
      setFiles(prev => prev.filter(f => f.cid !== cid));
      setSelectedFile(null);
      invoke<StorageMetrics>('get_storage_metrics').then(m => setMetrics(m)).catch(() => {});
    } catch (e: any) { alert('Delete failed: ' + String(e)); }
  }

  // ── File preview ──────────────────────────────────────────────────────────

  async function loadPreview(file: StoredFile) {
    setSelectedFile(file);
    setPreview(null);
    setPreviewLoading(true);
    try {
      const p = await invoke<FilePreview>('retrieve_file_preview', { cid: file.cid });
      setPreview(p);
    } catch (e) { console.error('Preview failed:', e); }
    finally { setPreviewLoading(false); }
  }

  // ── Metrics ───────────────────────────────────────────────────────────────

  const isConfigured = (metrics?.storage_allocated_bytes ?? 0) > 0;
  const allocated    = metrics?.storage_allocated_bytes ?? 0;
  const used         = metrics?.space_used_bytes ?? 0;
  const available    = metrics?.space_available_bytes ?? 0;
  const usedPct      = allocated > 0 ? Math.min(100, Math.round((used / allocated) * 100)) : 0;
  const earningsPerDay = storageEarningsPerDay(allocated);

  return (
    <div className="p-6 space-y-5 max-w-4xl mx-auto">
      {ConfirmDialog}

      {/* ── Storage Provider Configuration ─────────────────────────────── */}
      {!isConfigured ? (
        <div className="bg-gradient-to-br from-purple-900/60 to-blue-900/60 rounded-2xl border border-purple-500/30 p-6">
          <div className="flex items-start gap-4">
            <div className="text-4xl">🖥️</div>
            <div className="flex-1">
              <h3 className="text-lg font-bold mb-1">Become a Storage Provider</h3>
              <p className="text-sm text-gray-300 mb-4">
                Share your disk space with the Ego Network and earn EGOC.
                The more you allocate, the more you earn.
              </p>
              <div className="bg-black/30 rounded-xl p-3 text-xs text-gray-400 mb-4">
                Reward rate: <span className="text-green-400 font-semibold">0.5 EGOC / GB / day</span>
                &nbsp;· Files stored by others are AES-256-GCM encrypted and you cannot read their contents.
              </div>
              <button
                onClick={() => setShowProvConfig(true)}
                className="bg-purple-600 hover:bg-purple-500 transition px-5 py-2.5 rounded-xl font-semibold text-sm"
              >
                Configure Storage →
              </button>
            </div>
          </div>
        </div>
      ) : (
        /* ── Header stats (configured) ─────────────────────────────────── */
        <div className="grid grid-cols-4 gap-3">
          <div className="col-span-2 bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <div className="flex justify-between items-start mb-3">
              <div>
                <div className="text-xs text-gray-400">Storage Used / Allocated</div>
                <div className="text-2xl font-bold">{fmtBytes(used)}</div>
                <div className="text-xs text-gray-500">of {fmtBytes(allocated)} allocated</div>
              </div>
              <div className="text-right">
                <div className="bg-blue-500/20 text-blue-400 rounded-lg px-2 py-1 text-xs font-medium">{usedPct}% used</div>
                <button onClick={() => setShowProvConfig(true)} className="text-xs text-gray-500 hover:text-gray-300 mt-1 block">change</button>
              </div>
            </div>
            <div className="bg-gray-700 rounded-full h-2">
              <div className="bg-gradient-to-r from-blue-500 to-purple-500 h-2 rounded-full transition-all" style={{ width: `${usedPct}%` }} />
            </div>
          </div>

          <div className="bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <div className="text-xs text-gray-400 mb-1">Daily Earnings</div>
            <div className="text-xl font-bold text-green-400">{earningsPerDay.toFixed(2)}</div>
            <div className="text-xs text-gray-500">EGOC / day</div>
            <div className="text-xs text-green-500/70 mt-1">from {fmtBytes(allocated)} provision</div>
          </div>

          <div className="bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <div className="text-xs text-gray-400 mb-1">Files Stored</div>
            <div className="text-xl font-bold">{metrics?.encrypted_files_count ?? 0}</div>
            <div className="text-xs text-green-400 mt-1">🔐 AES-256-GCM</div>
            <div className="text-xs text-gray-500">Available: {fmtBytes(available)}</div>
          </div>
        </div>
      )}

      {/* ── Upload section ──────────────────────────────────────────────── */}
      <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-700">
          <h3 className="font-semibold">Store Your Files</h3>
          {step !== 'idle' && step !== 'done' && (
            <button onClick={resetUpload} className="text-xs text-gray-400 hover:text-white">Cancel</button>
          )}
        </div>

        <div className="p-5">
          {step === 'idle' && (
            <div className="text-center py-8">
              <div className="text-5xl mb-4">🗄️</div>
              <div className="text-lg font-semibold mb-1">Encrypted Local Storage</div>
              <div className="text-xs text-gray-400 mb-1 max-w-xs mx-auto">
                AES-256-GCM encryption · BLAKE2 content addressing · ledger commitment
              </div>
              <div className="text-xs text-gray-500 mb-6">
                Your file name stays private — nodes only see the CID hash.
              </div>
              <button onClick={pickFile} className="bg-blue-600 hover:bg-blue-500 transition px-6 py-3 rounded-xl font-semibold">
                + Pick File to Store
              </button>
            </div>
          )}

          {step === 'configure' && (
            <div className="max-w-md mx-auto space-y-5">
              <div className="bg-gray-900 rounded-xl p-4 flex items-start gap-3">
                <div className="text-3xl shrink-0">📄</div>
                <div className="min-w-0">
                  <div className="font-medium truncate">{fileName}</div>
                  <div className="text-xs text-gray-500 font-mono truncate mt-0.5">{filePath}</div>
                  <div className="text-xs text-blue-400 mt-1">🔒 Name will be private — only CID visible to network</div>
                </div>
              </div>
              <div>
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-gray-400">Storage Duration</span>
                  <span className="font-bold">{duration} month{duration > 1 ? 's' : ''}</span>
                </div>
                <input type="range" min="1" max="24" value={duration} onChange={e => setDuration(+e.target.value)} className="w-full accent-blue-500" />
                <div className="flex justify-between text-xs text-gray-500 mt-1"><span>1 month</span><span>24 months</span></div>
              </div>
              <div className="bg-gray-900 rounded-xl p-4 text-sm space-y-2">
                <div className="flex justify-between"><span className="text-gray-400">Encryption</span><span>AES-256-GCM</span></div>
                <div className="flex justify-between"><span className="text-gray-400">Content ID</span><span>BLAKE2s-256</span></div>
                <div className="flex justify-between"><span className="text-gray-400">Cost rate</span><span>0.01 EGOC / MB / month</span></div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <button onClick={resetUpload} className="bg-gray-700 hover:bg-gray-600 py-3 rounded-xl font-semibold text-sm transition">← Back</button>
                <button onClick={startUpload} className="bg-blue-600 hover:bg-blue-500 py-3 rounded-xl font-semibold text-sm transition">Encrypt & Store →</button>
              </div>
            </div>
          )}

          {step === 'processing' && (
            <div className="max-w-md mx-auto space-y-4">
              <div className="text-center mb-6">
                <div className="text-3xl mb-2">⚙️</div>
                <div className="font-semibold">Processing {fileName}</div>
              </div>
              {PROCESS_STAGES.map(stage => {
                const done   = completedStages.has(stage.key);
                const active = processStage === stage.key && !done;
                return (
                  <div key={stage.key} className={`rounded-xl p-4 border transition ${done ? 'border-green-500/30 bg-green-500/5' : active ? 'border-blue-500/50 bg-blue-500/10' : 'border-gray-700 bg-gray-900 opacity-50'}`}>
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-2">
                        <span>{done ? '✅' : active ? '⏳' : '○'}</span>
                        <span className="text-sm font-medium">{stage.label}</span>
                      </div>
                      {active && <span className="text-xs text-blue-400">{stageProgress}%</span>}
                      {done   && <span className="text-xs text-green-400">Done</span>}
                    </div>
                    <div className="text-xs text-gray-400 ml-6">{stage.detail}</div>
                    {active && (
                      <div className="mt-2 ml-6 bg-gray-700 rounded-full h-1.5">
                        <div className="bg-blue-500 h-1.5 rounded-full transition-all duration-100" style={{ width: `${stageProgress}%` }} />
                      </div>
                    )}
                  </div>
                );
              })}
              {processStage === 'complete' && !storeResult && !storeError && (
                <div className="text-center text-xs text-gray-400 animate-pulse">Finalising…</div>
              )}
            </div>
          )}

          {step === 'done' && storeResult && (
            <div className="max-w-md mx-auto space-y-4">
              <div className="text-center py-4">
                <div className="text-5xl mb-3">🎉</div>
                <div className="text-xl font-bold text-green-400">Stored Successfully!</div>
                <div className="text-xs text-gray-400 mt-1">
                  Your filename stays private. Network only sees the CID below.
                </div>
              </div>
              <div className="bg-gray-900 rounded-xl p-4 space-y-3">
                <div>
                  <div className="text-xs text-gray-400 mb-1">Content ID (CID) — your public file address</div>
                  <div className="font-mono text-xs text-green-400 break-all">{storeResult.cid}</div>
                </div>
                <div className="border-t border-gray-700 pt-3 space-y-2 text-xs">
                  <div className="flex justify-between"><span className="text-gray-400">Original size</span><span>{fmtBytes(storeResult.original_size)}</span></div>
                  <div className="flex justify-between"><span className="text-gray-400">Encrypted size</span><span>{fmtBytes(storeResult.encrypted_size)}</span></div>
                  <div className="flex justify-between"><span className="text-gray-400">Duration</span><span>{storeResult.duration_months} months</span></div>
                  <div className="flex justify-between"><span className="text-gray-400">Expires</span><span>{new Date(storeResult.expiry_timestamp * 1000).toLocaleDateString()}</span></div>
                  <div className="flex justify-between"><span className="text-gray-400">Cost burned</span><span className="text-yellow-400">{(storeResult.cost_uegoc / 1_000_000).toFixed(4)} EGOC</span></div>
                  <div className="flex justify-between"><span className="text-gray-400">Commitment</span><span className="text-green-400">Ledger anchored ✓</span></div>
                </div>
                <div className="border-t border-gray-700 pt-3">
                  <div className="text-xs text-yellow-400 mb-1">⚠️ Encryption Key (keep this safe!)</div>
                  <div className="font-mono text-xs text-yellow-300 break-all">{storeResult.key_nonce_hex.slice(0, 32)}…</div>
                </div>
              </div>
              <button onClick={resetUpload} className="w-full bg-blue-600 hover:bg-blue-500 py-3 rounded-xl font-semibold transition">Store Another File</button>
            </div>
          )}

          {step === 'error' && (
            <div className="max-w-md mx-auto text-center space-y-4 py-4">
              <div className="text-5xl">❌</div>
              <div className="text-lg font-bold text-red-400">Storage Failed</div>
              <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4 text-xs font-mono text-red-300 text-left break-all">{storeError}</div>
              <button onClick={resetUpload} className="w-full bg-gray-700 hover:bg-gray-600 py-3 rounded-xl font-semibold transition">Try Again</button>
            </div>
          )}
        </div>
      </div>

      {/* ── Stored files list ───────────────────────────────────────────── */}
      <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-700">
          <h3 className="font-semibold">Stored Files ({files.filter(f => f.status === 'Active' || f.status === 'Received').length})</h3>
          <button onClick={loadData} className="text-xs text-gray-400 hover:text-white transition">↻ Refresh</button>
        </div>
        {files.length === 0 ? (
          <div className="py-12 text-center text-gray-500">
            <div className="text-4xl mb-3">📂</div>
            <div className="text-sm">No files stored yet</div>
            <div className="text-xs mt-1 text-gray-600">Pick a file above to get started</div>
          </div>
        ) : (
          <div className="divide-y divide-gray-700/50">
            {files.map(file => (
              <div key={file.cid} className="px-5 py-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className="text-sm font-medium">{file.name}</span>
                      <span className={`shrink-0 text-xs px-2 py-0.5 rounded-full ${
                        file.status === 'Active'   ? 'bg-green-500/20 text-green-400' :
                        file.status === 'Received' ? 'bg-blue-500/20 text-blue-400' :
                                                     'bg-red-500/20 text-red-400'
                      }`}>{file.status}</span>
                    </div>
                    {/* Network ID = CID (node sees only this, not the name) */}
                    <div className="text-xs text-gray-600 mb-1">
                      🔒 Network ID: <span className="font-mono text-gray-500">{file.cid.slice(0, 20)}…</span>
                    </div>
                    <div className="flex gap-4 text-xs text-gray-500 flex-wrap">
                      {file.original_size > 0 && <span>{fmtBytes(file.original_size)}</span>}
                      <span>🔐 AES-256-GCM</span>
                      <span>{file.duration_months}mo</span>
                      <span className={file.status !== 'Active' && file.status !== 'Received' ? 'text-red-400' : ''}>{fmtExpiry(file.expiry)}</span>
                    </div>
                  </div>
                  <div className="flex gap-2 shrink-0">
                    <button onClick={() => loadPreview(file)} className="text-xs bg-gray-700 hover:bg-gray-600 px-3 py-1.5 rounded-lg transition">Details</button>
                    <button onClick={() => handleDelete(file.cid)} className="text-xs bg-red-600/20 hover:bg-red-600/40 text-red-400 px-3 py-1.5 rounded-lg transition">Delete</button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Storage Provision Config Modal ──────────────────────────────── */}
      {showProvConfig && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-md border border-gray-700 shadow-2xl">
            <div className="flex justify-between items-center mb-5">
              <h3 className="text-lg font-bold">Configure Storage Provision</h3>
              <button onClick={() => setShowProvConfig(false)} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>
            <div className="space-y-5">
              <div className="text-sm text-gray-400">
                Choose how much disk space to share with the Ego Network. You can change this anytime.
              </div>
              <div>
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-gray-400">Allocation</span>
                  <span className="font-bold text-blue-400">{allocGb} GB</span>
                </div>
                <input type="range" min="1" max="1000" step="1" value={allocGb} onChange={e => setAllocGb(+e.target.value)} className="w-full accent-blue-500" />
                <div className="flex justify-between text-xs text-gray-500 mt-1"><span>1 GB</span><span>1000 GB</span></div>
              </div>
              <div className="bg-gray-900 rounded-xl p-4 space-y-2 text-sm">
                <div className="flex justify-between"><span className="text-gray-400">Allocation</span><span>{allocGb} GB</span></div>
                <div className="flex justify-between"><span className="text-gray-400">Daily earnings</span><span className="text-green-400 font-bold">{(allocGb * 0.5).toFixed(2)} EGOC/day</span></div>
                <div className="flex justify-between"><span className="text-gray-400">Monthly earnings</span><span className="text-green-400">{(allocGb * 0.5 * 30).toFixed(0)} EGOC/month</span></div>
                <div className="flex justify-between"><span className="text-gray-400">Annual estimate</span><span className="text-green-400">{(allocGb * 0.5 * 365).toFixed(0)} EGOC/year</span></div>
              </div>
              <div className="text-xs text-gray-500">
                Files stored are encrypted by the uploader. You cannot read their contents.
                All data persists in your local app data directory.
              </div>
              <div className="grid grid-cols-2 gap-3">
                <button onClick={() => setShowProvConfig(false)} className="bg-gray-700 hover:bg-gray-600 py-3 rounded-xl font-semibold text-sm transition">Cancel</button>
                <button onClick={handleConfigureStorage} disabled={configuring} className="bg-blue-600 hover:bg-blue-500 disabled:opacity-40 py-3 rounded-xl font-semibold text-sm transition">
                  {configuring ? 'Saving…' : `Allocate ${allocGb} GB`}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── File Detail / Preview Modal ─────────────────────────────────── */}
      {selectedFile && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-lg border border-gray-700 shadow-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex justify-between items-center mb-5">
              <h3 className="text-lg font-bold">File Details</h3>
              <button onClick={() => { setSelectedFile(null); setPreview(null); }} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>

            {/* Real name (only you can see this) */}
            <div className="bg-gray-900 rounded-xl p-3 mb-4">
              <div className="text-xs text-gray-400 mb-0.5">Your file name (private, only stored locally)</div>
              <div className="font-medium">{selectedFile.name}</div>
              <div className="text-xs text-gray-600 mt-1">🔒 Nodes only see the CID below, not this name</div>
            </div>

            {/* Preview area */}
            {previewLoading && (
              <div className="bg-gray-900 rounded-xl p-8 text-center mb-4">
                <div className="text-2xl animate-spin mb-2">⏳</div>
                <div className="text-xs text-gray-400">Decrypting file…</div>
              </div>
            )}
            {preview && preview.previewable && preview.data_base64 && (
              <div className="mb-4 rounded-xl overflow-hidden border border-gray-700">
                {preview.mime_type.startsWith('image/') ? (
                  <img
                    src={`data:${preview.mime_type};base64,${preview.data_base64}`}
                    alt={selectedFile.name}
                    className="w-full max-h-64 object-contain bg-black"
                  />
                ) : (
                  <pre className="p-4 text-xs text-gray-300 overflow-auto max-h-48 bg-gray-900 whitespace-pre-wrap">
                    {atob(preview.data_base64).slice(0, 4000)}
                    {atob(preview.data_base64).length > 4000 ? '\n…(truncated)' : ''}
                  </pre>
                )}
              </div>
            )}
            {preview && !preview.previewable && (
              <div className="bg-gray-900 rounded-xl p-4 text-center mb-4 text-sm text-gray-400">
                <div className="text-3xl mb-2">📁</div>
                Preview not available for this file type.
                {selectedFile.status === 'Received' && ' (Remote file — not yet downloaded)'}
              </div>
            )}

            {/* Metadata */}
            <div className="grid grid-cols-2 gap-3 text-sm mb-4">
              {[
                { label: 'Original Size',  val: selectedFile.original_size > 0 ? fmtBytes(selectedFile.original_size) : '—' },
                { label: 'Encrypted Size', val: selectedFile.encrypted_size > 0 ? fmtBytes(selectedFile.encrypted_size) : '—' },
                { label: 'Duration',       val: `${selectedFile.duration_months} months` },
                { label: 'Status',         val: selectedFile.status },
                { label: 'Stored',         val: new Date(selectedFile.stored_at * 1000).toLocaleDateString() },
                { label: 'Expires',        val: new Date(selectedFile.expiry * 1000).toLocaleDateString() },
                { label: 'Encryption',     val: 'AES-256-GCM' },
                { label: 'Hash',           val: 'BLAKE2s-256' },
              ].map(({ label, val }) => (
                <div key={label} className="bg-gray-900 rounded-lg p-3">
                  <div className="text-xs text-gray-400 mb-0.5">{label}</div>
                  <div className="font-medium text-sm">{val}</div>
                </div>
              ))}
            </div>

            <div className="mb-3">
              <div className="text-xs text-gray-400 mb-1">Network CID</div>
              <div className="bg-gray-900 rounded-lg p-3 font-mono text-xs text-green-400 break-all">{selectedFile.cid}</div>
            </div>

            <div className="flex gap-3">
              <button onClick={() => handleDelete(selectedFile.cid)} className="w-full bg-red-600/20 hover:bg-red-600/40 text-red-400 py-2.5 rounded-xl text-sm font-semibold transition">
                🗑 Delete File
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};

export default StoragePage;
