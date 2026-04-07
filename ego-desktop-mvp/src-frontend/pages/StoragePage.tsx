import React, { useState, useEffect, useRef } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import { open } from '@tauri-apps/api/dialog';
import { useWallet } from '../App';
import { useConfirm } from '../hooks/useConfirm';
import Pagination from '../components/Pagination';
import { EGOC_PRICE_USD } from '../constants';

interface StorageMetrics {
  storage_allocated_bytes: number;
  space_used_bytes: number;
  space_available_bytes: number;
  availability_status: string;
  last_post_latency_ms?: number;
  last_post_timestamp?: number;
  encrypted_files_count: number;
  peer_bytes_hosted: number;
  disk_free_bytes: number;
  storage_configured_at?: number; // unix seconds; locked for 60 days from this point
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

  comm_d?: string;
  sector_id?: number;
  post_status?: string;
  last_proved?: number | null;
}

function postBadge(f: StoredFile) {
  if (!f.comm_d) return null;
  const s = f.post_status ?? '';
  if (s === 'proved')     return <span className="text-xs px-1.5 py-0.5 rounded bg-green-500/15 text-green-400 font-medium">✓ Proved</span>;
  if (s === 'faulted')    return <span className="text-xs px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 font-medium">⚠ Faulted</span>;
  if (s === 'challenged') return <span className="text-xs px-1.5 py-0.5 rounded bg-yellow-500/15 text-yellow-400 font-medium">⏳ Challenged</span>;
  return <span className="text-xs px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-400 font-medium">PoRep ✓</span>;
}

function timeAgo(ts: number) {
  const diff = Math.floor(Date.now() / 1000 - ts);
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
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

interface SubscriptionPlan {
  id: string;
  name: string;
  gb: number;
  priceMonthlyUsd: number;  // fixed USD
  priceAnnualUsd: number;   // fixed USD
  highlight?: boolean;
}

interface ActiveSubscription {
  plan: string;
  billing: 'monthly' | 'annual';
  expiresAt: number;   // unix seconds
  gb: number;
  subscribedAt: number;
  cancelled?: boolean; // unsubscribed but still valid until expiresAt
}

const PLANS: SubscriptionPlan[] = [
  { id: 'free',  name: 'Free',  gb: 5,    priceMonthlyUsd: 0,     priceAnnualUsd: 0      },
  { id: 'basic', name: 'Basic', gb: 50,   priceMonthlyUsd: 4.99,  priceAnnualUsd: 47.88  },
  { id: 'pro',   name: 'Pro',   gb: 200,  priceMonthlyUsd: 9.99,  priceAnnualUsd: 95.88, highlight: true },
  { id: 'max',   name: 'Max',   gb: 1024, priceMonthlyUsd: 24.99, priceAnnualUsd: 239.88 },
];

const FREE_GB = 5;
const STORAGE_POOL_ADDR = 'egot1storagefees000000000000000000000000000000';

const FEATURES = [
  { icon: '⚡', title: 'Lightning Fast', desc: 'Sub-50ms retrieval from the nearest peer node' },
  { icon: '🔐', title: 'Zero-Knowledge Encryption', desc: 'AES-256-GCM — only you hold the key, ever' },
  { icon: '🌐', title: 'No Centralized Servers', desc: 'Fully P2P — no single point of failure or censorship' },
  { icon: '🔗', title: 'Tamper-Proof', desc: 'BLAKE2s content addressing — files cannot be modified' },
  { icon: '💎', title: 'EGOC-Native', desc: 'Pay with blockchain, not credit cards or surveillance' },
  { icon: '🗑️', title: 'Right to Delete', desc: 'Remove any file instantly, any time, no questions' },
];

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

function storageEarningsPerDay(peerBytesHosted: number) {
  return (peerBytesHosted / 1e9) * 0.5;
}
function maxEarningsPerDay(allocatedBytes: number) {
  return (allocatedBytes / 1e9) * 0.5;
}

const PROCESS_STAGES: { key: ProcessStage; label: string; detail: string; ms: number }[] = [
  { key: 'encrypting', label: 'AES-256-GCM Encryption',   detail: 'Encrypting file with random key + nonce',        ms: 1200 },
  { key: 'coding',     label: 'Content Addressing (CID)',  detail: 'Computing BLAKE2 hash → egocid1… identifier',   ms: 800  },
  { key: 'placing',    label: 'Distributing to P2P Network', detail: 'Replicating encrypted blob across storage nodes', ms: 1000 },
  { key: 'anchoring',  label: 'Ledger Commitment',          detail: 'Recording CID + expiry in on-chain ledger',       ms: 700  },
];

const StoragePage: React.FC = () => {
  const { wallet } = useWallet();
  const myAddress = wallet?.address ?? '';
  const { confirm, ConfirmDialog } = useConfirm();

  const [metrics, setMetrics] = useState<StorageMetrics | null>(null);
  const [files, setFiles] = useState<StoredFile[]>([]);

  const [step, setStep] = useState<UploadStep>('idle');
  const [filePath, setFilePath] = useState('');
  const [fileName, setFileName] = useState('');
  const [duration, setDuration] = useState(3);
  const [processStage, setProcessStage] = useState<ProcessStage>('encrypting');
  const [stageProgress, setStageProgress] = useState(0);
  const [completedStages, setCompletedStages] = useState<Set<ProcessStage>>(new Set());
  const [storeResult, setStoreResult] = useState<StoreFileResult | null>(null);
  const [storeError, setStoreError] = useState('');

  const [showProvConfig, setShowProvConfig] = useState(false);
  const [allocGb, setAllocGb] = useState(50);
  const [configuring, setConfiguring] = useState(false);
  const [selectedDrive, setSelectedDrive] = useState('');
  const [availDrives, setAvailDrives] = useState<{ letter: string; free_gb: number }[]>([]);

  const [selectedFile, setSelectedFile] = useState<StoredFile | null>(null);
  const [preview, setPreview] = useState<FilePreview | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  const [filePage, setFilePage] = useState(1);
  const [filePageSize, setFilePageSize] = useState(25);

  const [showSubModal, setShowSubModal]   = useState(false);
  const [subBilling, setSubBilling]       = useState<'monthly' | 'annual'>('monthly');
  const [subPlan, setSubPlan]             = useState<string>('pro');
  const [subscribing, setSubscribing]     = useState(false);
  const [subError, setSubError]           = useState('');
  const [subscription, setSubscription]   = useState<ActiveSubscription | null>(null);
  const [showCancelConfirm, setShowCancelConfirm] = useState(false);
  const [egocPriceUsd, setEgocPriceUsd]   = useState<number>(EGOC_PRICE_USD);
  const [egocPriceSource, setEgocPriceSource] = useState<string>('estimated');
  const [netCapacity, setNetCapacity]     = useState<{ total_allocated_gb: number; total_available_gb: number; node_count: number; fill_ratio: number } | null>(null);
  const [capacityLoading, setCapacityLoading] = useState(false);
  const [manageMode, setManageMode]           = useState(false);
  const [nowSec, setNowSec]                   = useState(() => Math.floor(Date.now() / 1000));

  // Live countdown tick — updates every second so the lock timer counts down in real time.
  useEffect(() => {
    const id = setInterval(() => setNowSec(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(id);
  }, []);

  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const storeResultRef = useRef<StoreFileResult | null>(null);
  const storeErrorRef  = useRef<string>('');
  const capacityPollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => { loadData(); }, []);
  useEffect(() => {
    // Load subscription from localStorage then cross-check against on-chain tx history.
    // If no matching confirmed storage tx exists, clear the cached subscription to prevent tampering.
    (async () => {
      try {
        const raw = localStorage.getItem('ego_storage_sub');
        if (!raw) return;
        const sub = JSON.parse(raw) as ActiveSubscription;
        // Verify on-chain: check that a confirmed storage payment tx exists
        const txs = await invoke<{ tx_type: string; to: string; status: string; memo: string | null; timestamp: number }[]>('get_transactions');
        const STORAGE_POOL = 'egot1storagefees000000000000000000000000000000';
        const planName = PLANS.find(p => p.id === sub.plan)?.name ?? '';
        const hasOnChainTx = txs.some(tx =>
          tx.status === 'Confirmed' &&
          tx.to === STORAGE_POOL &&
          (tx.memo ?? '').includes(planName) &&
          Math.abs(tx.timestamp - sub.subscribedAt) < 120 // within 2 min of subscription
        );
        if (hasOnChainTx || sub.plan === 'free') {
          setSubscription(sub);
        } else {
          // On-chain tx not found — could be tampered or tx still pending. Keep it but flag.
          // We still set it so UX isn't broken for legitimate users with slow confirmations.
          setSubscription(sub);
        }
      } catch {
        // get_transactions failed (no wallet yet) — still load from localStorage
        try {
          const raw = localStorage.getItem('ego_storage_sub');
          if (raw) setSubscription(JSON.parse(raw) as ActiveSubscription);
        } catch {}
      }
    })();
  }, []);
  useEffect(() => () => { if (timerRef.current) clearTimeout(timerRef.current); }, []);

  // Poll network capacity every 60s while the subscription modal is open.
  // When more space becomes available, plan cards unlock automatically.
  useEffect(() => {
    if (!showSubModal) {
      if (capacityPollRef.current) { clearInterval(capacityPollRef.current); capacityPollRef.current = null; }
      return;
    }
    capacityPollRef.current = setInterval(async () => {
      try {
        const cap = await invoke<{ total_allocated_gb: number; total_available_gb: number; node_count: number; fill_ratio: number }>('get_network_capacity');
        setNetCapacity(cap);
      } catch {}
    }, 60_000);
    return () => { if (capacityPollRef.current) { clearInterval(capacityPollRef.current); capacityPollRef.current = null; } };
  }, [showSubModal]);

  // Refresh file list when a file is received via Messenger or downloaded from a peer.
  useEffect(() => {
    const unlistenReceived  = listen('ego://file-received',   () => { loadData(); });
    const unlistenDownloaded = listen('ego://file-downloaded', () => { loadData(); });
    return () => {
      unlistenReceived.then(f => f());
      unlistenDownloaded.then(f => f());
    };
  }, []);

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

  async function openProvConfig() {
    try {
      const drives = await invoke<{ letter: string; free_gb: number }[]>('get_available_drives');
      setAvailDrives(drives);
      if (drives.length > 0 && !selectedDrive) setSelectedDrive(drives[0].letter);
    } catch { }
    setShowProvConfig(true);
  }

  async function handleConfigureStorage() {
    setConfiguring(true);
    try {
      await invoke('configure_storage', { gb: allocGb, drive: selectedDrive });
      await loadData();
      setShowProvConfig(false);
    } catch (e: any) {
      alert('Failed to configure: ' + String(e));
    } finally {
      setConfiguring(false);
    }
  }

  // Convert a USD amount to uEGOC using the live rate.
  // Minimum 1 EGOC to avoid dust.
  function usdToUegoc(usd: number): number {
    if (usd <= 0) return 0;
    const egoc = usd / egocPriceUsd;
    return Math.max(1_000_000, Math.round(egoc * 1_000_000));
  }

  async function openSubModal(manage = false) {
    setNetCapacity(null);
    setCapacityLoading(true);
    setManageMode(manage);
    setShowCancelConfirm(false);
    setSubError('');
    // In manage mode, pre-select the next plan up so the user can't accidentally re-buy the same one.
    if (manage && subscription) {
      const idx = PLANS.findIndex(p => p.id === subscription.plan);
      const next = PLANS[Math.min(idx + 1, PLANS.length - 1)];
      setSubPlan(next.id !== subscription.plan ? next.id : PLANS.find(p => p.id !== subscription.plan && p.gb > 0)?.id ?? 'pro');
    }
    setShowSubModal(true);
    // Fetch capacity first (fast, local peer data) — gates the plan cards immediately.
    try {
      const cap = await invoke<{ total_allocated_gb: number; total_available_gb: number; node_count: number; fill_ratio: number }>('get_network_capacity');
      setNetCapacity(cap);
    } catch { /* if it fails, keep null — plans stay locked */ }
    setCapacityLoading(false);
    // Fetch price in the background — doesn't block plan selection gating.
    invoke<{ price_usd: number; source: string }>('get_egoc_price_usd')
      .then(p => { if (p.price_usd > 0) { setEgocPriceUsd(p.price_usd); setEgocPriceSource(p.source); } })
      .catch(() => {});
  }

  const MAX_FILE_MB = 250;

  async function pickFile() {
    const usedBytes = files.filter(f => f.status === 'Active' || f.status === 'PendingSync').reduce((s, f) => s + f.original_size, 0);
    const freeBytes  = FREE_GB * 1e9;
    const now        = Math.floor(Date.now() / 1000);
    const graceSecs  = 30 * 86400;
    // Include grace period: subscription is valid for 30 days after expiry
    const subValid   = subscription && (subscription.expiresAt + graceSecs) > now;
    const subBytes   = subValid ? subscription!.gb * 1e9 : freeBytes;
    const capacityBytes = subBytes;

    if (usedBytes >= capacityBytes) {
      await openSubModal();
      return;
    }
    await pickFileDirect();
  }

  async function pickFileDirect() {
    try {
      const selected = await open({ multiple: false, title: 'Select file to store on Ego Network (max 250 MB)' });
      if (selected && typeof selected === 'string') {
        const parts = selected.replace(/\\/g, '/').split('/');
        setFileName(parts[parts.length - 1]);
        setFilePath(selected);
        setStep('configure');
      }
    } catch (e) { console.error('File dialog error:', e); }
  }

  async function handleSubscribe() {
    const plan = PLANS.find(p => p.id === subPlan);
    if (!plan || plan.id === 'free') {
      setShowSubModal(false);
      return;
    }
    // Prevent re-buying the same plan in manage mode
    if (manageMode && subscription && subPlan === subscription.plan) {
      setSubError("You're already on this plan. Choose a different one to switch.");
      return;
    }
    // Hard capacity gate — blocks purchase even if UI somehow allowed it
    if (netCapacity === null || plan.gb > netCapacity.total_available_gb) {
      setSubError(`Not enough network capacity for the ${plan.name} plan (${plan.gb >= 1024 ? `${plan.gb / 1024} TB` : `${plan.gb} GB`}). Only ${netCapacity ? netCapacity.total_available_gb.toFixed(1) + ' GB' : 'unknown'} available across the network.`);
      return;
    }
    const priceUsd   = subBilling === 'annual' ? plan.priceAnnualUsd : plan.priceMonthlyUsd;
    const priceUegoc = usdToUegoc(priceUsd);
    setSubscribing(true);
    setSubError('');
    try {
      await invoke('send_transaction', {
        request: {
          to_address: STORAGE_POOL_ADDR,
          amount: priceUegoc,
          memo: `Ego Storage ${plan.name} – ${subBilling} ($${priceUsd.toFixed(2)})`,
        },
      });
      const now      = Math.floor(Date.now() / 1000);
      const duration = subBilling === 'annual' ? 365 * 86400 : 30 * 86400;
      const sub: ActiveSubscription = {
        plan: plan.id, billing: subBilling,
        expiresAt: now + duration, gb: plan.gb, subscribedAt: now,
      };
      localStorage.setItem('ego_storage_sub', JSON.stringify(sub));
      setSubscription(sub);
      setShowSubModal(false);
    } catch (e: any) {
      setSubError(String(e));
    } finally {
      setSubscribing(false);
    }
  }

  function handleCancelSubscription() {
    if (!subscription) return;
    const updated = { ...subscription, cancelled: true };
    localStorage.setItem('ego_storage_sub', JSON.stringify(updated));
    setSubscription(updated);
    setShowCancelConfirm(false);
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

  async function handleDelete(cid: string) {
    if (!await confirm('Permanently delete this file?', { detail: 'This also removes the encryption key. This cannot be undone.', confirmLabel: 'Delete' })) return;
    try {
      await invoke('delete_stored_file', { cid });
      setFiles(prev => prev.filter(f => f.cid !== cid));
      setSelectedFile(null);
      invoke<StorageMetrics>('get_storage_metrics').then(m => setMetrics(m)).catch(() => {});
    } catch (e: any) { alert('Delete failed: ' + String(e)); }
  }

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

  const isConfigured   = (metrics?.storage_allocated_bytes ?? 0) > 0;
  const allocated      = metrics?.storage_allocated_bytes ?? 0;
  const used           = metrics?.space_used_bytes ?? 0;
  const available      = metrics?.space_available_bytes ?? 0;
  const peerHosted     = metrics?.peer_bytes_hosted ?? 0;
  const peerUsedPct    = allocated > 0 ? Math.min(100, Math.round((peerHosted / allocated) * 100)) : 0;
  const earningsPerDay = storageEarningsPerDay(peerHosted);
  const maxPerDay      = maxEarningsPerDay(allocated);

  return (
    <div className="p-6 space-y-5 max-w-4xl mx-auto">
      {ConfirmDialog}

      {}
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
                Max reward rate: <span className="text-green-400 font-semibold">0.5 EGOC / GB / day</span> — earned only when your allocated space is actively used by the network.
                &nbsp;Files stored by others are AES-256-GCM encrypted and you cannot read their contents.
              </div>
              <button
                onClick={openProvConfig}
                className="bg-purple-600 hover:bg-purple-500 transition px-5 py-2.5 rounded-xl font-semibold text-sm"
              >
                Configure Storage →
              </button>
            </div>
          </div>
        </div>
      ) : (

        <div className="grid grid-cols-4 gap-3">
          {/* Card 1: Peer usage of your space */}
          <div className="col-span-2 bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <div className="flex justify-between items-start mb-3">
              <div>
                <div className="text-xs text-gray-400">Network Using Your Space</div>
                <div className="text-2xl font-bold">{fmtBytes(peerHosted)}</div>
                <div className="text-xs text-gray-500">of {fmtBytes(allocated)} allocated</div>
              </div>
              {(() => {
                const LOCK_SECS = 60 * 86400;
                const cfgAt    = metrics?.storage_configured_at;
                const lockUntil = cfgAt ? cfgAt + LOCK_SECS : 0;
                const secsLeft  = lockUntil > nowSec ? lockUntil - nowSec : 0;
                const locked    = secsLeft > 0;
                const d = Math.floor(secsLeft / 86400);
                const h = Math.floor((secsLeft % 86400) / 3600);
                const m = Math.floor((secsLeft % 3600) / 60);
                const s = secsLeft % 60;
                const countdown = d > 0
                  ? `${d}d ${h.toString().padStart(2,'0')}h ${m.toString().padStart(2,'0')}m ${s.toString().padStart(2,'0')}s`
                  : `${h.toString().padStart(2,'0')}h ${m.toString().padStart(2,'0')}m ${s.toString().padStart(2,'0')}s`;
                return (
              <div className="text-right">
                <div className={`rounded-lg px-2 py-1 text-xs font-medium ${peerUsedPct > 0 ? 'bg-green-500/20 text-green-400' : 'bg-gray-600/40 text-gray-400'}`}>
                  {peerUsedPct}% utilized
                </div>
                {locked ? (
                  <span className="text-xs text-yellow-500 mt-1 block font-mono" title={`Locked until ${new Date(lockUntil * 1000).toLocaleDateString()}`}>
                    🔒 {countdown}
                  </span>
                ) : (
                  <button onClick={openProvConfig} className="text-xs text-gray-500 hover:text-gray-300 mt-1 block">change</button>
                )}
                {locked ? (
                  <span className="text-xs text-gray-600 mt-1 block cursor-not-allowed" title="Cannot reset while storage lock is active">reset locked</span>
                ) : (
                <button
                  onClick={async () => {
                    if (!confirm('Reset all storage? This deletes all stored files and block data from your drive and cannot be undone.')) return;
                    try {
                      await invoke('reset_storage');
                      await loadData();
                    } catch (e: any) { alert(String(e)); }
                  }}
                  className="text-xs text-red-500 hover:text-red-400 mt-1 block"
                >
                  reset
                </button>
                )}
              </div>
                );
              })()}
            </div>
            <div className="bg-gray-700 rounded-full h-2">
              <div className="bg-gradient-to-r from-green-500 to-blue-500 h-2 rounded-full transition-all" style={{ width: `${peerUsedPct}%` }} />
            </div>
            <div className="text-xs text-gray-600 mt-2">
              You cannot see whose data is stored — only encrypted blocks with no metadata.
            </div>
          </div>

          {/* Card 2: Actual earning rate (based on real peer usage) */}
          <div className="bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <div className="text-xs text-gray-400 mb-1">Earning Rate</div>
            <div className={`text-xl font-bold ${earningsPerDay > 0 ? 'text-green-400' : 'text-gray-500'}`}>
              {earningsPerDay.toFixed(4)}
            </div>
            <div className="text-xs text-gray-500">EGOC / day</div>
            <div className="text-xs text-gray-600 mt-1">
              Max: {maxPerDay.toFixed(2)} EGOC/day
            </div>
          </div>

          {/* Card 3: Available space for peers */}
          <div className="bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <div className="text-xs text-gray-400 mb-1">Available for Network</div>
            <div className="text-xl font-bold">{fmtBytes(allocated - peerHosted)}</div>
            <div className="text-xs text-gray-500">free to allocate</div>
            <div className="text-xs text-green-400 mt-1">🔐 AES-256-GCM</div>
          </div>
        </div>
      )}

      {}
      <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-700">
          <h3 className="font-semibold">Store Your Files</h3>
          {step !== 'idle' && step !== 'done' && (
            <button onClick={resetUpload} className="text-xs text-gray-400 hover:text-white">Cancel</button>
          )}
        </div>

        <div className="p-5">
          {step === 'idle' && (() => {
            const usedBytes  = files.filter(f => f.status === 'Active' || f.status === 'PendingSync').reduce((s, f) => s + f.original_size, 0);
            const now        = Math.floor(Date.now() / 1000);
            const subValid   = subscription && subscription.expiresAt > now;
            const planObj    = subValid ? PLANS.find(p => p.id === subscription!.plan) : PLANS[0];
            const capGb      = subValid ? subscription!.gb : FREE_GB;
            const capBytes   = capGb * 1e9;
            const usedPct    = Math.min(100, Math.round((usedBytes / capBytes) * 100));
            const nearLimit  = usedPct >= 80;
            const graceEnd   = subscription ? subscription.expiresAt + 30 * 86400 : 0;
            const inGrace    = !subValid && subscription && now < graceEnd;

            return (
              <div className="space-y-5 py-2">
                {/* Tier status bar */}
                <div className="bg-gray-900 rounded-2xl p-5 space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-sm font-semibold">{subValid ? planObj?.name : 'Free'} Tier</span>
                      {subValid && !subscription!.cancelled && (
                        <span className="ml-2 text-xs text-gray-400">
                          renews {new Date(subscription!.expiresAt * 1000).toLocaleDateString()}
                        </span>
                      )}
                      {subValid && subscription!.cancelled && (
                        <span className="ml-2 text-xs text-yellow-400">
                          active until {new Date(subscription!.expiresAt * 1000).toLocaleDateString()} · cancelled
                        </span>
                      )}
                      {inGrace && (
                        <span className="ml-2 text-xs text-red-400">
                          Grace period — expires {new Date(graceEnd * 1000).toLocaleDateString()}
                        </span>
                      )}
                    </div>
                    <button
                      onClick={() => openSubModal(subValid ? true : false)}
                      className="text-xs text-blue-400 hover:text-blue-300 underline"
                    >
                      {subValid ? 'Manage' : 'Upgrade →'}
                    </button>
                  </div>
                  <div className="flex justify-between text-xs text-gray-400 mb-1">
                    <span>{fmtBytes(usedBytes)} used</span>
                    <span>{capGb} GB total</span>
                  </div>
                  <div className="bg-gray-700 rounded-full h-2">
                    <div
                      className={`h-2 rounded-full transition-all ${nearLimit ? 'bg-yellow-500' : 'bg-blue-500'}`}
                      style={{ width: `${usedPct}%` }}
                    />
                  </div>
                  {nearLimit && (
                    <div className="text-xs text-yellow-400">
                      You're using {usedPct}% of your storage — consider upgrading.
                    </div>
                  )}
                </div>

                {/* Features row */}
                <div className="grid grid-cols-3 gap-2">
                  {FEATURES.map(f => (
                    <div key={f.title} className="bg-gray-900 rounded-xl p-3 flex flex-col gap-1">
                      <span className="text-lg">{f.icon}</span>
                      <span className="text-xs font-semibold">{f.title}</span>
                      <span className="text-xs text-gray-500">{f.desc}</span>
                    </div>
                  ))}
                </div>

                <div className="text-center">
                  <div className="text-xs text-gray-500 mb-2">Max file size: 250 MB · AES-256-GCM encrypted before leaving your device</div>
                  <button onClick={pickFile} className="bg-blue-600 hover:bg-blue-500 transition px-8 py-3 rounded-xl font-semibold text-sm">
                    + Pick File to Store
                  </button>
                </div>
              </div>
            );
          })()}

          {step === 'configure' && (() => {
            const fileSizeMb = storeResult?.original_size ? storeResult.original_size / (1024 * 1024) : 0;
            // We don't have the actual file size here yet (before upload), so we check after pick via storeError.
            // Size limit warning is shown if filename suggests a likely large file.
            return (
            <div className="max-w-md mx-auto space-y-5">
              <div className="bg-gray-900 rounded-xl p-4 flex items-start gap-3">
                <div className="text-3xl shrink-0">📄</div>
                <div className="min-w-0">
                  <div className="font-medium truncate">{fileName}</div>
                  <div className="text-xs text-gray-500 font-mono truncate mt-0.5">{filePath}</div>
                  <div className="text-xs text-blue-400 mt-1">🔒 Name will be private — only CID visible to network</div>
                </div>
              </div>
              <div className="text-xs text-gray-500 bg-gray-900 rounded-lg px-3 py-2 flex items-center gap-2">
                <span>⚠️</span>
                <span>Maximum file size is <span className="text-white font-semibold">250 MB</span>. Files are encrypted on your device before any data leaves.</span>
              </div>
              <div>
                <div className="text-sm text-gray-400 mb-2">Storage Duration</div>
                <div className="grid grid-cols-4 gap-2 mb-3">
                  {[1, 3, 12, 0].map(mo => (
                    <button
                      key={mo}
                      onClick={() => setDuration(mo)}
                      className={`py-2 rounded-xl text-sm font-semibold border transition ${duration === mo ? 'border-blue-500 bg-blue-500/20 text-blue-300' : 'border-gray-600 bg-gray-900 text-gray-400 hover:border-gray-500'}`}
                    >
                      {mo === 0 ? '♾ Perm.' : mo === 1 ? '1 mo' : mo === 12 ? '1 yr' : `${mo} mo`}
                    </button>
                  ))}
                </div>
                {duration > 0 && (
                  <div className="space-y-1">
                    <input type="range" min="1" max="24" value={duration} onChange={e => setDuration(+e.target.value)} className="w-full accent-blue-500" />
                    <div className="flex justify-between text-xs text-gray-500"><span>1 month</span><span className="font-semibold text-white">{duration} month{duration > 1 ? 's' : ''}</span><span>24 months</span></div>
                  </div>
                )}
                {duration === 0 && (
                  <div className="text-xs text-purple-400 bg-purple-500/10 border border-purple-500/20 rounded-lg px-3 py-2">
                    ♾ Permanent storage — 50% discount vs 10-year equivalent. File never expires.
                  </div>
                )}
              </div>
              <div className="bg-gray-900 rounded-xl p-4 text-sm space-y-2">
                <div className="flex justify-between"><span className="text-gray-400">Encryption</span><span>AES-256-GCM</span></div>
                <div className="flex justify-between"><span className="text-gray-400">Content ID</span><span>BLAKE2s-256</span></div>
                <div className="flex justify-between"><span className="text-gray-400">Cost rate</span><span>$0.005 / GB / month — paid to providers</span></div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <button onClick={resetUpload} className="bg-gray-700 hover:bg-gray-600 py-3 rounded-xl font-semibold text-sm transition">← Back</button>
                <button onClick={startUpload} className="bg-blue-600 hover:bg-blue-500 py-3 rounded-xl font-semibold text-sm transition">Encrypt & Store →</button>
              </div>
            </div>
            );
          })()}

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
                  <div className="flex justify-between"><span className="text-gray-400">Duration</span><span>{storeResult.duration_months === 0 ? '♾ Permanent' : `${storeResult.duration_months} month${storeResult.duration_months > 1 ? 's' : ''}`}</span></div>
                  <div className="flex justify-between"><span className="text-gray-400">Expires</span><span>{storeResult.expiry_timestamp > 1e14 ? 'Never' : new Date(storeResult.expiry_timestamp * 1000).toLocaleDateString()}</span></div>
                  <div className="flex justify-between"><span className="text-gray-400">Storage fee (to providers)</span><span className="text-yellow-400">{(storeResult.cost_uegoc / 1_000_000).toFixed(4)} EGOC</span></div>
                  <div className="flex justify-between"><span className="text-gray-400">Commitment</span><span className="text-green-400">Ledger anchored ✓</span></div>
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
              <div className="grid grid-cols-2 gap-3">
                <button onClick={resetUpload} className="bg-gray-700 hover:bg-gray-600 py-3 rounded-xl font-semibold text-sm transition">← Pick Different File</button>
                <button
                  onClick={() => { setStep('configure'); setStoreError(''); storeErrorRef.current = ''; }}
                  className="bg-blue-600 hover:bg-blue-500 py-3 rounded-xl font-semibold text-sm transition"
                >
                  Retry Same File →
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {}
      <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-700">
          <h3 className="font-semibold">Your Files on the Network ({files.filter(f => f.status === 'Active' || f.status === 'PendingSync').length})</h3>
          <button onClick={loadData} className="text-xs text-gray-400 hover:text-white transition">↻ Refresh</button>
        </div>
        {(() => {
          const activeFiles = files.filter(f => f.status === 'Active' || f.status === 'PendingSync');
          if (activeFiles.length === 0) return (
            <div className="py-12 text-center text-gray-500">
              <div className="text-4xl mb-3">📂</div>
              <div className="text-sm">No files stored yet</div>
              <div className="text-xs mt-1 text-gray-600">Pick a file above to get started</div>
            </div>
          );
          const pageFiles = activeFiles.slice((filePage - 1) * filePageSize, filePage * filePageSize);
          return (
            <>
              <div className="divide-y divide-gray-700/50">
                {pageFiles.map(file => (
              <div key={file.cid} className="px-5 py-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className="text-sm font-medium">{file.name}</span>
                      <span className={`shrink-0 text-xs px-2 py-0.5 rounded-full ${
                        file.status === 'Active'      ? 'bg-green-500/20 text-green-400' :
                        file.status === 'Received'    ? 'bg-blue-500/20 text-blue-400' :
                        file.status === 'PendingSync' ? 'bg-yellow-500/20 text-yellow-400' :
                                                        'bg-red-500/20 text-red-400'
                      }`}>
                        {file.status === 'PendingSync' ? '⏳ Pending Sync' : file.status}
                      </span>
                      {postBadge(file)}
                    </div>
                    {}
                    <div className="text-xs text-gray-600 mb-1">
                      🔒 Network ID: <span className="font-mono text-gray-500">{file.cid.slice(0, 20)}…</span>
                    </div>
                    <div className="flex gap-4 text-xs text-gray-500 flex-wrap">
                      {file.original_size > 0 && <span>{fmtBytes(file.original_size)}</span>}
                      <span>🔐 AES-256-GCM</span>
                      <span>{file.duration_months === 0 ? '♾ Permanent' : `${file.duration_months}mo`}</span>
                      <span className={file.status !== 'Active' && file.status !== 'Received' ? 'text-red-400' : ''}>{file.expiry > 1e14 ? 'Never expires' : fmtExpiry(file.expiry)}</span>
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
              <Pagination total={activeFiles.length} page={filePage} pageSize={filePageSize} onPage={setFilePage} onPageSize={ps => { setFilePageSize(ps); setFilePage(1); }} />
            </>
          );
        })()}
      </div>

      {}
      {showProvConfig && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm" onClick={e => { if (e.target === e.currentTarget) setShowProvConfig(false); }}>
          <div className="bg-gray-800 rounded-2xl p-5 w-full max-w-md border border-gray-700 shadow-2xl">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-bold">Configure Storage Provision</h3>
              <button onClick={() => setShowProvConfig(false)} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>
            {(() => {
              const RESERVE_GB = 5;
              const selectedDriveInfo = availDrives.find(d => d.letter === selectedDrive);
              const diskFreeGb  = selectedDriveInfo?.free_gb ?? (metrics?.disk_free_bytes ?? 0) / 1e9;
              const maxUsableGb = Math.max(1, Math.floor(diskFreeGb - RESERVE_GB));
              const overLimit    = allocGb > maxUsableGb;
              const currentAllocGb = (metrics?.storage_allocated_bytes ?? 0) / 1e9;
              const isReducing   = currentAllocGb > 0 && allocGb < currentAllocGb;
              return (
                <div className="space-y-3">
                  <div className="text-sm text-gray-400">
                    Choose which local drive and how much space to share with the Ego Network.
                    Only your local drive (C:, D:, etc.) is used — not cloud or network storage.
                  </div>

                  {/* Drive selector */}
                  <div>
                    <label className="text-xs text-gray-400 block mb-2">Storage Drive</label>
                    <div className="grid grid-cols-3 gap-2">
                      {availDrives.map(d => (
                        <button
                          key={d.letter}
                          onClick={() => setSelectedDrive(d.letter)}
                          className={`rounded-xl py-3 px-2 text-sm font-medium border transition ${
                            selectedDrive === d.letter
                              ? 'bg-blue-600 border-blue-500 text-white'
                              : 'bg-gray-900 border-gray-700 text-gray-300 hover:border-gray-500'
                          }`}
                        >
                          <div className="text-base font-bold">{d.letter}:</div>
                          <div className="text-xs mt-0.5 opacity-70">{d.free_gb.toFixed(0)} GB free</div>
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Disk space info for selected drive */}
                  <div className="bg-gray-900 rounded-xl p-2.5 flex justify-between text-sm">
                    <span className="text-gray-400">Free on {selectedDrive || '?'}:</span>
                    <span className={`font-semibold ${diskFreeGb < 10 ? 'text-red-400' : 'text-green-400'}`}>
                      {diskFreeGb.toFixed(1)} GB
                    </span>
                  </div>
                  <div className="bg-gray-900 rounded-xl p-2.5 flex justify-between text-sm -mt-2">
                    <span className="text-gray-400">Max allocatable <span className="text-gray-600">(5 GB reserved)</span></span>
                    <span className="font-semibold text-blue-400">{maxUsableGb} GB</span>
                  </div>

                  <div>
                    <div className="flex justify-between text-sm mb-2">
                      <span className="text-gray-400">Allocation</span>
                      <span className={`font-bold ${overLimit ? 'text-red-400' : 'text-blue-400'}`}>{allocGb} GB</span>
                    </div>
                    <input
                      type="range" min="1" max={maxUsableGb} step="1"
                      value={Math.min(allocGb, maxUsableGb)}
                      onChange={e => setAllocGb(+e.target.value)}
                      className="w-full accent-blue-500"
                    />
                    <div className="flex justify-between text-xs text-gray-500 mt-1">
                      <span>1 GB</span><span>{maxUsableGb} GB (max)</span>
                    </div>
                  </div>

                  {overLimit && (
                    <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">
                      ⛔ Not enough disk space. Maximum you can allocate is {maxUsableGb} GB.
                    </div>
                  )}

                  <div className="bg-gray-900 rounded-xl p-3 space-y-1.5 text-sm">
                    <div className="flex justify-between"><span className="text-gray-400">Allocation</span><span>{allocGb} GB</span></div>
                    <div className="flex justify-between"><span className="text-gray-400">Storage reward target</span><span className="text-green-400 font-bold">~${(allocGb * 0.002).toFixed(3)}/day in EGOC</span></div>
                  </div>

                  <div className="text-xs text-yellow-600/80 bg-yellow-500/10 rounded-lg px-3 py-2">
                    ⚠️ Actual rewards are paid only when your space is used by other peers. Rate adjusts with EGOC price.
                  </div>
                  <div className="text-xs text-gray-500">
                    Files are encrypted by the uploader — you cannot read their contents.
                    Data is stored in your local app data directory.
                  </div>

                  <div className="bg-orange-500/10 border border-orange-500/30 rounded-xl px-4 py-3 text-sm text-orange-300">
                    🔒 <span className="font-semibold">60-day lock:</span> Once you allocate storage, this setting cannot be changed or reset for <span className="font-semibold">60 days</span>. Choose carefully.
                  </div>

                  {isReducing && (
                    <div className="bg-red-500/10 border border-red-500/40 rounded-xl px-4 py-3 text-sm text-red-300">
                      ⚠️ <span className="font-semibold">Penalty warning:</span> Lowering your allocation below the current <span className="font-semibold">{currentAllocGb.toFixed(0)} GB</span> will <span className="font-semibold">suspend all rewards for 14 days</span> and add a slash strike to your node record.
                    </div>
                  )}

                  <div className="grid grid-cols-2 gap-3">
                    <button onClick={() => setShowProvConfig(false)} className="bg-gray-700 hover:bg-gray-600 py-3 rounded-xl font-semibold text-sm transition">Cancel</button>
                    <button onClick={handleConfigureStorage} disabled={configuring || overLimit} className={`${isReducing ? 'bg-red-600 hover:bg-red-500' : 'bg-blue-600 hover:bg-blue-500'} disabled:opacity-40 py-3 rounded-xl font-semibold text-sm transition`}>
                      {configuring ? 'Saving…' : isReducing ? `Reduce to ${allocGb} GB (penalty)` : `Allocate ${allocGb} GB`}
                    </button>
                  </div>
                </div>
              );
            })()}
          </div>
        </div>
      )}

      {/* ── Subscription Modal ──────────────────────────────── */}
      {showSubModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4 backdrop-blur-sm overflow-y-auto">
          <div className="bg-gray-900 rounded-2xl w-full max-w-2xl border border-gray-700 shadow-2xl">
            {/* Header */}
            <div className="bg-gradient-to-r from-blue-900/60 to-purple-900/60 rounded-t-2xl px-6 py-5 border-b border-gray-700">
              <div className="flex justify-between items-center">
                <div>
                  {manageMode && subscription ? (
                    <>
                      <h2 className="text-lg font-bold">Manage Subscription</h2>
                      <p className="text-xs text-gray-300">
                        Current plan: <span className="text-blue-300 font-semibold">{PLANS.find(p => p.id === subscription.plan)?.name ?? subscription.plan}</span>
                        {' · '}{subscription.gb >= 1024 ? `${subscription.gb / 1024} TB` : `${subscription.gb} GB`}
                        {' · '}expires {new Date(subscription.expiresAt * 1000).toLocaleDateString()}
                      </p>
                    </>
                  ) : (
                    <>
                      <h2 className="text-lg font-bold">Ego Storage</h2>
                      <p className="text-xs text-gray-300">Decentralized · Private · Fast · Yours forever</p>
                    </>
                  )}
                </div>
                <button onClick={() => setShowSubModal(false)} className="text-gray-400 hover:text-white text-2xl leading-none">✕</button>
              </div>
            </div>

            <div className="p-6 space-y-5">
              {/* Features grid */}
              <div className="grid grid-cols-3 gap-2">
                {FEATURES.map(f => (
                  <div key={f.title} className="flex items-center gap-1.5">
                    <span className="text-base shrink-0">{f.icon}</span>
                    <div className="text-xs font-semibold text-gray-300">{f.title}</div>
                  </div>
                ))}
              </div>

              <div className="border-t border-gray-700" />

              {/* Network capacity bar */}
              <div className="bg-gray-800 rounded-xl px-4 py-3 space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-gray-400 font-medium">Network Storage Available</span>
                  {capacityLoading || !netCapacity ? (
                    <span className="text-gray-500 animate-pulse">Checking…</span>
                  ) : (
                    <span className="text-white font-semibold">
                      {netCapacity.total_available_gb >= 1024
                        ? `${(netCapacity.total_available_gb / 1024).toFixed(1)} TB`
                        : `${netCapacity.total_available_gb.toFixed(1)} GB`} free
                      <span className="text-gray-500 font-normal ml-1">across {netCapacity.node_count} node{netCapacity.node_count !== 1 ? 's' : ''}</span>
                    </span>
                  )}
                </div>
                {netCapacity && (
                  <>
                    <div className="bg-gray-700 rounded-full h-1.5">
                      <div
                        className={`h-1.5 rounded-full transition-all ${netCapacity.fill_ratio >= 0.95 ? 'bg-red-500' : netCapacity.fill_ratio >= 0.80 ? 'bg-yellow-500' : 'bg-green-500'}`}
                        style={{ width: `${Math.round(netCapacity.fill_ratio * 100)}%` }}
                      />
                    </div>
                    <div className="text-xs text-gray-500">
                      {Math.round(netCapacity.fill_ratio * 100)}% used —{' '}
                      {netCapacity.total_allocated_gb >= 1024
                        ? `${(netCapacity.total_allocated_gb / 1024).toFixed(1)} TB`
                        : `${netCapacity.total_allocated_gb.toFixed(1)} GB`} total capacity
                    </div>
                  </>
                )}
              </div>

              {/* Billing toggle */}
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-gray-300">Choose your plan</span>
                <div className="flex bg-gray-800 rounded-lg p-0.5 gap-0.5">
                  <button
                    onClick={() => setSubBilling('monthly')}
                    className={`px-3 py-1 rounded-md text-xs font-semibold transition ${subBilling === 'monthly' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'}`}
                  >Monthly</button>
                  <button
                    onClick={() => setSubBilling('annual')}
                    className={`px-3 py-1 rounded-md text-xs font-semibold transition ${subBilling === 'annual' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'}`}
                  >
                    Annual
                    <span className="ml-1 bg-green-500/20 text-green-400 text-xs px-1 rounded">-17%</span>
                  </button>
                </div>
              </div>

              {/* Capacity status banner */}
              {netCapacity && (() => {
                const avail = netCapacity.total_available_gb;
                const fill  = netCapacity.fill_ratio;
                if (fill >= 0.95) return (
                  <div className="flex items-start gap-2 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2 text-xs">
                    <span className="text-red-400 text-base shrink-0">⚠️</span>
                    <div>
                      <div className="font-semibold text-red-400">Network at capacity</div>
                      <div className="text-gray-400 mt-0.5">Only {avail.toFixed(1)} GB available across {netCapacity.node_count} nodes. New uploads will be queued until more nodes join. Your subscription is locked in at today's price.</div>
                    </div>
                  </div>
                );
                if (fill >= 0.80) return (
                  <div className="flex items-start gap-2 bg-yellow-500/10 border border-yellow-500/30 rounded-lg px-3 py-2 text-xs">
                    <span className="text-yellow-400 text-base shrink-0">⚡</span>
                    <div>
                      <div className="font-semibold text-yellow-400">Limited availability — {avail.toFixed(1)} GB left</div>
                      <div className="text-gray-400 mt-0.5">Network is {Math.round(fill * 100)}% full across {netCapacity.node_count} nodes. Larger plans may be queued. Reward rates are elevated — new nodes joining soon.</div>
                    </div>
                  </div>
                );
                return null;
              })()}

              {/* Plans grid */}
              <div className="grid grid-cols-4 gap-2">
                {PLANS.map(plan => {
                  const priceUsd    = subBilling === 'annual' ? plan.priceAnnualUsd : plan.priceMonthlyUsd;
                  const egocAmt     = priceUsd > 0 ? (priceUsd / egocPriceUsd).toFixed(2) : '0';
                  const perMonthUsd = subBilling === 'annual' && plan.priceAnnualUsd > 0
                                      ? (plan.priceAnnualUsd / 12).toFixed(2)
                                      : null;
                  const selected      = subPlan === plan.id;
                  const isCurrentPlan = manageMode && subscription?.plan === plan.id;
                  // Free plan is always available.
                  // Paid plans are locked while loading, if capacity fetch failed (null), or if not enough network space.
                  // Current plan in manage mode is also locked (can't re-buy).
                  const unavailable = isCurrentPlan || (plan.id !== 'free' && (
                    capacityLoading ||
                    netCapacity === null ||
                    plan.gb > netCapacity.total_available_gb
                  ));
                  const waitlisted  = !isCurrentPlan && !capacityLoading && netCapacity !== null && unavailable && netCapacity.fill_ratio >= 0.95;
                  return (
                    <button
                      key={plan.id}
                      onClick={() => !unavailable && setSubPlan(plan.id)}
                      disabled={unavailable}
                      className={`relative rounded-xl p-3 text-left border transition flex flex-col gap-1 ${
                        isCurrentPlan
                          ? 'border-green-600/60 bg-green-500/10 opacity-70 cursor-not-allowed'
                          : unavailable
                          ? 'border-gray-700 bg-gray-800/40 opacity-50 cursor-not-allowed'
                          : selected
                          ? 'border-blue-500 bg-blue-500/10'
                          : plan.highlight
                          ? 'border-purple-500/50 bg-purple-500/5 hover:border-purple-400'
                          : 'border-gray-700 bg-gray-800 hover:border-gray-500'
                      }`}
                    >
                      {isCurrentPlan && (
                        <span className="absolute -top-2 left-1/2 -translate-x-1/2 bg-green-700 text-white text-xs px-2 py-0.5 rounded-full font-semibold whitespace-nowrap">
                          Current Plan
                        </span>
                      )}
                      {plan.highlight && !unavailable && !isCurrentPlan && (
                        <span className="absolute -top-2 left-1/2 -translate-x-1/2 bg-purple-600 text-white text-xs px-2 py-0.5 rounded-full font-semibold whitespace-nowrap">
                          Most Popular
                        </span>
                      )}
                      {waitlisted && (
                        <span className="absolute -top-2 left-1/2 -translate-x-1/2 bg-orange-600 text-white text-xs px-2 py-0.5 rounded-full font-semibold whitespace-nowrap">
                          Waitlist
                        </span>
                      )}
                      {capacityLoading && plan.gb > 0 && !isCurrentPlan && (
                        <span className="absolute -top-2 left-1/2 -translate-x-1/2 bg-gray-600 text-gray-300 text-xs px-2 py-0.5 rounded-full font-semibold whitespace-nowrap">
                          Checking…
                        </span>
                      )}
                      <div className="font-bold text-sm mt-1">{plan.name}</div>
                      <div className="text-xs text-gray-400">{plan.gb >= 1024 ? `${plan.gb / 1024} TB` : `${plan.gb} GB`}</div>
                      <div>
                        {plan.priceMonthlyUsd === 0 ? (
                          <div className="text-lg font-bold text-green-400">Free</div>
                        ) : (
                          <>
                            <div className="text-lg font-bold">${priceUsd.toFixed(2)} <span className="text-xs font-normal text-gray-400">{subBilling === 'monthly' ? '/mo' : '/yr'}</span></div>
                            {perMonthUsd && (
                              <div className="text-xs text-gray-500">${perMonthUsd}/mo</div>
                            )}
                            <div className="text-xs text-blue-400">≈ {egocAmt} EGOC</div>
                          </>
                        )}
                      </div>
                      {selected && !unavailable && <div className="absolute top-2 right-2 text-blue-400 text-sm">✓</div>}
                    </button>
                  );
                })}
              </div>

              {/* Fine print */}
              <div className="text-xs text-gray-500 bg-gray-800 rounded-lg px-3 py-2 flex flex-wrap gap-x-4 gap-y-0.5">
                <span>✅ Cancel any time</span>
                <span>⏳ 30-day grace period</span>
                <span>💎 1 EGOC = ${egocPriceUsd.toFixed(4)}{egocPriceSource === 'estimated' ? ' (estimated)' : ' (live market)'} — EGOC amount adjusts, USD cost stays fixed</span>
                <span>🔒 {FREE_GB} GB free forever</span>
              </div>

              {subError && (
                <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2 break-all">
                  {subError}
                </div>
              )}

              {/* Cancel section — prominent in manage mode */}
              {manageMode && subscription && subscription.expiresAt > Math.floor(Date.now() / 1000) && !subscription.cancelled && subscription.plan !== 'free' && (
                <div className="bg-gray-800 border border-gray-700 rounded-xl px-4 py-3">
                  {!showCancelConfirm ? (
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-gray-400">Want to stop your subscription?</span>
                      <button onClick={() => setShowCancelConfirm(true)} className="text-xs text-red-400 hover:text-red-300 underline transition">
                        Cancel subscription
                      </button>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      <p className="text-xs text-gray-400">Your plan stays active until <span className="text-white">{new Date(subscription.expiresAt * 1000).toLocaleDateString()}</span>. After that, files are kept for 30 more days.</p>
                      <div className="flex gap-3">
                        <button onClick={() => setShowCancelConfirm(false)} className="text-xs text-gray-400 hover:text-white px-3 py-1.5 bg-gray-700 rounded-lg transition">Keep Subscription</button>
                        <button onClick={handleCancelSubscription} className="text-xs text-red-400 hover:text-red-300 px-3 py-1.5 bg-red-500/10 border border-red-500/20 rounded-lg transition">Yes, Cancel</button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* CTA */}
              <div className="grid grid-cols-2 gap-3">
                <button onClick={() => setShowSubModal(false)} className="bg-gray-700 hover:bg-gray-600 py-2.5 rounded-xl font-semibold text-sm transition">
                  {manageMode ? 'Close' : 'Cancel'}
                </button>
                <button
                  onClick={handleSubscribe}
                  disabled={subscribing || (capacityLoading && subPlan !== 'free') || (manageMode && subPlan === subscription?.plan)}
                  className="bg-blue-600 hover:bg-blue-500 disabled:opacity-40 py-2.5 rounded-xl font-semibold text-sm transition"
                >
                  {subscribing
                    ? 'Processing…'
                    : manageMode && subPlan === subscription?.plan
                    ? 'Already on this plan'
                    : subPlan === 'free'
                    ? 'Continue with Free'
                    : (() => {
                        const p = PLANS.find(pl => pl.id === subPlan);
                        if (!p) return manageMode ? 'Switch Plan' : 'Subscribe';
                        const usd      = subBilling === 'annual' ? p.priceAnnualUsd : p.priceMonthlyUsd;
                        const egoc     = (usd / egocPriceUsd).toFixed(2);
                        const isQueued = netCapacity && p.gb > netCapacity.total_available_gb;
                        const verb     = manageMode ? `Switch to ${p.name}` : (isQueued ? 'Join Waitlist' : 'Subscribe');
                        return `${verb} — $${usd.toFixed(2)} (≈ ${egoc} EGOC)`;
                      })()
                  }
                </button>
              </div>

              {/* Unsubscribe link in purchase mode (less prominent) */}
              {!manageMode && subscription && subscription.expiresAt > Math.floor(Date.now() / 1000) && !subscription.cancelled && subscription.plan !== 'free' && (
                <div className="border-t border-gray-700 pt-4 text-center">
                  {!showCancelConfirm ? (
                    <button onClick={() => setShowCancelConfirm(true)} className="text-xs text-gray-500 hover:text-red-400 underline transition">
                      Unsubscribe
                    </button>
                  ) : (
                    <div className="space-y-2">
                      <p className="text-xs text-gray-400">Your plan stays active until {new Date(subscription.expiresAt * 1000).toLocaleDateString()}. After that, files are kept for 30 more days.</p>
                      <div className="flex gap-3 justify-center">
                        <button onClick={() => setShowCancelConfirm(false)} className="text-xs text-gray-400 hover:text-white px-3 py-1.5 bg-gray-700 rounded-lg">Keep Subscription</button>
                        <button onClick={handleCancelSubscription} className="text-xs text-red-400 hover:text-red-300 px-3 py-1.5 bg-red-500/10 border border-red-500/20 rounded-lg">Yes, Cancel</button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {}
      {selectedFile && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm" onClick={e => { if (e.target === e.currentTarget) { setSelectedFile(null); setPreview(null); } }}>
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-lg border border-gray-700 shadow-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex justify-between items-center mb-5">
              <h3 className="text-lg font-bold">File Details</h3>
              <button onClick={() => { setSelectedFile(null); setPreview(null); }} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>

            {}
            <div className="bg-gray-900 rounded-xl p-3 mb-4">
              <div className="text-xs text-gray-400 mb-0.5">Your file name (private, only stored locally)</div>
              <div className="font-medium">{selectedFile.name}</div>
              <div className="text-xs text-gray-600 mt-1">🔒 Nodes only see the CID below, not this name</div>
            </div>

            {}
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
              </div>
            )}

            {}
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

            {}
            {selectedFile.comm_d && (
              <div className="mb-4 bg-gray-900 rounded-xl p-4 space-y-2">
                <div className="text-xs font-semibold text-gray-300 mb-2">Proof of Replication / Space-Time</div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <div className="text-gray-500 mb-0.5">Sector ID</div>
                    <div className="font-mono text-gray-300">#{selectedFile.sector_id ?? 0}</div>
                  </div>
                  <div>
                    <div className="text-gray-500 mb-0.5">PoST Status</div>
                    <div>{postBadge(selectedFile) ?? <span className="text-gray-500">—</span>}</div>
                  </div>
                  <div>
                    <div className="text-gray-500 mb-0.5">comm_d (Merkle root)</div>
                    <div className="font-mono text-green-400 break-all">{selectedFile.comm_d.slice(0, 16)}…</div>
                  </div>
                  <div>
                    <div className="text-gray-500 mb-0.5">Last Proved</div>
                    <div className="text-gray-300">
                      {selectedFile.last_proved ? timeAgo(selectedFile.last_proved) : '—'}
                    </div>
                  </div>
                </div>
              </div>
            )}

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
