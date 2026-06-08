import React, { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import { open, save } from '@tauri-apps/api/dialog';
import { open as shellOpen } from '@tauri-apps/api/shell';

interface HardwareProfile {
  cpu_cores: number; cpu_model: string; ram_gb: number;
  gpu_name: string; gpu_vram_gb: number; gpu_count: number;
  has_cuda: boolean; compute_score: number;
}

interface ComputeStatus {
  enabled: boolean; hardware: HardwareProfile | null;
  allocated_cores: number; allocated_ram_gb: number;
  locked_cores: number; locked_ram_gb: number;
  price_per_gpu_hour_uegoc: number; price_per_core_hour_uegoc: number;
  total_jobs_completed: number; earnings_uegoc: number;
  online_nodes: number; address: string;
}
interface ComputeEarnings {
  total_uegoc: number; jobs_completed: number;
  avg_per_job_uegoc: number; last_24h_uegoc: number;
}
interface ComputeCapacityOffer {
  offer_id: string; provider_address: string;
  cpu_cores: number; ram_gb: number; gpu_count: number;
  gpu_vram_gb: number; gpu_name: string;
  price_per_gpu_hour_uegoc: number; price_per_core_hour_uegoc: number;
  min_duration_hours: number; max_duration_hours: number;
  sla_uptime_pct: number; available_from: number;
  status: string; created_at: number; bonded: boolean;
}
interface ComputeReservation {
  reservation_id: string; offer_id: string;
  buyer_address: string; provider_address: string;
  cpu_cores: number; ram_gb: number; gpu_count: number;
  duration_minutes: number; period_minutes: number; period_rate_uegoc: number;
  total_cost_uegoc: number; collateral_uegoc: number; status: string;
  created_at: number; expires_at: number; last_heartbeat_at: number;
  periods_paid: number; breach_count: number; escrow_remaining: number;
  started_at?: number | null;
}
interface ClusterNode {
  provider_address: string; reservation_id: string;
  cpu_cores: number; ram_gb: number; gpu_count: number;
  gpu_vram_gb: number; gpu_name: string;
  wg_pubkey: string; wg_ip: string; endpoint: string;
  is_head: boolean; status: string;
  joined_at: number; last_heartbeat_at: number;
  period_rate_uegoc: number;
}
interface ClusterBooking {
  cluster_id: string; buyer_address: string; name: string;
  subnet: string; nodes: ClusterNode[];
  head_provider_address: string; head_wg_ip: string;
  buyer_wg_pubkey: string;
  total_gpu_count: number; total_cpu_cores: number; total_ram_gb: number;
  total_cost_uegoc: number; status: string;
  created_at: number; expires_at: number; duration_minutes: number;
  framework: string; wg_listen_port: number;
}
interface ClusterConnectInfo {
  cluster_id: string; status: string;
  nodes_active: number; nodes_total: number;
  total_gpus: number; total_cores: number; total_ram_gb: number;
  subnet: string;
  connect: {
    type: string; head_ip: string;
    ray_address?: string; python_snippet?: string;
    head_bootstrap?: string; worker_bootstrap?: string;
    ssh_command: string; note?: string;
  };
}

const u = (egoc: number) => Math.round(egoc * 1_000_000);
const e = (uegoc: number) => uegoc / 1_000_000;
const fmt = (uegoc: number) => e(uegoc).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const fmtAddr = (a: string) => a.length > 14 ? a.slice(0, 8) + '…' + a.slice(-4) : a;

function fmtDuration(mins: number): string {
  if (mins < 60)     return `${mins} min`;
  if (mins < 1440)   return `${mins / 60} hr`;
  if (mins < 10080)  return `${mins / 1440} day${mins / 1440 !== 1 ? 's' : ''}`;
  if (mins < 43200)  return `${Math.round(mins / 10080)} week${Math.round(mins / 10080) !== 1 ? 's' : ''}`;
  if (mins < 525600) return `${Math.round(mins / 43200)} month${Math.round(mins / 43200) !== 1 ? 's' : ''}`;
  return `${Math.round(mins / 525600)} yr`;
}

const DURATION_OPTIONS: { label: string; minutes: number }[] = [
  { label: '30 min',   minutes: 30 },
  { label: '1 hour',   minutes: 60 },
  { label: '6 hours',  minutes: 360 },
  { label: '12 hours', minutes: 720 },
  { label: '1 day',    minutes: 1_440 },
  { label: '3 days',   minutes: 4_320 },
  { label: '1 week',   minutes: 10_080 },
  { label: '1 month',  minutes: 43_200 },
  { label: '3 months', minutes: 129_600 },
  { label: '6 months', minutes: 259_200 },
  { label: '1 year',   minutes: 525_600 },
];

const BOOKING_RANGE_OPTIONS: { label: string; hours: number }[] = [
  { label: '1 hour',   hours: 1 },
  { label: '6 hours',  hours: 6 },
  { label: '12 hours', hours: 12 },
  { label: '1 day',    hours: 24 },
  { label: '3 days',   hours: 72 },
  { label: '1 week',   hours: 168 },
  { label: '1 month',  hours: 720 },
  { label: '3 months', hours: 2_160 },
  { label: '6 months', hours: 4_320 },
  { label: '1 year',   hours: 8_760 },
];

const RES_STATUS: Record<string, { label: string; cls: string }> = {
  active:          { label: 'Active',    cls: 'bg-green-900 text-green-300' },
  terminated:      { label: 'Ended',     cls: 'bg-gray-700 text-gray-400' },
  auto_terminated: { label: 'Ended',     cls: 'bg-gray-700 text-gray-400' },
  breached:        { label: 'Ended',     cls: 'bg-gray-700 text-gray-400' },
  open:            { label: 'Open',      cls: 'bg-blue-900 text-blue-300' },
};

function StatusBadge({ s }: { s: string }) {
  const d = RES_STATUS[s] ?? { label: s, cls: 'bg-gray-700 text-gray-400' };
  return <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${d.cls}`}>{d.label}</span>;
}

function gpuLabel(hw: HardwareProfile | ComputeCapacityOffer | ComputeReservation) {
  const name = 'gpu_name' in hw ? hw.gpu_name : '';
  const vram = 'gpu_vram_gb' in hw ? hw.gpu_vram_gb : 0;
  const cnt  = 'gpu_count' in hw ? hw.gpu_count : 0;
  if (!name || name === 'None' || cnt === 0) return 'CPU only (no GPU)';
  return `${cnt > 1 ? `${cnt}× ` : ''}${name}${vram > 0 ? `, ${vram}GB memory` : ''}`;
}

function hourlyRate(o: ComputeCapacityOffer): number {
  return o.price_per_gpu_hour_uegoc * o.gpu_count + o.price_per_core_hour_uegoc * o.cpu_cores;
}

export default function ComputePage() {
  const [status,   setStatus]   = useState<ComputeStatus | null>(null);
  const [earnings, setEarnings] = useState<ComputeEarnings | null>(null);
  const [hw,       setHw]       = useState<HardwareProfile | null>(null);
  const [loading,  setLoading]  = useState(true);
  const [tab,      setTab]      = useState<'earn' | 'book' | 'cluster'>('earn');

  const [offers,       setOffers]       = useState<ComputeCapacityOffer[]>([]);
  const [reservations, setReservations] = useState<ComputeReservation[]>([]);

  const [enabled,      setEnabled]      = useState(false);
  const [allocCores,   setAllocCores]   = useState(2);
  const [allocRam,     setAllocRam]     = useState(4);
  const [gpuHourEgoc,  setGpuHourEgoc]  = useState(1.00);
  const [coreHourEgoc, setCoreHourEgoc] = useState(0.10);
  const [saving,       setSaving]       = useState(false);
  const [saveMsg,      setSaveMsg]      = useState('');
  const [saveErr,      setSaveErr]      = useState('');
  const [detectingHw,  setDetectingHw]  = useState(false);

  const [offerOpen,         setOfferOpen]         = useState(false);
  const [offerCores,        setOfferCores]        = useState(4);
  const [offerRam,          setOfferRam]          = useState(16);
  const [offerGpuCount,     setOfferGpuCount]     = useState(1);
  const [offerGpuVram,      setOfferGpuVram]      = useState(8);
  const [offerGpuName,      setOfferGpuName]      = useState('');
  const [offerGpuHourEgoc,  setOfferGpuHourEgoc]  = useState(0.50);
  const [offerCoreHourEgoc, setOfferCoreHourEgoc] = useState(0.02);
  const [offerMinHours,     setOfferMinHours]     = useState(1);
  const [offerMaxHours,     setOfferMaxHours]     = useState(8760);
  const [offerBonded,       setOfferBonded]       = useState(true);
  const [offerPosting,      setOfferPosting]      = useState(false);
  const [offerMsg,          setOfferMsg]          = useState('');

  const [bookOpen,         setBookOpen]         = useState<ComputeCapacityOffer | null>(null);
  const [bookDurationMins, setBookDurationMins] = useState(1_440);
  const [booking,          setBooking]          = useState(false);
  const [bookMsg,          setBookMsg]          = useState('');
  const [busyRes,          setBusyRes]          = useState<string | null>(null);
  const [cancellingOffer,  setCancellingOffer]  = useState<string | null>(null);
  const [confirmRemove,    setConfirmRemove]    = useState<string | null>(null);
  const [confirmTermRes,   setConfirmTermRes]   = useState<string | null>(null);
  const [confirmTermEarly, setConfirmTermEarly] = useState<{ id: string, penalty: number } | null>(null);
  const [confirmDeleteHistory, setConfirmDeleteHistory] = useState<string | null>(null);
  const [confirmProvTerm,  setConfirmProvTerm]  = useState<string | null>(null);
  const [confirmTermCluster, setConfirmTermCluster] = useState<string | null>(null);

  const [aiFilter,       setAiFilter]       = useState<string>('All');
  const [terminalOpen,   setTerminalOpen]   = useState(false);

  const [showConsole,    setShowConsole]    = useState<string | null>(null);
  const [consoleCmd,     setConsoleCmd]     = useState('');
  const [consoleOut,     setConsoleOut]     = useState('');
  const [consoleBusy,    setConsoleBusy]    = useState(false);

  const [usageStats, setUsageStats] = useState<{
    cpu: number;
    ram_used_gb: number;
    gpu: number;
    os: string;
    sandboxed: boolean;
  } | null>(null);
  const [usageError, setUsageError] = useState<string | null>(null);

  const [rentalFiles,  setRentalFiles]  = useState<{ name: string; size: number }[]>([]);
  const [fileBusy,     setFileBusy]     = useState(false);
  const [filePreview,  setFilePreview]  = useState<{ name: string; url: string } | null>(null);
  const [appBusy,      setAppBusy]      = useState<string | null>(null);
  const [appImgFile,   setAppImgFile]   = useState('');
  const [appImgWidth,  setAppImgWidth]  = useState(800);
  const [appImgPrompt, setAppImgPrompt] = useState('');
  const [appAudioFile, setAppAudioFile] = useState('');
  const [gpuAppUrl,    setGpuAppUrl]    = useState<{ app: string; url: string; port: number; os: string } | null>(null);
  const [appPollSecs,  setAppPollSecs]  = useState<number | null>(null);

  const [now, setNow] = useState(Math.floor(Date.now() / 1000));
  useEffect(() => {
    const id = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(id);
  }, []);

  const [sshKeyOpen,    setSshKeyOpen]    = useState(false);
  const [sshKeyText,    setSshKeyText]    = useState('');
  const [sshKeyLoading, setSshKeyLoading] = useState(false);
  const [sshKeyCopied,  setSshKeyCopied]  = useState(false);

  const [clusters,            setClusters]            = useState<ClusterBooking[]>([]);
  const [clusterOpen,         setClusterOpen]         = useState(false);
  const [clusterName,         setClusterName]         = useState('');
  const [clusterGpuCount,     setClusterGpuCount]     = useState(4);
  const [clusterMinVram,      setClusterMinVram]       = useState(8);
  const [clusterCpuCores,     setClusterCpuCores]     = useState(4);
  const [clusterRamGb,        setClusterRamGb]        = useState(16);
  const [clusterDurationMins, setClusterDurationMins] = useState(1_440);
  const [clusterFramework,    setClusterFramework]    = useState<'ray' | 'ssh'>('ray');
  const [clusterBusy,         setClusterBusy]         = useState(false);
  const [clusterMsg,          setClusterMsg]          = useState('');
  const [connectInfo,         setConnectInfo]         = useState<ClusterConnectInfo | null>(null);
  const [wgConfigText,        setWgConfigText]        = useState('');
  const [wgConfigOpen,        setWgConfigOpen]        = useState(false);
  const [clusterHeartbeatId,  setClusterHeartbeatId]  = useState<string | null>(null);
  const [terminatingCluster,  setTerminatingCluster]  = useState<string | null>(null);
  const [selectedWorkspace,   setSelectedWorkspace]   = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [s, ea, of_, rv, cl] = await Promise.all([
        invoke<ComputeStatus>('get_compute_status'),
        invoke<ComputeEarnings>('get_compute_earnings'),
        invoke<ComputeCapacityOffer[]>('get_capacity_offers'),
        invoke<ComputeReservation[]>('get_reservations'),
        invoke<ClusterBooking[]>('get_cluster_bookings'),
      ]);
      setStatus(s); setEarnings(ea);
      setOffers(of_); setReservations(rv); setClusters(cl);
      setEnabled(s.enabled);
      setAllocCores(s.allocated_cores || 2);
      setAllocRam(s.allocated_ram_gb || 4);
      setGpuHourEgoc(e(s.price_per_gpu_hour_uegoc) || 1.00);
      setCoreHourEgoc(e(s.price_per_core_hour_uegoc) || 0.10);
      if (s.hardware) setHw(s.hardware);
    } catch {}
    finally { setLoading(false); }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 15_000);
    return () => clearInterval(t);
  }, [load]);

  useEffect(() => {
    const unlisten = listen('ego://reservation-terminated', () => {
      load();
    });
    return () => { unlisten.then(f => f()); };
  }, [load]);

  async function detectHw() {
    setDetectingHw(true);
    try {
      const h = await invoke<HardwareProfile>('detect_hardware');
      setHw(h);
      setAllocCores(Math.max(1, Math.floor(h.cpu_cores / 2)));
      setAllocRam(Math.max(1, Math.floor(h.ram_gb / 2)));
      if (h.gpu_name && h.gpu_name !== 'None') {
        setOfferGpuName(h.gpu_name);
        setOfferGpuVram(h.gpu_vram_gb);
        setOfferGpuCount(h.gpu_count);
      }
      setOfferCores(Math.max(1, Math.floor(h.cpu_cores / 2)));
      setOfferRam(Math.max(1, Math.floor(h.ram_gb / 2)));
    } catch {}
    setDetectingHw(false);
  }

  async function saveSettings() {
    setSaving(true); setSaveMsg(''); setSaveErr('');
    try {
      await invoke('configure_compute_node', {
        enabled, allocatedCores: allocCores, allocatedRamGb: allocRam,
        pricePerGpuHourUegoc: u(gpuHourEgoc),
        pricePerCoreHourUegoc: u(coreHourEgoc),
      });
      setSaveMsg('Saved!');
      await load();
    } catch (err: any) { setSaveErr(String(err)); }
    setSaving(false);
  }

  async function postOffer() {
    setOfferPosting(true); setOfferMsg('');
    try {
      await invoke<string>('post_capacity_offer', {
        cpuCores: offerCores, ramGb: offerRam,
        gpuCount: offerGpuCount, gpuVramGb: offerGpuVram, gpuName: offerGpuName,
        pricePerGpuHourUegoc:  u(offerGpuHourEgoc),
        pricePerCoreHourUegoc: u(offerCoreHourEgoc),
        minDurationHours: offerMinHours,
        maxDurationHours: offerMaxHours,
        slaUptimePct: 99, bonded: offerBonded,
      });
      setOfferOpen(false);
      await load();
    } catch (err: any) { setOfferMsg(String(err)); }
    setOfferPosting(false);
  }

  async function bookReservation() {
    if (!bookOpen) return;
    setBooking(true); setBookMsg('');
    try {
      await invoke<string>('book_reservation', { offerId: bookOpen.offer_id, durationMinutes: bookDurationMins });
      setBookOpen(null);
      await load();
    } catch (err: any) { setBookMsg(String(err)); }
    setBooking(false);
  }

  async function confirmCancelOffer() {
    if (!confirmRemove) return;
    const offerId = confirmRemove;
    setConfirmRemove(null);
    setCancellingOffer(offerId);
    try { await invoke('cancel_capacity_offer', { offerId }); await load(); }
    catch (err: any) { alert(String(err)); }
    setCancellingOffer(null);
  }

  async function sendHeartbeat(reservationId: string) {
    setBusyRes(reservationId);
    try { await invoke('send_reservation_heartbeat', { reservationId }); await load(); }
    catch (err: any) { alert(String(err)); }
    setBusyRes(null);
  }

  async function executeProviderTerminate() {
    if (!confirmProvTerm) return;
    const id = confirmProvTerm;
    setConfirmProvTerm(null);
    setBusyRes(id);
    try {
      await invoke('provider_terminate_reservation', { reservationId: id });
      await load();
    } catch (err: any) { alert(String(err)); }
    setBusyRes(null);
  }

  async function executeTerminateReservation() {
    if (!confirmTermRes) return;
    const id = confirmTermRes;
    setConfirmTermRes(null);
    setBusyRes(id);
    try { await invoke('terminate_reservation', { reservationId: id }); await load(); }
    catch (err: any) { alert(String(err)); }
    setBusyRes(null);
  }

  async function executeDeleteHistoryItem() {
    if (!confirmDeleteHistory) return;
    const id = confirmDeleteHistory;
    setConfirmDeleteHistory(null);
    setBusyRes(id);
    try {
      await invoke('delete_reservation_history_item', { reservationId: id });
      await load();
    } catch (err: any) { alert(String(err)); }
    setBusyRes(null);
  }

  function getLiveCost(r: ComputeReservation) {
    if (!r.started_at) return 0;
    const elapsed = Math.max(0, now - r.started_at);
    const periodSecs = Math.max(1, r.period_minutes * 60);
    const ratePerSec = r.period_rate_uegoc / periodSecs;
    return Math.min(r.total_cost_uegoc, Math.floor(elapsed * ratePerSec));
  }

  const refreshLiveUsage = useCallback(async (resId: string) => {
    try {
      const stats = await invoke<any>('get_remote_usage', { reservationId: resId });
      if (stats && typeof stats.cpu === 'number') {
        setUsageStats({
          cpu: Math.round(stats.cpu),
          ram_used_gb: stats.ram_used_gb,
          gpu: stats.gpu,
          os: typeof stats.os === 'string' ? stats.os : '',
          sandboxed: !!stats.sandboxed
        });
        setUsageError(null);
      } else {
        setUsageError('Provider returned unexpected payload');
      }
    } catch (e) {
      const msg = String(e);
      const trimmed = msg.length > 120 ? msg.slice(0, 117) + '…' : msg;
      setUsageError(trimmed);
      console.error("Usage poll failed", e);
    }
  }, []);

  useEffect(() => {
    let interval: any;
    if (showConsole) {
      refreshLiveUsage(showConsole);
      interval = setInterval(() => refreshLiveUsage(showConsole), 1000);
    } else {
      setUsageStats(null);
      setUsageError(null);
    }
    return () => clearInterval(interval);
  }, [showConsole, refreshLiveUsage]);

  async function refreshConnection() {
    if (!showConsole) return;
    try { await invoke('compute_node_heartbeat'); }
    catch (err) { alert(String(err)); }
  }

  async function executeRemoteCommand(customCmd?: string, label?: string) {
    const cmd = (customCmd || consoleCmd).trim();
    if (!showConsole || !cmd) return;
    const id = showConsole;
    setConsoleBusy(true);
    try {
      const res = await invoke<string>('run_remote_command', { reservationId: id, command: cmd });
      const displayTag = label ? `\n--- EXECUTE: ${label.toUpperCase()} ---\n` : `\n> ${cmd}\n`;
      setConsoleOut(prev => prev + `${displayTag}${res}\n`);
      if (!customCmd) setConsoleCmd('');
    } catch (err: any) {
      const displayTag = label ? `\n--- FAILED: ${label.toUpperCase()} ---\n` : `\n> ${cmd}\n`;
      setConsoleOut(prev => prev + `${displayTag}Error: ${String(err)}\n`);
    }
    setConsoleBusy(false);
  }

  async function executeRemoteIntent(kind: 'SPECS' | 'BENCH', label: string) {
    if (!showConsole) return;
    const id = showConsole;
    setConsoleBusy(true);
    try {
      const res = await invoke<string>('run_remote_intent', { reservationId: id, kind });
      setConsoleOut(prev => prev + `\n--- ${label.toUpperCase()} ---\n${res}\n`);
    } catch (err: any) {
      setConsoleOut(prev => prev + `\n--- FAILED: ${label.toUpperCase()} ---\nError: ${String(err)}\n`);
    }
    setConsoleBusy(false);
  }

  const refreshFiles = useCallback(async () => {
    if (!showConsole) return;
    try {
      const f = await invoke<{ name: string; size: number }[]>('list_rental_files', { reservationId: showConsole });
      setRentalFiles(f);
    } catch (e) {
      setConsoleOut(prev => prev + `\n[files] ${String(e)}\n`);
    }
  }, [showConsole]);

  useEffect(() => {
    if (showConsole) {
      refreshFiles();
    } else {
      setRentalFiles([]); setFilePreview(null); setAppImgFile(''); setAppImgPrompt(''); setAppAudioFile(''); setGpuAppUrl(null); setAppPollSecs(null);
    }
  }, [showConsole, refreshFiles]);

  const isImage = (n: string) => /\.(png|jpe?g|gif|webp|bmp)$/i.test(n);
  const fmtBytes = (b: number) => b < 1024 ? `${b} B` : b < 1_048_576 ? `${(b / 1024).toFixed(1)} KB` : `${(b / 1_048_576).toFixed(1)} MB`;

  async function uploadFile() {
    if (!showConsole) return;
    try {
      const sel = await open({ multiple: false, title: 'Select a file to upload to your rental' });
      if (sel && typeof sel === 'string') {
        setFileBusy(true);
        const name = await invoke<string>('upload_to_rental', { reservationId: showConsole, localPath: sel });
        setConsoleOut(prev => prev + `\n[uploaded] ${name}\n`);
        await refreshFiles();
      }
    } catch (e) { setConsoleOut(prev => prev + `\n[upload failed] ${String(e)}\n`); }
    setFileBusy(false);
  }

  async function downloadFile(name: string) {
    if (!showConsole) return;
    try {
      const dest = await save({ defaultPath: name });
      if (dest) {
        setFileBusy(true);
        await invoke('download_from_rental', { reservationId: showConsole, fileName: name, savePath: dest });
        setConsoleOut(prev => prev + `\n[downloaded] ${name} → ${dest}\n`);
      }
    } catch (e) { setConsoleOut(prev => prev + `\n[download failed] ${String(e)}\n`); }
    setFileBusy(false);
  }

  async function previewFile(name: string) {
    if (!showConsole) return;
    try {
      const b64 = await invoke<string>('get_rental_file_b64', { reservationId: showConsole, fileName: name });
      const ext = name.split('.').pop()?.toLowerCase() || '';
      const mime = ext === 'png' ? 'image/png'
        : (ext === 'jpg' || ext === 'jpeg') ? 'image/jpeg'
        : ext === 'gif' ? 'image/gif'
        : ext === 'webp' ? 'image/webp' : 'application/octet-stream';
      setFilePreview({ name, url: `data:${mime};base64,${b64}` });
    } catch (e) { setConsoleOut(prev => prev + `\n[preview failed] ${String(e)}\n`); }
  }

  async function runImageResize() {
    if (!showConsole || !appImgFile) return;
    const id = showConsole;
    const inName = appImgFile;
    const w = Math.max(1, Math.floor(appImgWidth));
    const outName = `resized_${w}_${inName}`;
    setAppBusy('image-resize');
    const cmd =
      `pip install -q pillow >/dev/null 2>&1; ` +
      `python -c "from PIL import Image; im=Image.open('${inName}'); ` +
      `ratio=${w}/im.width; im=im.resize((${w}, max(1,int(im.height*ratio)))); ` +
      `im.save('${outName}'); print('Saved ${outName}', im.size)"`;
    try {
      const res = await invoke<string>('run_remote_command', { reservationId: id, command: cmd });
      setConsoleOut(prev => prev + `\n--- IMAGE RESIZE ---\n${res}\n`);
      await refreshFiles();
      await previewFile(outName);
    } catch (e) {
      setConsoleOut(prev => prev + `\n--- FAILED: IMAGE RESIZE ---\nError: ${String(e)}\n`);
    }
    setAppBusy(null);
  }

  const APP_PORTS: Record<string, number> = { llm: 8000, sdxl: 7860, jupyter: 8888 };
  const APP_HINTS: Record<string, string> = {
    llm:     'Installing packages + downloading TinyLlama (~640 MB). First run: 5-10 min. Click "View logs" to watch progress.',
    sdxl:    'Installing packages + downloading Stable Diffusion (~2 GB). First run: 15-20 min. Click "View logs" to watch.',
    jupyter: 'Installing JupyterLab in background. Ready in ~2-4 min. Click "View logs" to watch.',
  };

  async function openWebApp(app: string, label: string) {
    if (!showConsole) return;
    const id = showConsole;
    setAppBusy(app);
    setGpuAppUrl(null);
    setAppPollSecs(null);
    setConsoleOut(prev => prev + `\n--- ${label.toUpperCase()}: packages installing… ---\n`);
    try {
      const providerOs = usageStats?.os ?? 'linux';
      const info = await invoke<{ container_port: number; path: string; startup_log?: string }>('launch_web_app', { reservationId: id, app, os: providerOs });
      const hostPort = await invoke<string>('open_rental_app', { reservationId: id, containerPort: info.container_port });
      const url = `http://${hostPort}${info.path}`;
      setGpuAppUrl({ app, url, port: info.container_port, os: providerOs });
      const log = (info.startup_log ?? '').trim();
      const crashed = log.includes('[CRASHED]') || log.includes('[ERROR]');
      setConsoleOut(prev => prev +
        (log ? `${log}\n` : '') +
        (crashed ? '' : `Tunnel: ${url}\n${APP_HINTS[app] ?? 'Starting…'}\nAuto-checking every 20 s — will open automatically when ready.\n`)
      );
      if (!crashed) setAppPollSecs(20);
    } catch (e) {
      setConsoleOut(prev => prev + `--- FAILED: ${label.toUpperCase()} ---\nError: ${String(e)}\n`);
    }
    setAppBusy(null);
  }

  useEffect(() => {
    if (appPollSecs === null || !showConsole || !gpuAppUrl) return;
    if (appPollSecs > 0) {
      const t = setTimeout(() => setAppPollSecs(s => (s ?? 1) - 1), 1000);
      return () => clearTimeout(t);
    }
    const { port, os, url } = gpuAppUrl;
    const win = os.toLowerCase().includes('win');
    const checkCmd = win
      ? `try { $t = New-Object System.Net.Sockets.TcpClient('127.0.0.1', ${port}); $t.Close(); Write-Output 'ready' } catch { Write-Output 'not_ready' }`
      : `timeout 1 bash -c 'echo "" >/dev/tcp/127.0.0.1/${port}' 2>/dev/null && echo ready || echo not_ready`;
    invoke<string>('run_remote_command', { reservationId: showConsole, command: checkCmd })
      .then(result => {
        if (result.trim() === 'ready') {
          setAppPollSecs(null);
          setConsoleOut(prev => prev + `[✓] Server ready — opening browser\n`);
          shellOpen(url);
        } else {
          setAppPollSecs(20);
        }
      })
      .catch(() => setAppPollSecs(20));
  }, [appPollSecs, showConsole, gpuAppUrl]);

  async function checkAndOpenApp(app: string) {
    if (!showConsole || !gpuAppUrl) return;
    const { port, os, url } = gpuAppUrl;
    const win = os.toLowerCase().includes('win');
    const checkCmd = win
      ? `try { $t = New-Object System.Net.Sockets.TcpClient('127.0.0.1', ${port}); $t.Close(); Write-Output 'ready' } catch { Write-Output 'not_ready' }`
      : `timeout 1 bash -c 'echo "" >/dev/tcp/127.0.0.1/${port}' 2>/dev/null && echo ready || echo not_ready`;
    setAppBusy(app + '_check');
    try {
      const result = await invoke<string>('run_remote_command', { reservationId: showConsole, command: checkCmd });
      if (result.trim() === 'ready') {
        setAppPollSecs(null);
        await shellOpen(url);
      } else {
        setConsoleOut(prev => prev + `[not ready yet] Still loading — auto-check resumes in 20 s\n`);
        setAppPollSecs(20);
      }
    } catch (e) {
      setConsoleOut(prev => prev + `[check failed] ${String(e)}\n`);
      setAppPollSecs(20);
    }
    setAppBusy(null);
  }

  async function transcribeAudio() {
    if (!showConsole || !appAudioFile) return;
    const id = showConsole;
    const fname = appAudioFile;
    const outName = fname + '.txt';
    setAppBusy('transcribe');
    const win = (gpuAppUrl?.os ?? usageStats?.os ?? '').toLowerCase().includes('win');
    const pyBin = win ? 'python' : 'python3';
    const wsSep = win ? '; ' : '; ';
    const wsPath = win ? `os.path.join(os.environ.get('TEMP','C:\\\\Temp'),'ego')` : `'/workspace'`;
    const install = win
      ? `pip install -q openai-whisper 2>$null`
      : `pip install -q openai-whisper >/dev/null 2>&1`;
    const cmd = win
      ? `${install}; ${pyBin} -c "import whisper,os; ws=os.path.join(os.environ.get('TEMP','C:\\\\Temp'),'ego'); m=whisper.load_model('base'); r=m.transcribe(os.path.join(ws,'${fname}')); t=r['text']; open(os.path.join(ws,'${outName}'),'w').write(t); print('TRANSCRIPT:',t)"`
      : `${install}; ${pyBin} -c "import whisper; m=whisper.load_model('base'); r=m.transcribe('/workspace/${fname}'); t=r['text']; open('/workspace/${outName}','w').write(t); print('TRANSCRIPT:',t)"`;
    try {
      const res = await invoke<string>('run_remote_command', { reservationId: id, command: cmd });
      setConsoleOut(prev => prev + `\n--- WHISPER TRANSCRIPTION ---\n${res}\n`);
      await refreshFiles();
    } catch (e) {
      setConsoleOut(prev => prev + `\n--- FAILED: TRANSCRIPTION ---\nError: ${String(e)}\n`);
    }
    setAppBusy(null);
  }

  async function executeTerminateEarly() {
    if (!confirmTermEarly) return;
    const { id } = confirmTermEarly;
    setConfirmTermEarly(null);
    setBusyRes(id);
    try { await invoke('terminate_reservation_early', { reservationId: id }); await load(); }
    catch (err: any) { alert(String(err)); }
    setBusyRes(null);
  }

  async function createCluster() {
    setClusterBusy(true); setClusterMsg('');
    try {
      await invoke<ClusterBooking>('create_cluster_booking', {
        gpuCount: clusterGpuCount, minGpuVramGb: clusterMinVram,
        cpuCores: clusterCpuCores, ramGb: clusterRamGb,
        durationMinutes: clusterDurationMins,
        framework: clusterFramework, name: clusterName,
      });
      setClusterOpen(false);
      await load();
    } catch (err: any) { setClusterMsg(String(err)); }
    setClusterBusy(false);
  }

  async function showConnectInfo(clusterId: string) {
    try {
      const info = await invoke<ClusterConnectInfo>('get_cluster_connect_info', { clusterId });
      setConnectInfo(info);
    } catch (err: any) { alert(String(err)); }
  }

  async function downloadBuyerWgConfig(clusterId: string) {
    try {
      const cfg = await invoke<string>('get_cluster_wg_config', { clusterId });
      setWgConfigText(cfg); setWgConfigOpen(true);
    } catch (err: any) { alert(String(err)); }
  }

  async function downloadNodeWgConfig(clusterId: string) {
    try {
      const cfg = await invoke<string>('get_node_wg_config', { clusterId });
      setWgConfigText(cfg); setWgConfigOpen(true);
    } catch (err: any) { alert(String(err)); }
  }

  async function executeTerminateCluster() {
    if (!confirmTermCluster) return;
    const id = confirmTermCluster;
    setConfirmTermCluster(null);
    setTerminatingCluster(id);
    try { await invoke('terminate_cluster', { clusterId: id }); await load(); }
    catch (err: any) { alert(String(err)); }
    setTerminatingCluster(null);
  }

  async function sendClusterHeartbeat(clusterId: string) {
    setClusterHeartbeatId(clusterId);
    try { await invoke('send_cluster_node_heartbeat', { clusterId }); await load(); }
    catch (err: any) { alert(String(err)); }
    setClusterHeartbeatId(null);
  }

  async function openSshKey() {
    setSshKeyOpen(true);
    setSshKeyLoading(true);
    try {
      const key = await invoke<string>('get_or_create_ssh_key');
      setSshKeyText(key);
    } catch (err: any) { alert(String(err)); }
    finally { setSshKeyLoading(false); }
  }

  function aiSuitability(o: ComputeCapacityOffer): string[] {
    if (o.gpu_count === 0) return ['Embeddings', 'Transcription', 'CPU Inference'];
    if (o.gpu_vram_gb >= 24) return ['LLM 70B+', 'Fine-tuning', 'Image Gen'];
    if (o.gpu_vram_gb >= 16) return ['LLM 13B', 'Fine-tuning', 'Image Gen'];
    if (o.gpu_vram_gb >= 8)  return ['LLM 7B', 'Image Gen', 'Embeddings'];
    if (o.gpu_vram_gb >= 4)  return ['LLM Chat', 'Image Gen', 'Embeddings'];
    return ['Embeddings', 'Image Gen'];
  }

  function matchesAiFilter(o: ComputeCapacityOffer): boolean {
    if (aiFilter === 'All') return true;
    const tags = aiSuitability(o);
    if (aiFilter === 'LLM')       return tags.some(t => t.startsWith('LLM'));
    if (aiFilter === 'Image Gen') return tags.includes('Image Gen');
    if (aiFilter === 'Fine-tune') return tags.includes('Fine-tuning');
    if (aiFilter === 'Embeddings') return tags.includes('Embeddings');
    return true;
  }

  async function openLocalFileToWorkspace() {
    if (!showConsole) return;
    try {
      const sel = await open({ multiple: false, title: 'Add a file — it will be sent to your remote GPU' });
      if (sel && typeof sel === 'string') {
        setFileBusy(true);
        const name = await invoke<string>('upload_to_rental', { reservationId: showConsole, localPath: sel });
        setConsoleOut(prev => prev + `[uploaded] ${name}\n`);
        await refreshFiles();
        const ext = name.split('.').pop()?.toLowerCase() ?? '';
        if (['mp3','wav','m4a','ogg','flac','webm'].includes(ext)) setAppAudioFile(name);
        else if (['png','jpg','jpeg','gif','webp'].includes(ext))   setAppImgFile(name);
      }
    } catch (e) { setConsoleOut(prev => prev + `[upload failed] ${String(e)}\n`); }
    setFileBusy(false);
  }

  async function pickAudioFile() {
    if (!showConsole) return;
    try {
      const sel = await open({
        multiple: false,
        title: 'Select an audio file',
        filters: [{ name: 'Audio', extensions: ['mp3','wav','m4a','ogg','flac','webm'] }],
      });
      if (sel && typeof sel === 'string') {
        setFileBusy(true);
        const name = await invoke<string>('upload_to_rental', { reservationId: showConsole, localPath: sel });
        setConsoleOut(prev => prev + `[uploaded] ${name}\n`);
        await refreshFiles();
        setAppAudioFile(name);
      }
    } catch (e) { setConsoleOut(prev => prev + `[upload failed] ${String(e)}\n`); }
    setFileBusy(false);
  }

  async function uploadFolder() {
    if (!showConsole) return;
    try {
      const dir = await open({ directory: true, title: 'Add a folder — all files will be sent to your remote GPU' });
      if (dir && typeof dir === 'string') {
        setFileBusy(true);
        const count = await invoke<number>('upload_folder_to_rental', { reservationId: showConsole, localFolder: dir });
        setConsoleOut(prev => prev + `[uploaded folder] ${count} file(s)\n`);
        await refreshFiles();
      }
    } catch (e) { setConsoleOut(prev => prev + `[folder upload failed] ${String(e)}\n`); }
    setFileBusy(false);
  }

  if (loading) return <div className="flex items-center justify-center h-64 text-gray-400">Loading…</div>;

  const myAddr           = status?.address ?? '';
  const activeResCount   = reservations.filter(r => r.status === 'active').length;
  const myClusterCount   = clusters.filter(c => c.buyer_address === myAddr && c.status !== 'terminated').length;

  return (
    <div className="p-6 space-y-5 max-w-4xl mx-auto">

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">AI Compute</h1>
          <p className="text-gray-400 text-sm mt-0.5">
            Rent a GPU for AI — run LLMs, generate images, fine-tune models · Earn by sharing your hardware
          </p>
        </div>
      </div>

      {/* Quick earnings strip */}
      {earnings && (earnings.total_uegoc > 0 || earnings.jobs_completed > 0) && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { label: 'Total earned',  value: `${fmt(earnings.total_uegoc)} EGOC` },
            { label: 'Jobs done',     value: String(earnings.jobs_completed) },
            { label: 'Avg per job',   value: `${fmt(earnings.avg_per_job_uegoc)} EGOC` },
            { label: 'Last 24 hours', value: `${fmt(earnings.last_24h_uegoc)} EGOC` },
          ].map(({ label, value }) => (
            <div key={label} className="bg-gray-800 rounded-xl p-4 border border-gray-700">
              <p className="text-gray-400 text-xs">{label}</p>
              <p className="text-white font-bold text-sm mt-1">{value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-700 flex-wrap">
        {([
          { id: 'earn',    label: 'Earn' },
          { id: 'book',    label: `Run AI${activeResCount > 0 ? ` (${activeResCount})` : ''}` },
          { id: 'cluster', label: `Train${myClusterCount > 0 ? ` (${myClusterCount})` : ''}` },
        ] as const).map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${tab === t.id ? 'bg-purple-600 text-white' : 'text-gray-400 hover:text-white'}`}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ── EARN tab ── */}
      {tab === 'earn' && (
        <div className="space-y-4">

          <div className="bg-gray-800 rounded-xl border border-gray-700 p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-white font-semibold text-lg">Earn from your Hardware</h2>
                <p className="text-gray-400 text-xs mt-0.5">List your CPU, GPU, or RAM on the marketplace to earn EGOC per hour.</p>
              </div>
              <div className="flex gap-2">
                <button onClick={detectHw} disabled={detectingHw}
                  className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-300 text-sm rounded-lg font-medium transition-all disabled:opacity-50">
                  {detectingHw ? 'Scanning…' : 'Detect Hardware'}
                </button>
                <button onClick={() => setOfferOpen(true)}
                  className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white text-sm rounded-lg font-medium whitespace-nowrap shadow-lg transition-transform active:scale-95">
                  + List My Hardware
                </button>
              </div>
            </div>

            {hw && (
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div className="bg-gray-750 border border-gray-700 rounded-xl p-3">
                  <p className="text-gray-400 text-[10px] uppercase font-bold tracking-wider">Processor</p>
                  <p className="text-white font-medium">{hw.cpu_model}</p>
                  <p className="text-gray-500 text-xs mt-0.5">{hw.cpu_cores} cores · {hw.ram_gb}GB RAM</p>
                </div>
                <div className="bg-gray-750 border border-gray-700 rounded-xl p-3">
                  <p className="text-gray-400 text-[10px] uppercase font-bold tracking-wider">Graphics</p>
                  <p className="text-white font-medium">{gpuLabel(hw)}</p>
                  {hw.has_cuda && <p className="text-green-400 text-[10px] mt-0.5 font-bold">✓ CUDA ACCELERATION ACTIVE</p>}
                </div>
              </div>
            )}

            <div className="bg-blue-900/10 border border-blue-700/30 rounded-xl px-4 py-3 text-xs text-blue-300">
              Renting is simple: list your available capacity, set your price, and get paid automatically in EGOC. 
              <strong> Keep the app open to remain listed.</strong>
            </div>

            {offers.filter(o => o.provider_address === myAddr).length === 0 ? (
              <div className="border-2 border-dashed border-gray-600 rounded-xl p-6 text-center space-y-2">
                <p className="text-gray-400 text-sm">You haven't listed any hardware yet.</p>
                <p className="text-gray-500 text-xs">Click "List My Hardware" to start earning from rentals.</p>
              </div>
            ) : (
              <div className="space-y-2">
                {offers.filter(o => o.provider_address === myAddr).map(o => {
                  const rate = hourlyRate(o);
                  return (
                    <div key={o.offer_id} className="bg-gray-750 border border-gray-600 rounded-lg p-3 space-y-1">
                      <div className="flex items-center justify-between gap-3">
                        <div className="space-y-0.5 flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <p className="text-white text-sm font-medium">{gpuLabel(o)}</p>
                            <span className="text-xs text-gray-400">· {o.cpu_cores} cores · {o.ram_gb}GB RAM</span>
                            {o.bonded
                              ? <span className="text-xs bg-green-900 text-green-300 px-2 py-0.5 rounded-full">✓ Protected</span>
                              : <span className="text-xs bg-orange-900 text-orange-300 px-2 py-0.5 rounded-full">Basic</span>}
                            <StatusBadge s={o.status} />
                          </div>
                          <p className="text-yellow-400 text-sm font-semibold">{fmt(rate)} EGOC/hr</p>
                          <p className="text-gray-500 text-xs">
                            {fmtDuration(o.min_duration_hours * 60)}–{fmtDuration(o.max_duration_hours * 60)} bookings
                          </p>
                        </div>
                        {o.status === 'open' && (
                          <button onClick={() => setConfirmRemove(o.offer_id)}
                            disabled={cancellingOffer === o.offer_id}
                            className="shrink-0 px-3 py-1.5 bg-gray-700 hover:bg-red-900 text-gray-400 hover:text-red-300 text-xs rounded-lg transition-colors disabled:opacity-50">
                            {cancellingOffer === o.offer_id ? 'Removing…' : 'Remove'}
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* My active bookings as provider */}
          {reservations.filter(r => r.provider_address === myAddr && r.status === 'active').length > 0 && (
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-5 space-y-3">
              <h2 className="text-white font-semibold">Active rentals — claim your payment</h2>
              <p className="text-gray-400 text-xs">Send a check-in each period to receive your payment from escrow.</p>
              {reservations.filter(r => r.provider_address === myAddr && r.status === 'active').map(r => {
                const totalPeriods = r.period_minutes > 0 ? Math.round(r.duration_minutes / r.period_minutes) : 1;
                const earned = r.period_rate_uegoc * r.periods_paid;
                return (
                  <div key={r.reservation_id} className="bg-gray-750 border border-gray-600 rounded-lg p-3 space-y-2">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-white text-sm font-medium">{gpuLabel(r)} · {r.cpu_cores} cores</p>
                        <p className="text-gray-400 text-xs">
                          Period {r.periods_paid}/{totalPeriods} · {fmt(r.period_rate_uegoc)} EGOC/{fmtDuration(r.period_minutes)}
                        </p>
                      </div>
                      <p className="text-yellow-400 font-bold">{fmt(earned)} EGOC earned</p>
                    </div>
                    {r.breach_count > 0 && (
                      <p className="text-red-400 text-xs">⚠ {r.breach_count} missed period{r.breach_count > 1 ? 's' : ''} detected</p>
                    )}
                    <div className="flex gap-2">
                      <button onClick={() => sendHeartbeat(r.reservation_id)}
                        disabled={busyRes === r.reservation_id}
                        className="flex-1 py-1.5 bg-green-700 hover:bg-green-600 text-white text-xs rounded-lg disabled:opacity-60 font-medium">
                        {busyRes === r.reservation_id ? 'Sending…' : 'Check-In & Claim'}
                      </button>
                      <button onClick={() => setConfirmProvTerm(r.reservation_id)}
                        disabled={busyRes === r.reservation_id}
                        className="px-3 py-1.5 bg-gray-700 hover:bg-red-900/40 text-gray-400 hover:text-red-100 text-xs rounded-lg transition-all border border-gray-600">
                        Stop
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {clusters.filter(c => c.nodes.some(n => n.provider_address === myAddr)).length > 0 && (
            <div className="bg-gray-800 rounded-xl border border-gray-700 p-5 space-y-3">
              <h2 className="text-white font-semibold">Clusters I'm a node in</h2>
              <p className="text-gray-400 text-xs">Your hardware was auto-joined to these clusters. Send a heartbeat each period to claim payment.</p>
              {clusters.filter(c => c.nodes.some(n => n.provider_address === myAddr)).map(c => {
                const myNode = c.nodes.find(n => n.provider_address === myAddr)!;
                return (
                  <div key={c.cluster_id} className="bg-gray-750 border border-gray-600 rounded-lg p-3 space-y-2">
                    <div className="flex items-center justify-between gap-3">
                      <div className="flex-1 min-w-0 space-y-0.5">
                        <div className="flex items-center gap-2 flex-wrap">
                          <p className="text-white text-sm font-medium truncate">{c.name || c.cluster_id.slice(0, 8)}</p>
                          {myNode.is_head && <span className="text-xs bg-cyan-900 text-cyan-300 px-2 py-0.5 rounded-full shrink-0">Head</span>}
                        </div>
                        <p className="text-gray-400 text-xs">My IP: {myNode.wg_ip} · {myNode.gpu_count}× GPU · {myNode.cpu_cores} cores · {myNode.ram_gb}GB RAM</p>
                        <p className="text-gray-500 text-xs">{c.framework.toUpperCase()} cluster · {fmtDuration(c.duration_minutes)} total</p>
                      </div>
                      <p className="text-yellow-400 text-sm font-bold shrink-0">{fmt(myNode.period_rate_uegoc)} EGOC/period</p>
                    </div>
                    <div className="flex gap-2">
                      <button onClick={() => downloadNodeWgConfig(c.cluster_id)}
                        className="flex-1 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-300 text-xs rounded-lg">
                        WireGuard Config
                      </button>
                      <button onClick={() => sendClusterHeartbeat(c.cluster_id)}
                        disabled={clusterHeartbeatId === c.cluster_id}
                        className="flex-1 py-1.5 bg-green-700 hover:bg-green-600 text-white text-xs rounded-lg disabled:opacity-60">
                        {clusterHeartbeatId === c.cluster_id ? 'Sending…' : 'Heartbeat & Claim'}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

        </div>
      )}

      {/* ── BOOK CAPACITY tab ── */}
      {tab === 'book' && (
        <div className="space-y-4">

          <div className="bg-gradient-to-br from-purple-900/30 to-blue-900/20 border border-purple-700/30 rounded-xl p-4 space-y-2">
            <p className="text-white font-semibold text-sm">Run AI on a rented GPU</p>
            <p className="text-gray-300 text-xs leading-relaxed">Pick a GPU, rent it, and launch apps that open in your browser. <strong className="text-white">The heavy compute runs remotely</strong> — your computer is just the screen. Use it for LLM chat, image generation, fine-tuning, or any Python workload.</p>
            <div className="flex gap-2 flex-wrap pt-1 text-[10px]">
              <span className="bg-purple-900/40 text-purple-300 px-2 py-0.5 rounded-full border border-purple-700/30">🤖 LLM inference</span>
              <span className="bg-pink-900/40 text-pink-300 px-2 py-0.5 rounded-full border border-pink-700/30">🎨 Image generation</span>
              <span className="bg-blue-900/40 text-blue-300 px-2 py-0.5 rounded-full border border-blue-700/30">🧬 Fine-tuning</span>
              <span className="bg-teal-900/40 text-teal-300 px-2 py-0.5 rounded-full border border-teal-700/30">🔢 Embeddings</span>
              <span className="bg-orange-900/40 text-orange-300 px-2 py-0.5 rounded-full border border-orange-700/30">🎤 Transcription</span>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-gray-500 text-xs font-bold uppercase tracking-widest">Filter:</span>
            {(['All', 'LLM', 'Image Gen', 'Fine-tune', 'Embeddings'] as const).map(f => (
              <button key={f} onClick={() => setAiFilter(f)}
                className={`px-3 py-1 text-xs rounded-full font-medium transition-colors ${aiFilter === f ? 'bg-purple-600 text-white' : 'bg-gray-800 text-gray-400 hover:text-white border border-gray-700'}`}>
                {f}
              </button>
            ))}
          </div>

          {offers.filter(o => o.status === 'open' && o.provider_address !== myAddr && matchesAiFilter(o)).length === 0 ? (
            <div className="bg-gray-800 rounded-xl border border-gray-600 p-8 text-center">
              <p className="text-gray-400 text-sm">{aiFilter === 'All' ? 'No GPU providers online yet.' : `No providers match "${aiFilter}" right now.`}</p>
              <p className="text-gray-500 text-xs mt-1">Providers list hardware in the Earn tab. Try "All" to see everything.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {offers.filter(o => o.status === 'open' && o.provider_address !== myAddr && matchesAiFilter(o)).map(o => {
                const rate = hourlyRate(o);
                const tags = aiSuitability(o);
                return (
                  <div key={o.offer_id} className={`rounded-xl border p-4 space-y-3 ${o.bonded ? 'bg-gray-800 border-gray-700' : 'bg-gray-800 border-orange-800/40'}`}>
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-1.5 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          {o.gpu_count > 0
                            ? <p className="text-white font-bold text-base">{gpuLabel(o)}</p>
                            : <p className="text-white font-bold text-base">{o.cpu_cores}-core CPU · {o.ram_gb}GB RAM</p>}
                          {o.bonded
                            ? <span className="text-xs bg-green-900 text-green-300 px-2 py-0.5 rounded-full">✓ Protected</span>
                            : <span className="text-xs bg-orange-900 text-orange-300 px-2 py-0.5 rounded-full">Unprotected</span>}
                        </div>
                        {o.gpu_count > 0 && (
                          <p className="text-gray-400 text-xs">{o.gpu_count}× GPU · {o.gpu_vram_gb}GB VRAM · {o.cpu_cores} cores · {o.ram_gb}GB RAM</p>
                        )}
                        <div className="flex gap-1.5 flex-wrap items-center">
                          <span className="text-[10px] text-gray-500 font-bold uppercase tracking-wider">Good for:</span>
                          {tags.map(t => (
                            <span key={t} className="text-[10px] bg-gray-700 text-gray-300 px-2 py-0.5 rounded-full">{t}</span>
                          ))}
                        </div>
                        <div className="flex items-center gap-3 pt-0.5">
                          <p className="text-yellow-400 font-bold text-lg">{fmt(rate)} <span className="text-sm font-normal text-gray-400">EGOC/hr</span></p>
                          <p className="text-gray-500 text-xs">{fmtDuration(o.min_duration_hours * 60)}–{fmtDuration(o.max_duration_hours * 60)}</p>
                        </div>
                      </div>
                      <button onClick={() => { setBookOpen(o); setBookDurationMins(Math.max(o.min_duration_hours * 60, 1_440)); setBookMsg(''); }}
                        className="px-5 py-2.5 bg-purple-600 hover:bg-purple-500 text-white text-sm rounded-xl font-bold whitespace-nowrap shadow-lg transition-all active:scale-95">
                        Rent GPU
                      </button>
                    </div>
                    <div className="flex gap-4 text-xs text-gray-600 pt-1 border-t border-gray-700/50 flex-wrap">
                      <span>1 day = <span className="text-gray-400">{fmt(rate * 24)} EGOC</span></span>
                      <span>1 week = <span className="text-gray-400">{fmt(rate * 24 * 7)} EGOC</span></span>
                      <span>Provider: <span className="text-gray-400">{fmtAddr(o.provider_address)}</span></span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Unified AI Workspace — one panel for ALL active rentals */}
          {(() => {
            const activeRentals = reservations.filter(r => r.buyer_address === myAddr && r.status === 'active');
            if (activeRentals.length === 0) return null;
            const target = selectedWorkspace && activeRentals.find(r => r.reservation_id === selectedWorkspace)
              ? selectedWorkspace
              : activeRentals[0].reservation_id;
            return (
              <div className="p-4 bg-purple-900/20 border border-purple-500/30 rounded-xl space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold text-purple-300 uppercase tracking-widest">AI Workspace</span>
                  <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse"></span>
                </div>
                {activeRentals.length > 1 && (
                  <p className="text-gray-400 text-xs">{activeRentals.length} active rentals — switch between them inside the workspace.</p>
                )}
                <button onClick={async () => {
                  await invoke('start_rental', { reservationId: target }).catch(() => {});
                  setShowConsole(target); setConsoleOut(''); setConsoleCmd(''); setTerminalOpen(false);
                }}
                  className="w-full py-3 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-white text-sm rounded-xl font-bold shadow-xl transition-all active:scale-95 flex items-center justify-center gap-2">
                  <svg className="w-4 h-4 shrink-0 animate-spin" style={{ animationDuration: '6s' }} viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 2C12 7.5 7.5 12 2 12C7.5 12 12 16.5 12 22C12 16.5 16.5 12 22 12C16.5 12 12 7.5 12 2Z"/>
                  </svg> Open AI Workspace
                </button>
                <p className="text-[10px] text-gray-500 text-center">Apps run on the remote GPU · Opens in your browser</p>
              </div>
            );
          })()}

          {/* My reservations as buyer */}
          {reservations.length > 0 && (
            <div className="space-y-3">
              <h2 className="text-white font-semibold">My Active AI Workspaces</h2>
              {reservations.map(r => {
                const isBuyer      = r.buyer_address === myAddr;
                const isProvider   = r.provider_address === myAddr;
                const totalPeriods = r.period_minutes > 0 ? Math.round(r.duration_minutes / r.period_minutes) : 1;
                const pct          = totalPeriods > 0 ? Math.round(r.periods_paid / totalPeriods * 100) : 0;
                const periodsLeft  = totalPeriods - r.periods_paid;
                const minsLeft     = periodsLeft * r.period_minutes;
                return (
                  <div key={r.reservation_id} className="bg-gray-800 border border-gray-700 rounded-xl p-4 space-y-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <StatusBadge s={r.status} />
                          {isBuyer    && <span className="text-xs bg-cyan-900 text-cyan-300 px-2 py-0.5 rounded-full">Renter</span>}
                          {isProvider && <span className="text-xs bg-purple-900 text-purple-300 px-2 py-0.5 rounded-full">Provider</span>}
                        </div>
                        <p className="text-white font-bold text-sm">{r.cpu_cores} Cores · {r.ram_gb}GB RAM · {gpuLabel(r)}</p>
                        <p className="text-gray-400 text-xs">
                          {fmt(r.period_rate_uegoc)} EGOC/{fmtDuration(r.period_minutes)} · {fmtDuration(r.duration_minutes)} total
                        </p>
                        <p className="text-gray-500 text-xs">
                          {isBuyer ? `Provider: ${fmtAddr(r.provider_address)}` : `Renter: ${fmtAddr(r.buyer_address)}`}
                        </p>
                      </div>
                      <div className="text-right shrink-0">
                        {isBuyer && r.status === 'active' && (
                          <div>
                            {r.started_at
                              ? <p className="text-white text-sm font-bold">{fmtDuration(minsLeft)} left</p>
                              : <p className="text-yellow-400 text-sm font-bold">Ready — not started</p>}
                            <p className="text-gray-400 text-xs">{fmt(r.escrow_remaining)} EGOC in escrow</p>
                          </div>
                        )}
                        {isProvider && (
                          <div>
                            <p className="text-yellow-400 text-sm font-bold">{fmt(r.period_rate_uegoc * r.periods_paid)} EGOC</p>
                            <p className="text-gray-400 text-xs">earned so far</p>
                            {isProvider && r.status === 'active' && (
                              <button onClick={() => setConfirmProvTerm(r.reservation_id)}
                                className="mt-1 px-3 py-1 bg-gray-700 hover:bg-red-900/40 text-gray-400 hover:text-red-300 text-[10px] uppercase font-bold tracking-wider rounded-lg transition-all">
                                Stop
                              </button>
                            )}
                          </div>
                        )}
                        {r.status !== 'active' && (
                          <button onClick={() => setConfirmDeleteHistory(r.reservation_id)}
                            className="px-3 py-1 bg-gray-700 hover:bg-red-900/40 text-gray-400 hover:text-red-300 text-[10px] uppercase font-bold tracking-wider rounded-lg transition-all">
                            Remove
                          </button>
                        )}
                      </div>
                    </div>

                    {r.status === 'active' && (
                      <div>
                        <div className="flex justify-between text-xs text-gray-500 mb-1">
                          <span>Period {r.periods_paid} of {totalPeriods}</span>
                          <span>{pct}% complete</span>
                        </div>
                        <div className="w-full bg-gray-700 rounded-full h-1.5">
                          <div className="bg-gradient-to-r from-purple-500 to-cyan-400 h-1.5 rounded-full transition-all" style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                    )}

                    {r.breach_count > 0 && (
                      <p className="text-red-400 text-xs">⚠ Provider missed {r.breach_count} period{r.breach_count > 1 ? 's' : ''}</p>
                    )}

                    {r.status === 'active' && isBuyer && (
                      <div className="flex flex-col gap-2 w-full mt-3 pt-3 border-t border-gray-700">
                        {r.breach_count >= 1 ? (
                          <button onClick={() => setConfirmTermRes(r.reservation_id)}
                            disabled={busyRes === r.reservation_id}
                            className="w-full py-2 bg-red-700 hover:bg-red-600 text-white text-sm rounded-lg disabled:opacity-60">
                            {busyRes === r.reservation_id ? 'Processing…'
                              : r.collateral_uegoc > 0
                                ? 'End Rental — Get Refund + Security Deposit'
                                : 'End Rental — Get Unused Escrow Refunded'}
                          </button>
                        ) : (
                          <>
                            <p className="text-gray-500 text-xs text-center mt-1 mb-2">
                              Payments release automatically each period. If the provider goes offline you'll be refunded.
                            </p>
                            <button onClick={() => setConfirmTermEarly({ id: r.reservation_id, penalty: r.period_rate_uegoc })}
                              disabled={busyRes === r.reservation_id}
                              className="w-full py-2 bg-gray-700 hover:bg-red-900 text-white hover:text-red-100 text-sm rounded-lg transition-colors disabled:opacity-60 border border-red-900/30">
                              {busyRes === r.reservation_id ? 'Processing…' : 'Terminate Early (Pay 1 Period Penalty)'}
                            </button>
                          </>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}



      {/* ── CLUSTER tab ── */}
      {tab === 'cluster' && (
        <div className="space-y-4">
          <div className="bg-gradient-to-br from-blue-900/30 to-purple-900/20 border border-blue-700/30 rounded-xl p-4 space-y-2">
            <p className="text-white font-semibold text-sm">Enterprise AI Training Clusters</p>
            <p className="text-gray-300 text-xs leading-relaxed">For companies and researchers who need scale. Book GPUs from multiple independent providers — they auto-join a WireGuard mesh. Run <strong className="text-white">PyTorch distributed training, DeepSpeed, or Ray</strong> across the entire cluster with a single head-node IP.</p>
            <div className="flex gap-2 flex-wrap pt-1 text-[10px]">
              <span className="bg-blue-900/40 text-blue-300 px-2 py-0.5 rounded-full border border-blue-700/30">🧬 Fine-tune LLaMA 70B</span>
              <span className="bg-purple-900/40 text-purple-300 px-2 py-0.5 rounded-full border border-purple-700/30">🔥 PyTorch DDP</span>
              <span className="bg-teal-900/40 text-teal-300 px-2 py-0.5 rounded-full border border-teal-700/30">⚡ DeepSpeed ZeRO</span>
              <span className="bg-orange-900/40 text-orange-300 px-2 py-0.5 rounded-full border border-orange-700/30">🌐 Ray Distributed</span>
            </div>
          </div>

          <div className="flex items-center justify-between">
            <h2 className="text-white font-semibold">My Clusters</h2>
            <button onClick={() => setClusterOpen(true)}
              className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white text-sm rounded-lg font-medium">
              + New Cluster
            </button>
          </div>

          {(() => {
            const myActive     = clusters.filter(c => c.buyer_address === myAddr && c.status !== 'terminated' && c.status !== 'auto_terminated');
            const myTerminated = clusters.filter(c => c.buyer_address === myAddr && (c.status === 'terminated' || c.status === 'auto_terminated'));
            if (myActive.length === 0 && myTerminated.length === 0) return (
              <div className="bg-gray-800 rounded-xl border border-gray-600 p-8 text-center space-y-2">
                <p className="text-4xl">🖥</p>
                <p className="text-gray-300 font-medium">No clusters yet</p>
                <p className="text-gray-500 text-sm">Combine GPUs from multiple providers into one machine — one VPN, one head IP, thousands of GPUs.</p>
                <button onClick={() => setClusterOpen(true)}
                  className="mt-2 px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white text-sm rounded-lg">
                  Create my first cluster
                </button>
              </div>
            );
            return (
            <div className="space-y-4">
              {[...myActive, ...myTerminated].map(c => {
                const activeNodes = c.nodes.filter(n => n.status === 'active').length;
                const minsLeft    = Math.max(0, Math.round((c.expires_at - Date.now() / 1000) / 60));
                const statusCls   = c.status === 'active' ? 'bg-green-900 text-green-300'
                                  : c.status === 'forming' || c.status === 'assembling' ? 'bg-yellow-900 text-yellow-300'
                                  : 'bg-gray-700 text-gray-400';
                const statusLabel = c.status === 'active' ? 'Active'
                                  : c.status === 'forming' || c.status === 'assembling' ? 'Assembling…'
                                  : c.status;
                return (
                  <div key={c.cluster_id} className={`border rounded-xl p-4 space-y-3 ${c.status === 'terminated' || c.status === 'auto_terminated' ? 'bg-gray-850 border-gray-700 opacity-70' : 'bg-gray-800 border-gray-700'}`}>
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-1 flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <p className="text-white font-semibold truncate">{c.name || c.cluster_id.slice(0, 8)}</p>
                          <span className={`text-xs px-2 py-0.5 rounded-full font-medium shrink-0 ${statusCls}`}>{statusLabel}</span>
                          <span className="text-xs bg-gray-700 text-gray-300 px-2 py-0.5 rounded-full shrink-0">{c.framework.toUpperCase()}</span>
                        </div>
                        <p className="text-gray-400 text-xs">{c.total_gpu_count} GPU · {c.total_cpu_cores} cores · {c.total_ram_gb}GB RAM · Subnet {c.subnet}.0/24</p>
                        <p className="text-gray-500 text-xs">{fmtDuration(minsLeft)} remaining · {c.nodes.length} nodes</p>
                      </div>
                      <div className="text-right shrink-0">
                        <p className="text-yellow-400 text-sm font-bold">{fmt(c.total_cost_uegoc)} EGOC</p>
                        <p className="text-gray-500 text-xs">locked</p>
                      </div>
                    </div>

                    <div className="space-y-1.5">
                      <p className="text-gray-500 text-xs">{activeNodes}/{c.nodes.length} nodes online</p>
                      <div className="flex flex-wrap gap-1.5">
                        {c.nodes.map(n => (
                          <div key={n.provider_address}
                            title={`${fmtAddr(n.provider_address)} · ${n.gpu_count}× ${n.gpu_name || 'CPU'} · ${n.wg_ip}${n.is_head ? ' (head)' : ''}`}
                            className={`w-3.5 h-3.5 rounded-full border-2 ${
                              n.status === 'active'  ? 'bg-green-500 border-green-400'   :
                              n.status === 'pending' ? 'bg-yellow-500 border-yellow-400' :
                              'bg-gray-600 border-gray-500'} ${n.is_head ? 'ring-1 ring-white ring-offset-1 ring-offset-gray-800' : ''}`} />
                        ))}
                      </div>
                    </div>

                    <div className="flex flex-wrap gap-2 pt-2 border-t border-gray-700">
                      {(c.status === 'active' || c.status === 'forming' || c.status === 'assembling') && (
                        <>
                          <button onClick={() => showConnectInfo(c.cluster_id)}
                            disabled={c.status !== 'active'}
                            className="px-3 py-1.5 bg-cyan-700 hover:bg-cyan-600 text-white text-xs rounded-lg font-medium disabled:opacity-50">
                            {c.status === 'active' ? 'Connect' : 'Waiting for Nodes...'}
                          </button>
                          <button onClick={() => downloadBuyerWgConfig(c.cluster_id)}
                            disabled={c.status !== 'active'}
                            className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-300 text-xs rounded-lg disabled:opacity-50">
                            WireGuard Config
                          </button>
                        </>
                      )}
                      {c.status !== 'terminated' && c.status !== 'auto_terminated' && (
                        <button onClick={() => setConfirmTermCluster(c.cluster_id)}
                          disabled={terminatingCluster === c.cluster_id}
                          className="px-3 py-1.5 bg-gray-700 hover:bg-red-900 text-gray-400 hover:text-red-300 text-xs rounded-lg transition-colors disabled:opacity-50 ml-auto">
                          {terminatingCluster === c.cluster_id ? 'Terminating…' : 'Terminate'}
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
            );
          })()}
        </div>
      )}

      {/* ── List Capacity modal ── */}
      {offerOpen && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6 w-full max-w-md space-y-3 max-h-[90vh] overflow-y-auto">
            <h3 className="text-white font-semibold">List my hardware for rent</h3>
            <p className="text-gray-400 text-xs">Set your price per hour. Buyers pick their own duration — from 30 minutes to a year.</p>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-gray-400 text-xs block mb-1">CPU cores to offer</label>
                <input type="number" min={1} value={offerCores} onChange={ev => setOfferCores(Number(ev.target.value))}
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm" />
              </div>
              <div>
                <label className="text-gray-400 text-xs block mb-1">RAM to offer (GB)</label>
                <input type="number" min={1} value={offerRam} onChange={ev => setOfferRam(Number(ev.target.value))}
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm" />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-gray-400 text-xs block mb-1">Number of GPUs</label>
                <input type="number" min={0} value={offerGpuCount} onChange={ev => setOfferGpuCount(Number(ev.target.value))}
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm" />
              </div>
              <div>
                <label className="text-gray-400 text-xs block mb-1">GPU memory (GB)</label>
                <input type="number" min={0} value={offerGpuVram} onChange={ev => setOfferGpuVram(Number(ev.target.value))}
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm" />
              </div>
            </div>

            {(() => {
              const v = offerGpuVram;
              const hasGpu = offerGpuCount > 0;
              const tiers: { label: string; desc: string; cls: string; gpu: number; core: number }[] =
                !hasGpu ? [
                  { label: 'Budget',   desc: 'High volume, beat Hetzner',         cls: 'border-gray-600',   gpu: 0,    core: 0.006 },
                  { label: 'Standard', desc: '40% below AWS, still profitable',   cls: 'border-purple-700', gpu: 0,    core: 0.014 },
                  { label: 'Premium',  desc: 'High-perf CPU, below AWS on-demand',cls: 'border-yellow-700', gpu: 0,    core: 0.028 },
                ] : v <= 8 ? [
                  { label: 'Budget',   desc: 'Undercut Vast.ai entry GPUs',       cls: 'border-gray-600',   gpu: 0.06, core: 0.006 },
                  { label: 'Standard', desc: 'At Vast.ai floor, 40% below RunPod',cls: 'border-purple-700', gpu: 0.12, core: 0.010 },
                  { label: 'Premium',  desc: 'Fair rate for 8GB inference',       cls: 'border-yellow-700', gpu: 0.20, core: 0.018 },
                ] : v <= 16 ? [
                  { label: 'Budget',   desc: '40% below RunPod RTX 3080',         cls: 'border-gray-600',   gpu: 0.12, core: 0.008 },
                  { label: 'Standard', desc: 'Matches Vast.ai RTX 3080 floor',    cls: 'border-purple-700', gpu: 0.22, core: 0.014 },
                  { label: 'Premium',  desc: '25% below Lambda RTX 6000',         cls: 'border-yellow-700', gpu: 0.38, core: 0.022 },
                ] : [
                  { label: 'Budget',   desc: '20% below Vast.ai RTX 3090',        cls: 'border-gray-600',   gpu: 0.20, core: 0.010 },
                  { label: 'Standard', desc: 'Matches RunPod 4090, 70% below AWS',cls: 'border-purple-700', gpu: 0.40, core: 0.020 },
                  { label: 'Premium',  desc: '40% below Lambda A100 ($1.29/hr)',  cls: 'border-yellow-700', gpu: 0.75, core: 0.035 },
                ];
              return (
                <div className="space-y-1.5">
                  <p className="text-gray-400 text-xs">Suggested prices <span className="text-gray-500">(click to apply)</span></p>
                  <div className="grid grid-cols-3 gap-2">
                    {tiers.map(t => {
                      const dailyU = u((t.gpu * offerGpuCount + t.core * offerCores) * 24);
                      const active = Math.abs(offerGpuHourEgoc - t.gpu) < 0.001 && Math.abs(offerCoreHourEgoc - t.core) < 0.0001;
                      return (
                        <button key={t.label} onClick={() => { setOfferGpuHourEgoc(t.gpu); setOfferCoreHourEgoc(t.core); }}
                          className={`border rounded-lg p-2 text-left space-y-0.5 transition-colors ${active ? 'bg-purple-900/40 ' + t.cls : t.cls + ' bg-gray-750 hover:bg-gray-700'}`}>
                          <p className={`text-xs font-semibold ${t.label === 'Premium' ? 'text-yellow-400' : t.label === 'Standard' ? 'text-purple-300' : 'text-gray-300'}`}>{t.label}</p>
                          {hasGpu && <p className="text-white text-xs">{t.gpu} EGOC/GPU/hr</p>}
                          <p className="text-gray-400 text-xs">{t.core} EGOC/core/hr</p>
                          <p className="text-green-400 text-xs font-medium">{fmt(dailyU)}/day</p>
                          <p className="text-gray-500 text-xs leading-tight">{t.desc}</p>
                        </button>
                      );
                    })}
                  </div>
                </div>
              );
            })()}

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-gray-400 text-xs block mb-1">Price per GPU · per hour (EGOC)</label>
                <input type="number" min={0} step={0.01} value={offerGpuHourEgoc}
                  onChange={ev => setOfferGpuHourEgoc(Number(ev.target.value))}
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm" />
              </div>
              <div>
                <label className="text-gray-400 text-xs block mb-1">Price per CPU core · per hour (EGOC)</label>
                <input type="number" min={0} step={0.001} value={offerCoreHourEgoc}
                  onChange={ev => setOfferCoreHourEgoc(Number(ev.target.value))}
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm" />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-gray-400 text-xs block mb-1">Minimum booking</label>
                <select value={offerMinHours} onChange={ev => setOfferMinHours(Number(ev.target.value))}
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm">
                  {BOOKING_RANGE_OPTIONS.map(o => (
                    <option key={o.hours} value={o.hours}>{o.label}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-gray-400 text-xs block mb-1">Maximum booking</label>
                <select value={offerMaxHours} onChange={ev => setOfferMaxHours(Number(ev.target.value))}
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm">
                  {BOOKING_RANGE_OPTIONS.map(o => (
                    <option key={o.hours} value={o.hours}>{o.label}</option>
                  ))}
                </select>
              </div>
            </div>

            <div className={`border rounded-xl p-3 space-y-2 cursor-pointer ${offerBonded ? 'border-green-700 bg-green-950/20' : 'border-gray-600 bg-gray-750'}`}
              onClick={() => setOfferBonded(b => !b)}>
              <div className="flex items-center justify-between">
                <p className={`text-sm font-medium ${offerBonded ? 'text-green-300' : 'text-gray-300'}`}>
                  {offerBonded ? '✓ Protected listing (recommended)' : 'Basic listing (no deposit)'}
                </p>
                <div className={`w-10 h-5 rounded-full transition-colors ${offerBonded ? 'bg-green-600' : 'bg-gray-600'}`}>
                  <div className={`w-4 h-4 bg-white rounded-full m-0.5 transition-transform ${offerBonded ? 'translate-x-5' : ''}`} />
                </div>
              </div>
              <p className="text-gray-400 text-xs">
                {offerBonded
                  ? `You lock a security deposit (30% of each booking). Buyers trust you more and you can charge higher prices. Deposit returned when booking ends normally.`
                  : 'No deposit needed. Renters get unused escrow back automatically if you go offline, but no extra penalty for you.'}
              </p>
            </div>

            <div className="bg-gray-750 border border-gray-600 rounded-lg p-3 text-xs space-y-1">
              <p className="text-gray-300">Earnings estimate:</p>
              <p className="text-yellow-400 text-base font-bold">
                {fmt(u(offerGpuHourEgoc * offerGpuCount + offerCoreHourEgoc * offerCores))} EGOC/hr
              </p>
              <p className="text-gray-500">= {fmt(u((offerGpuHourEgoc * offerGpuCount + offerCoreHourEgoc * offerCores) * 24))} EGOC/day</p>
              <p className="text-gray-500">= {fmt(u((offerGpuHourEgoc * offerGpuCount + offerCoreHourEgoc * offerCores) * 24 * 30))} EGOC/month (if fully booked)</p>
            </div>

            {offerMsg && <p className="text-red-400 text-sm">{offerMsg}</p>}
            <div className="flex gap-3">
              <button onClick={postOffer} disabled={offerPosting}
                className="flex-1 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-sm font-medium disabled:opacity-60">
                {offerPosting ? 'Listing…' : 'List My Hardware'}
              </button>
              <button onClick={() => setOfferOpen(false)}
                className="flex-1 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Book Reservation modal ── */}
      {bookOpen && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6 w-full max-w-md space-y-4 max-h-[90vh] overflow-y-auto">
            <h3 className="text-white font-semibold text-lg">Rent this hardware</h3>

            <div className={`border rounded-xl p-3 space-y-1 ${bookOpen.bonded ? 'border-green-700 bg-green-950/10' : 'border-orange-700/40 bg-orange-950/10'}`}>
              <div className="flex items-center gap-2">
                <p className="text-white font-medium">{gpuLabel(bookOpen)}</p>
                {bookOpen.bonded
                  ? <span className="text-xs bg-green-900 text-green-300 px-2 py-0.5 rounded-full">✓ Protected</span>
                  : <span className="text-xs bg-orange-900 text-orange-300 px-2 py-0.5 rounded-full">Basic</span>}
              </div>
              <p className="text-gray-400 text-xs">{bookOpen.cpu_cores} CPU cores · {bookOpen.ram_gb}GB RAM · {fmt(hourlyRate(bookOpen))} EGOC/hr</p>
              <p className="text-gray-400 text-xs">Provider: {fmtAddr(bookOpen.provider_address)}</p>
            </div>

            <div>
              <label className="text-gray-400 text-xs block mb-2">How long do you need it?</label>
              <div className="grid grid-cols-3 gap-2">
                {DURATION_OPTIONS.filter(d => d.minutes >= bookOpen.min_duration_hours * 60 && d.minutes <= bookOpen.max_duration_hours * 60).map(d => (
                  <button key={d.minutes} onClick={() => setBookDurationMins(d.minutes)}
                    className={`py-2 text-sm rounded-lg transition-colors ${bookDurationMins === d.minutes ? 'bg-purple-600 text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'}`}>
                    {d.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="bg-gray-750 border border-gray-600 rounded-lg p-3 space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-400">Duration</span>
                <span className="text-white">{fmtDuration(bookDurationMins)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Rate</span>
                <span className="text-white">{fmt(hourlyRate(bookOpen))} EGOC/hr</span>
              </div>
              <div className="flex justify-between border-t border-gray-600 pt-2">
                <span className="text-gray-400">Total you pay now</span>
                <span className="text-yellow-400 font-bold">
                  {fmt(Math.round(hourlyRate(bookOpen) * bookDurationMins / 60))} EGOC
                </span>
              </div>
              {bookOpen.bonded && (
                <div className="flex justify-between">
                  <span className="text-gray-400">Provider's security deposit</span>
                  <span className="text-green-400">{fmt(Math.round(hourlyRate(bookOpen) * bookDurationMins / 60 * 0.3))} EGOC</span>
                </div>
              )}
            </div>

            {bookOpen.bonded ? (
              <div className="bg-green-950/20 border border-green-800/40 rounded-lg p-3 text-xs text-green-300 space-y-1">
                <p className="font-medium">✓ Your payment is protected</p>
                <p className="text-green-400/70">If the provider goes offline, your unused escrow is refunded automatically. You also receive their security deposit as compensation.</p>
              </div>
            ) : (
              <div className="bg-orange-950/20 border border-orange-800/40 rounded-lg p-3 text-xs text-orange-300 space-y-1">
                <p className="font-medium">Basic protection</p>
                <p className="text-orange-400/70">If the provider goes offline, your unused escrow is refunded automatically. No extra penalty for the provider.</p>
              </div>
            )}

            {bookMsg && <p className="text-red-400 text-sm">{bookMsg}</p>}
            <div className="flex gap-3">
              <button onClick={bookReservation} disabled={booking}
                className="flex-1 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-sm font-medium disabled:opacity-60">
                {booking ? 'Booking…' : `Confirm — Pay ${fmt(Math.round(hourlyRate(bookOpen) * bookDurationMins / 60))} EGOC`}
              </button>
              <button onClick={() => setBookOpen(null)}
                className="flex-1 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Remove Offer confirmation modal ── */}
      {confirmRemove && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-xl border border-red-800/50 p-6 w-full max-w-sm space-y-4">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-full bg-red-900/40 flex items-center justify-center shrink-0">
                <svg className="w-5 h-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                </svg>
              </div>
              <div>
                <h3 className="text-white font-semibold">Remove this listing?</h3>
                <p className="text-gray-400 text-sm mt-1">
                  Your hardware will be unlisted and buyers won't be able to book it. This can't be undone.
                </p>
              </div>
            </div>
            <div className="flex gap-3 pt-1">
              <button onClick={confirmCancelOffer}
                className="flex-1 py-2.5 bg-red-700 hover:bg-red-600 text-white rounded-lg text-sm font-medium transition-colors">
                Yes, remove it
              </button>
              <button onClick={() => setConfirmRemove(null)}
                className="flex-1 py-2.5 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm transition-colors">
                Keep it
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Provider Terminate confirmation modal ── */}
      {confirmProvTerm && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-xl border border-red-800/50 p-6 w-full max-w-sm space-y-4 shadow-2xl">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-full bg-red-900/40 flex items-center justify-center shrink-0">
                <svg className="w-5 h-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                </svg>
              </div>
              <div>
                <h3 className="text-white font-semibold">Stop this rental?</h3>
                <p className="text-gray-400 text-sm mt-1">
                  You will stop earning rewards. Remaining escrow will be refunded to the buyer. Your security deposit will be returned.
                </p>
              </div>
            </div>
            <div className="flex gap-3 pt-1">
              <button onClick={executeProviderTerminate}
                className="flex-1 py-2.5 bg-red-700 hover:bg-red-600 text-white rounded-lg text-sm font-medium transition-colors">
                Stop Rental
              </button>
              <button onClick={() => setConfirmProvTerm(null)}
                className="flex-1 py-2.5 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm transition-colors">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Terminate Reservation confirmation modal ── */}
      {confirmTermRes && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-xl border border-red-800/50 p-6 w-full max-w-sm space-y-4">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-full bg-red-900/40 flex items-center justify-center shrink-0">
                <svg className="w-5 h-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                </svg>
              </div>
              <div>
                <h3 className="text-white font-semibold">End this rental?</h3>
                <p className="text-gray-400 text-sm mt-1">
                  The provider has breached the SLA. You will get your unused payment back.
                </p>
              </div>
            </div>
            <div className="flex gap-3 pt-1">
              <button onClick={executeTerminateReservation}
                className="flex-1 py-2.5 bg-red-700 hover:bg-red-600 text-white rounded-lg text-sm font-medium transition-colors">
                Yes, end rental
              </button>
              <button onClick={() => setConfirmTermRes(null)}
                className="flex-1 py-2.5 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm transition-colors">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Terminate Early confirmation modal ── */}
      {confirmTermEarly && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-xl border border-red-800/50 p-6 w-full max-w-sm space-y-4">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-full bg-red-900/40 flex items-center justify-center shrink-0">
                <svg className="w-5 h-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                </svg>
              </div>
              <div>
                <h3 className="text-white font-semibold">Terminate Early?</h3>
                <p className="text-gray-400 text-sm mt-1">
                  You will be charged a penalty of <span className="text-yellow-400 font-bold">{fmt(confirmTermEarly.penalty)} EGOC</span> (1 period). The rest of your unused escrow will be refunded.
                </p>
              </div>
            </div>
            <div className="flex gap-3 pt-1">
              <button onClick={executeTerminateEarly}
                className="flex-1 py-2.5 bg-red-700 hover:bg-red-600 text-white rounded-lg text-sm font-medium transition-colors">
                Yes, terminate
              </button>
              <button onClick={() => setConfirmTermEarly(null)}
                className="flex-1 py-2.5 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm transition-colors">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Delete History Item confirmation modal ── */}
      {confirmDeleteHistory && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-xl border border-red-800/50 p-6 w-full max-w-sm space-y-4">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-full bg-red-900/40 flex items-center justify-center shrink-0">
                <svg className="w-5 h-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
              </div>
              <div>
                <h3 className="text-white font-semibold">Remove from history?</h3>
                <p className="text-gray-400 text-sm mt-1">This will permanently clear this record from your local history.</p>
              </div>
            </div>
            <div className="flex gap-3 pt-1">
              <button onClick={executeDeleteHistoryItem} className="flex-1 py-2.5 bg-red-700 hover:bg-red-600 text-white rounded-lg text-sm font-medium transition-colors">Yes, remove</button>
              <button onClick={() => setConfirmDeleteHistory(null)} className="flex-1 py-2.5 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm transition-colors">Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* ── Terminate Cluster confirmation modal ── */}
      {confirmTermCluster && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-xl border border-red-800/50 p-6 w-full max-w-sm space-y-4">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-full bg-red-900/40 flex items-center justify-center shrink-0">
                <svg className="w-5 h-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                </svg>
              </div>
              <div>
                <h3 className="text-white font-semibold">Terminate Cluster?</h3>
                <p className="text-gray-400 text-sm mt-1">
                  Are you sure you want to end this cluster? Any unused escrow will be refunded to you.
                </p>
              </div>
            </div>
            <div className="flex gap-3 pt-1">
              <button onClick={executeTerminateCluster}
                className="flex-1 py-2.5 bg-red-700 hover:bg-red-600 text-white rounded-lg text-sm font-medium transition-colors">
                Yes, terminate
              </button>
              <button onClick={() => setConfirmTermCluster(null)}
                className="flex-1 py-2.5 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm transition-colors">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── AI Workspace Modal ── */}
      {showConsole && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4 backdrop-blur-md">
          <div className="bg-gray-900 rounded-2xl border border-purple-500/30 w-full max-w-3xl flex flex-col h-[88vh] shadow-2xl">
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-purple-600 to-blue-600 flex items-center justify-center shrink-0">
                  <svg className="w-5 h-5 text-white animate-spin" style={{ animationDuration: '6s' }} viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 2C12 7.5 7.5 12 2 12C7.5 12 12 16.5 12 22C12 16.5 16.5 12 22 12C16.5 12 12 7.5 12 2Z"/>
                  </svg>
                </div>
                <div>
                  <h3 className="font-bold text-white text-base leading-none">AI Workspace</h3>
                  <p className="text-gray-500 text-[10px] mt-0.5">Apps open in your browser · Compute runs on remote GPU</p>
                </div>
                <span className="text-[9px] bg-green-900/50 text-green-300 px-2 py-0.5 rounded border border-green-700/50 uppercase font-bold tracking-widest animate-pulse">Connected</span>
                {usageStats && (
                  usageStats.sandboxed
                    ? <span className="text-[9px] bg-cyan-900/50 text-cyan-300 px-2 py-0.5 rounded border border-cyan-700/50 uppercase font-bold tracking-widest">🔒 Isolated</span>
                    : <span className="text-[9px] bg-orange-900/50 text-orange-300 px-2 py-0.5 rounded border border-orange-700/50 uppercase font-bold tracking-widest">⚠ Shared Host</span>
                )}
              </div>
              <div className="flex items-center gap-3">
                <button onClick={refreshConnection} className="text-[10px] text-gray-500 hover:text-cyan-400 uppercase font-bold tracking-widest transition-colors">↺ Reconnect</button>
                <button onClick={() => setShowConsole(null)} className="text-gray-500 hover:text-white text-xl leading-none">✕</button>
              </div>
            </div>

            {/* Live Stats Dashboard — totals across ALL active rentals */}
            {(() => {
              const activeRentals = reservations.filter(r => r.buyer_address === myAddr && r.status === 'active');
              if (activeRentals.length === 0) return null;
              const totalCores = activeRentals.reduce((s, r) => s + r.cpu_cores, 0);
              const totalRam   = activeRentals.reduce((s, r) => s + r.ram_gb, 0);
              const totalGpu   = activeRentals.reduce((s, r) => s + r.gpu_count, 0);
              const nodeLabel  = activeRentals.length > 1 ? `Node ${activeRentals.findIndex(r => r.reservation_id === showConsole) + 1} load` : (usageStats?.sandboxed ? 'Your usage' : 'Host load');
              return (
                <div className="bg-gray-850 px-6 py-3 border-b border-gray-800 grid grid-cols-3 gap-4 shrink-0">
                  <div className="space-y-1">
                    <div className="flex justify-between text-[10px] uppercase font-bold tracking-tight">
                      <span className="text-gray-500">Total CPU</span>
                      <span className="text-blue-400">{totalCores} Cores{activeRentals.length > 1 ? ` · ${activeRentals.length} nodes` : ''}</span>
                    </div>
                    <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                      <div className="h-full bg-blue-500 transition-all duration-1000" style={{ width: `${usageStats?.cpu ?? 0}%` }} />
                    </div>
                    <div className="text-[9px] text-gray-600">{nodeLabel}: {usageStats?.cpu ?? 0}%</div>
                  </div>

                  <div className="space-y-1">
                    <div className="flex justify-between text-[10px] uppercase font-bold tracking-tight">
                      <span className="text-gray-500">Total RAM</span>
                      <span className="text-purple-400">{totalRam} GB</span>
                    </div>
                    <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                      <div className="h-full bg-purple-500 transition-all duration-1000"
                           style={{ width: `${Math.min(100, ((usageStats?.ram_used_gb ?? 0) / totalRam) * 100)}%` }} />
                    </div>
                    <div className="text-[9px] text-gray-600">{nodeLabel}: {usageStats?.ram_used_gb?.toFixed(1) ?? 0} GB</div>
                  </div>

                  <div className="space-y-1">
                    <div className="flex justify-between text-[10px] uppercase font-bold tracking-tight">
                      <span className="text-gray-500">Total GPU</span>
                      <span className="text-green-400">{totalGpu > 0 ? `${totalGpu} active` : 'None'}</span>
                    </div>
                    <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                      <div className={`h-full transition-all duration-1000 ${totalGpu > 0 ? 'bg-green-500' : 'bg-gray-700'}`}
                           style={{ width: `${totalGpu > 0 ? (usageStats?.gpu ?? 0) : 0}%` }} />
                    </div>
                    <div className="text-[9px] text-gray-600">
                      {totalGpu > 0 ? `${nodeLabel}: ${usageStats?.gpu ?? 0}%` : 'No GPU in any rental'}
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* Rental switcher — only shown when 2+ active rentals */}
            {(() => {
              const activeRentals = reservations.filter(r => r.buyer_address === myAddr && r.status === 'active');
              if (activeRentals.length < 2) return null;
              return (
                <div className="flex items-center gap-1 px-4 py-2 border-b border-gray-800 overflow-x-auto shrink-0 bg-gray-900/60">
                  {activeRentals.map((r, i) => (
                    <button key={r.reservation_id}
                      onClick={async () => {
                        await invoke('start_rental', { reservationId: r.reservation_id }).catch(() => {});
                        setShowConsole(r.reservation_id);
                        setConsoleOut(''); setConsoleCmd(''); setGpuAppUrl(null); setAppPollSecs(null);
                      }}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-colors shrink-0 ${showConsole === r.reservation_id ? 'bg-purple-700 text-white' : 'bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700'}`}>
                      <span className="w-1.5 h-1.5 rounded-full bg-green-400 shrink-0" />
                      GPU {i + 1} · {r.cpu_cores}c/{r.ram_gb}GB{r.gpu_count > 0 ? ` · ${r.gpu_count}×GPU` : ''}
                    </button>
                  ))}
                </div>
              );
            })()}

            {/* Metrics error banner — surfaces the underlying P2P/auth failure
                instead of leaving the panel frozen at 0%. */}
            {usageError && (
              <div className="bg-red-900/30 border-b border-red-800/60 px-6 py-2 text-[10px] text-red-300 font-mono shrink-0">
                ⚠ Live metrics unreachable: {usageError}
              </div>
            )}

            {/* Scrollable body */}
            <div className="flex-1 overflow-y-auto">

              {/* AI Task Launcher — 2×2 grid */}
              {(() => {
                const consoleRes = reservations.find(r => r.reservation_id === showConsole);
                const hasGpu = (consoleRes?.gpu_count ?? 0) > 0;
                return (
                  <div className="p-4 space-y-3">
                    <div className="text-[10px] text-gray-500 font-bold uppercase tracking-widest">Launch an AI App</div>
                    <div className="grid grid-cols-2 gap-3">

                      {/* LLM Chat */}
                      <div className="bg-gray-800 border border-gray-700 rounded-xl p-4 space-y-2.5 hover:border-emerald-700/50 transition-colors">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-2xl">💬</span>
                            <div>
                              <div className="text-white font-bold text-sm">LLM Chat</div>
                              <div className="text-gray-500 text-[10px]">TinyLlama 1.1B · ~640 MB</div>
                            </div>
                          </div>
                          {!hasGpu && <span className="text-[9px] bg-yellow-900/30 text-yellow-500 px-1.5 py-0.5 rounded border border-yellow-700/30 shrink-0">CPU ok</span>}
                        </div>
                        <p className="text-gray-500 text-[10px]">Chat with a local LLM. Runs on the remote GPU, opens in your browser.</p>
                        {gpuAppUrl?.app === 'llm'
                          ? <div className="space-y-1.5">
                              <button onClick={() => checkAndOpenApp('llm')} disabled={appBusy === 'llm_check'}
                                className="w-full py-2 text-xs bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-bold disabled:opacity-50">
                                {appBusy === 'llm_check' ? 'Checking…' : 'Open in browser ↗'}
                              </button>
                              {appPollSecs !== null && <p className="text-[10px] text-emerald-600 text-center">Auto-checking in {appPollSecs}s…</p>}
                              <button onClick={() => invoke<string>('run_remote_command', { reservationId: showConsole, command: "Get-Content 'C:\\ego_ws\\llm.log' -EA SilentlyContinue -Tail 20; Write-Output '---'; Get-Content 'C:\\ego_ws\\llm.err' -EA SilentlyContinue -Tail 20" }).then(r => setConsoleOut(p => p + `\n--- LOG ---\n${r}\n`)).catch(e => setConsoleOut(p => p + `\n[log fetch failed] ${e}\n`))} className="w-full py-1.5 text-[10px] bg-gray-700 hover:bg-gray-600 text-gray-400 hover:text-white rounded font-mono">
                                View logs
                              </button>
                            </div>
                          : <button onClick={() => openWebApp('llm', 'LLM Chat')} disabled={!!appBusy}
                              className="w-full py-2 text-xs bg-emerald-600/20 hover:bg-emerald-600 text-emerald-300 hover:text-white rounded-lg border border-emerald-700/30 font-bold disabled:opacity-40">
                              {appBusy === 'llm' ? 'Installing & launching…' : 'Launch Chat →'}
                            </button>}
                      </div>

                      {/* Image Generator */}
                      <div className="bg-gray-800 border border-gray-700 rounded-xl p-4 space-y-2.5 hover:border-pink-700/50 transition-colors">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-2xl">🎨</span>
                            <div>
                              <div className="text-white font-bold text-sm">Image Generator</div>
                              <div className="text-gray-500 text-[10px]">Stable Diffusion · ~2 GB</div>
                            </div>
                          </div>
                          {!hasGpu && <span className="text-[9px] bg-orange-900/30 text-orange-400 px-1.5 py-0.5 rounded border border-orange-700/30 shrink-0">GPU rec.</span>}
                        </div>
                        <p className="text-gray-500 text-[10px]">Generate images from text prompts. Opens as a web UI in your browser.</p>
                        {gpuAppUrl?.app === 'sdxl'
                          ? <div className="space-y-1.5">
                              <button onClick={() => checkAndOpenApp('sdxl')} disabled={appBusy === 'sdxl_check'}
                                className="w-full py-2 text-xs bg-pink-600 hover:bg-pink-500 text-white rounded-lg font-bold disabled:opacity-50">
                                {appBusy === 'sdxl_check' ? 'Checking…' : 'Open in browser ↗'}
                              </button>
                              {appPollSecs !== null && <p className="text-[10px] text-pink-600 text-center">Auto-checking in {appPollSecs}s… (~10 min first run)</p>}
                            </div>
                          : <button onClick={() => openWebApp('sdxl', 'Image Generator')} disabled={!!appBusy}
                              className="w-full py-2 text-xs bg-pink-600/20 hover:bg-pink-600 text-pink-300 hover:text-white rounded-lg border border-pink-700/30 font-bold disabled:opacity-40">
                              {appBusy === 'sdxl' ? 'Installing & launching…' : 'Launch Generator →'}
                            </button>}
                      </div>

                      {/* Jupyter */}
                      <div className="bg-gray-800 border border-gray-700 rounded-xl p-4 space-y-2.5 hover:border-cyan-700/50 transition-colors">
                        <div className="flex items-center gap-2">
                          <span className="text-2xl">🔬</span>
                          <div>
                            <div className="text-white font-bold text-sm">Jupyter Lab</div>
                            <div className="text-gray-500 text-[10px]">Python notebooks · full environment</div>
                          </div>
                        </div>
                        <p className="text-gray-500 text-[10px]">Write and run Python. Train models, process data, run scripts — all on the remote GPU.</p>
                        {gpuAppUrl?.app === 'jupyter'
                          ? <div className="space-y-1.5">
                              <button onClick={() => checkAndOpenApp('jupyter')} disabled={appBusy === 'jupyter_check'}
                                className="w-full py-2 text-xs bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg font-bold disabled:opacity-50">
                                {appBusy === 'jupyter_check' ? 'Checking…' : 'Open in browser ↗'}
                              </button>
                              {appPollSecs !== null && <p className="text-[10px] text-cyan-600 text-center">Auto-checking in {appPollSecs}s…</p>}
                            </div>
                          : <button onClick={() => openWebApp('jupyter', 'Jupyter')} disabled={!!appBusy}
                              className="w-full py-2 text-xs bg-cyan-600/20 hover:bg-cyan-600 text-cyan-300 hover:text-white rounded-lg border border-cyan-700/30 font-bold disabled:opacity-40">
                              {appBusy === 'jupyter' ? 'Installing & launching…' : 'Launch Jupyter →'}
                            </button>}
                      </div>

                      {/* Audio Transcription */}
                      <div className="bg-gray-800 border border-gray-700 rounded-xl p-4 space-y-2.5 hover:border-orange-700/50 transition-colors">
                        <div className="flex items-center gap-2">
                          <span className="text-2xl">🎤</span>
                          <div>
                            <div className="text-white font-bold text-sm">Transcribe Audio</div>
                            <div className="text-gray-500 text-[10px]">Whisper · .mp3 .wav .m4a · CPU ok</div>
                          </div>
                        </div>
                        <p className="text-gray-500 text-[10px]">Pick an audio file from your computer — it gets sent to the remote GPU and transcribed with Whisper.</p>
                        <div className="flex items-center gap-2">
                          <button onClick={pickAudioFile} disabled={fileBusy}
                            className="flex-1 py-1.5 text-[11px] bg-gray-700 hover:bg-gray-600 text-gray-200 hover:text-white rounded-lg font-bold disabled:opacity-40">
                            {fileBusy ? 'Uploading…' : '📂 Add audio file'}
                          </button>
                          {appAudioFile && (
                            <span className="text-[10px] text-gray-400 truncate max-w-[120px]">{appAudioFile}</span>
                          )}
                        </div>
                        {rentalFiles.filter(f => /\.(mp3|wav|m4a|ogg|flac|webm)$/i.test(f.name)).length > 0 && (
                          <select value={appAudioFile} onChange={e => setAppAudioFile(e.target.value)}
                            className="w-full bg-black border border-gray-700 rounded-lg px-2 py-1.5 text-[11px] text-white outline-none">
                            <option value="">Or choose from workspace…</option>
                            {rentalFiles.filter(f => /\.(mp3|wav|m4a|ogg|flac|webm)$/i.test(f.name)).map(f => (
                              <option key={f.name} value={f.name}>{f.name}</option>
                            ))}
                          </select>
                        )}
                        <button onClick={transcribeAudio} disabled={!appAudioFile || appBusy === 'transcribe'}
                          className="w-full py-2 text-xs bg-orange-600/20 hover:bg-orange-600 text-orange-300 hover:text-white rounded-lg border border-orange-700/30 font-bold disabled:opacity-40">
                          {appBusy === 'transcribe' ? 'Transcribing…' : 'Transcribe → save .txt'}
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })()}

              {/* Files section */}
              <div className="px-4 pb-3 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="text-[10px] text-gray-500 font-bold uppercase tracking-widest">Your Files</div>
                  <div className="flex gap-2">
                    <button onClick={refreshFiles} disabled={fileBusy}
                      className="text-[10px] text-gray-500 hover:text-cyan-400 font-bold transition-colors disabled:opacity-40">↺ Refresh</button>
                    <button onClick={openLocalFileToWorkspace} disabled={fileBusy}
                      className="px-3 py-1 bg-purple-600/20 hover:bg-purple-600 text-purple-300 hover:text-white text-[11px] rounded-lg border border-purple-500/30 font-bold disabled:opacity-40">
                      {fileBusy ? 'Uploading…' : '📂 Add File'}
                    </button>
                    <button onClick={uploadFolder} disabled={fileBusy}
                      className="px-3 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 hover:text-white text-[11px] rounded-lg font-bold disabled:opacity-40">
                      {fileBusy ? '…' : '📁 Add Folder'}
                    </button>
                  </div>
                </div>
                <p className="text-[10px] text-gray-600">Files live on the remote machine. Add a file or folder from your computer — audio and images are auto-detected.</p>
                <div className="rounded-xl border border-gray-800 divide-y divide-gray-800 overflow-hidden">
                  {rentalFiles.length === 0 ? (
                    <div className="text-[11px] text-gray-600 px-4 py-4 text-center">No files yet — click "Open from your computer" to upload one</div>
                  ) : rentalFiles.map(f => (
                    <div key={f.name} className="flex items-center justify-between px-4 py-2 text-[11px] hover:bg-gray-800/50">
                      <span className="text-gray-300 truncate mr-2">{f.name} <span className="text-gray-600">· {fmtBytes(f.size)}</span></span>
                      <div className="flex gap-3 shrink-0">
                        {isImage(f.name) && (
                          <button onClick={() => previewFile(f.name)} className="text-purple-400 hover:text-white font-bold">Preview</button>
                        )}
                        <button onClick={() => downloadFile(f.name)} className="text-cyan-400 hover:text-white font-bold">Download</button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Developer Terminal — collapsed by default */}
              <div className="border-t border-gray-800">
                <button onClick={() => setTerminalOpen(v => !v)}
                  className="w-full px-4 py-2.5 flex items-center justify-between text-gray-500 hover:text-gray-300 hover:bg-gray-800/30 transition-colors">
                  <span className="text-[10px] font-bold uppercase tracking-widest">Developer Terminal</span>
                  <span className="text-xs">{terminalOpen ? '▲ Hide' : '▼ Show'}</span>
                </button>
                {terminalOpen && (
                  <>
                    <div className="h-48 bg-black/60 px-4 py-3 font-mono text-xs overflow-y-auto text-green-400">
                      <div className="text-gray-600 mb-2"># Dilithium-signed P2P shell · {usageStats?.os ?? 'linux'}</div>
                      <pre className="whitespace-pre-wrap">{consoleOut}</pre>
                      {consoleBusy && <div className="animate-pulse text-blue-400">Running…</div>}
                    </div>
                    <div className="p-3 bg-gray-900 border-t border-gray-800 flex gap-2">
                      <input
                        value={consoleCmd}
                        onChange={e => setConsoleCmd(e.target.value)}
                        onKeyDown={e => e.key === 'Enter' && executeRemoteCommand()}
                        placeholder="nvidia-smi, ls, python3 script.py…"
                        className="flex-1 bg-black border border-gray-700 rounded-lg px-3 py-2 text-sm font-mono text-white outline-none focus:border-purple-500 transition-colors"
                        autoFocus={terminalOpen}
                      />
                      <button onClick={() => executeRemoteCommand()} disabled={consoleBusy || !consoleCmd.trim()}
                        className="bg-purple-600 hover:bg-purple-500 text-white px-5 rounded-lg font-bold text-sm disabled:opacity-40">Run</button>
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Image preview modal ── */}
      {filePreview && (
        <div className="fixed inset-0 bg-black/85 flex items-center justify-center z-[60] p-6 backdrop-blur-sm" onClick={() => setFilePreview(null)}>
          <div className="bg-gray-900 rounded-2xl border border-gray-700 p-4 max-w-3xl max-h-[90vh] flex flex-col" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-3">
              <span className="text-white text-sm font-bold truncate">{filePreview.name}</span>
              <div className="flex items-center gap-3">
                <button onClick={() => downloadFile(filePreview.name)} className="text-cyan-400 hover:text-white text-xs font-bold">Download</button>
                <button onClick={() => setFilePreview(null)} className="text-gray-500 hover:text-white text-xl">✕</button>
              </div>
            </div>
            <img src={filePreview.url} alt={filePreview.name} className="max-w-full max-h-[75vh] object-contain rounded-lg" />
          </div>
        </div>
      )}

      {/* ── Create Cluster modal ── */}
      {clusterOpen && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6 w-full max-w-md space-y-4 max-h-[90vh] overflow-y-auto">
            <div>
              <h3 className="text-white font-semibold text-lg">Create a GPU Cluster</h3>
              <p className="text-gray-400 text-xs mt-1">We select matching providers, book individual reservations, and wire them together over WireGuard automatically. You get one head IP.</p>
            </div>

            <div>
              <label className="text-gray-400 text-xs block mb-1">Cluster name</label>
              <input type="text" placeholder="e.g. training-run-1" value={clusterName}
                onChange={ev => setClusterName(ev.target.value)}
                className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm" />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-gray-400 text-xs block mb-1">Total GPUs wanted</label>
                <input type="number" min={1} value={clusterGpuCount}
                  onChange={ev => setClusterGpuCount(Number(ev.target.value))}
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm" />
              </div>
              <div>
                <label className="text-gray-400 text-xs block mb-1">Min VRAM per GPU (GB)</label>
                <input type="number" min={0} value={clusterMinVram}
                  onChange={ev => setClusterMinVram(Number(ev.target.value))}
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm" />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-gray-400 text-xs block mb-1">Min CPU cores per node</label>
                <input type="number" min={1} value={clusterCpuCores}
                  onChange={ev => setClusterCpuCores(Number(ev.target.value))}
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm" />
              </div>
              <div>
                <label className="text-gray-400 text-xs block mb-1">Min RAM per node (GB)</label>
                <input type="number" min={1} value={clusterRamGb}
                  onChange={ev => setClusterRamGb(Number(ev.target.value))}
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm" />
              </div>
            </div>

            <div>
              <label className="text-gray-400 text-xs block mb-2">Duration</label>
              <div className="grid grid-cols-3 gap-2">
                {DURATION_OPTIONS.map(d => (
                  <button key={d.minutes} onClick={() => setClusterDurationMins(d.minutes)}
                    className={`py-2 text-xs rounded-lg transition-colors ${clusterDurationMins === d.minutes ? 'bg-purple-600 text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'}`}>
                    {d.label}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="text-gray-400 text-xs block mb-2">Framework</label>
              <div className="grid grid-cols-2 gap-2">
                {(['ray', 'ssh'] as const).map(f => (
                  <button key={f} onClick={() => setClusterFramework(f)}
                    className={`py-2 text-sm rounded-lg transition-colors ${clusterFramework === f ? 'bg-purple-600 text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'}`}>
                    {f === 'ray' ? 'Ray (ML / distributed)' : 'SSH only'}
                  </button>
                ))}
              </div>
              <p className="text-gray-500 text-xs mt-1.5">
                {clusterFramework === 'ray'
                  ? 'Head runs ray start --head. Workers auto-join. Connect with ray.init(address="ray://<head>:10001").'
                  : 'SSH into the head node\'s WireGuard IP and orchestrate workers manually.'}
              </p>
            </div>

            <div className="bg-blue-900/20 border border-blue-700/30 rounded-lg p-3 text-xs text-blue-300 space-y-1">
              <p className="font-medium">How it works</p>
              <p>1. Matching providers are selected by price, cheapest first</p>
              <p>2. Each node generates a WireGuard keypair and joins the mesh automatically</p>
              <p>3. The node with the most VRAM becomes the head coordinator</p>
              <p>4. You get a wg0.conf to connect and a single head IP to work with</p>
            </div>

            {clusterMsg && <p className="text-red-400 text-sm">{clusterMsg}</p>}
            <div className="flex gap-3">
              <button onClick={createCluster} disabled={clusterBusy}
                className="flex-1 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-sm font-medium disabled:opacity-60">
                {clusterBusy ? 'Finding providers…' : 'Create Cluster'}
              </button>
              <button onClick={() => { setClusterOpen(false); setClusterMsg(''); }}
                className="flex-1 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Connect Info modal ── */}
      {connectInfo && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6 w-full max-w-lg space-y-4 max-h-[90vh] overflow-y-auto">
            <h3 className="text-white font-semibold text-lg">Connect to Cluster</h3>
            <div className="grid grid-cols-4 gap-2 text-center">
              {[
                { label: 'Status',  value: connectInfo.status },
                { label: 'Nodes',   value: `${connectInfo.nodes_active}/${connectInfo.nodes_total}` },
                { label: 'GPUs',    value: String(connectInfo.total_gpus) },
                { label: 'RAM',     value: `${connectInfo.total_ram_gb}GB` },
              ].map(({ label, value }) => (
                <div key={label} className="bg-gray-750 rounded-lg p-2">
                  <p className="text-gray-400 text-xs">{label}</p>
                  <p className="text-white font-bold text-sm">{value}</p>
                </div>
              ))}
            </div>

            {connectInfo.connect.type === 'ray' && connectInfo.connect.python_snippet && (
              <div>
                <p className="text-gray-400 text-xs mb-1">Python — connect with Ray</p>
                <pre className="bg-gray-900 rounded-lg p-3 text-green-400 text-xs overflow-x-auto whitespace-pre-wrap">{connectInfo.connect.python_snippet}</pre>
              </div>
            )}
            {connectInfo.connect.type === 'ray' && connectInfo.connect.head_bootstrap && (
              <div>
                <p className="text-gray-400 text-xs mb-1">Head node bootstrap (run once on head)</p>
                <pre className="bg-gray-900 rounded-lg p-3 text-cyan-400 text-xs overflow-x-auto whitespace-pre-wrap">{connectInfo.connect.head_bootstrap}</pre>
              </div>
            )}

            <div>
              <p className="text-gray-400 text-xs mb-1">SSH command</p>
              <pre className="bg-gray-900 rounded-lg p-3 text-yellow-400 text-xs overflow-x-auto">{connectInfo.connect.ssh_command}</pre>
            </div>
            {connectInfo.connect.note && (
              <div className="bg-yellow-900/20 border border-yellow-700/30 rounded-lg p-3 text-xs text-yellow-300">
                {connectInfo.connect.note}
              </div>
            )}
            <p className="text-gray-500 text-xs">Subnet: {connectInfo.subnet}.0/24 · Head IP: {connectInfo.connect.head_ip}</p>
            <button onClick={() => setConnectInfo(null)}
              className="w-full py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm">
              Close
            </button>
          </div>
        </div>
      )}

      {/* ── WireGuard Config modal ── */}
      {wgConfigOpen && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6 w-full max-w-lg space-y-4">
            <h3 className="text-white font-semibold">WireGuard Configuration</h3>
            <p className="text-gray-400 text-xs">
              Download the config below, then on <strong className="text-white">Windows</strong>: open WireGuard → <em>Import tunnel(s) from file…</em> → select <code className="text-white bg-gray-700 px-1 rounded">wg0.conf</code> → Activate.{' '}
              On <strong className="text-white">Linux/macOS</strong>: <code className="text-white bg-gray-700 px-1 rounded">wg-quick up wg0</code>.
            </p>
            <pre className="bg-gray-900 rounded-lg p-3 text-green-400 text-xs overflow-x-auto max-h-64 overflow-y-auto whitespace-pre">{wgConfigText}</pre>
            <div className="flex gap-3">
              <button onClick={() => {
                const blob = new Blob([wgConfigText], { type: 'text/plain' });
                const url  = URL.createObjectURL(blob);
                const a    = document.createElement('a');
                a.href = url; a.download = 'wg0.conf'; a.click();
                URL.revokeObjectURL(url);
              }} className="flex-1 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-sm font-medium">
                Download wg0.conf
              </button>
              <button onClick={() => setWgConfigOpen(false)}
                className="flex-1 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm">
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── SSH Key modal ── */}
      {sshKeyOpen && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm" onClick={e => e.target === e.currentTarget && setSshKeyOpen(false)}>
          <div className="bg-gray-800 rounded-2xl border border-gray-700 p-6 w-full max-w-lg space-y-4 shadow-2xl">
            <div className="flex justify-between items-center">
              <h3 className="text-white font-semibold text-lg">Your Public SSH Key</h3>
              <button onClick={() => setSshKeyOpen(false)} className="text-gray-400 hover:text-white text-xl leading-none">✕</button>
            </div>
            
            <div className="bg-blue-900/20 border border-blue-700/30 rounded-xl p-3 text-xs text-blue-300 leading-relaxed">
              <p className="font-semibold mb-1">To authorize your computer:</p>
              Copy the key below and send it to the compute provider. They must add it to their <code className="text-white bg-black/30 px-1 rounded">authorized_keys</code> file. Once they do, you can connect with one click.
            </div>

            <div className="relative group">
              {sshKeyLoading ? (
                <div className="h-32 bg-gray-900 rounded-xl flex items-center justify-center text-gray-500 text-sm animate-pulse">
                  Generating secure Ed25519 keypair…
                </div>
              ) : (
                <>
                  <pre className="bg-gray-900 rounded-xl p-4 text-[10px] text-green-400 font-mono break-all whitespace-pre-wrap h-32 overflow-y-auto border border-gray-700 group-hover:border-blue-500 transition-colors">
                    {sshKeyText}
                  </pre>
                  <button 
                    onClick={() => {
                      navigator.clipboard.writeText(sshKeyText);
                      setSshKeyCopied(true);
                      setTimeout(() => setSshKeyCopied(false), 2000);
                    }}
                    className={`absolute top-2 right-2 px-3 py-1.5 rounded-lg text-[10px] font-bold transition-all shadow-lg ${
                      sshKeyCopied ? 'bg-green-600 text-white' : 'bg-blue-600 hover:bg-blue-500 text-white opacity-0 group-hover:opacity-100'
                    }`}
                  >
                    {sshKeyCopied ? '✓ COPIED' : '📋 COPY'}
                  </button>
                </>
              )}
            </div>

            <button onClick={() => setSshKeyOpen(false)}
              className="w-full py-2.5 bg-gray-700 hover:bg-gray-600 text-white rounded-xl font-medium text-sm transition-colors">
              Close
            </button>
          </div>
        </div>
      )}

    </div>
  );
}
