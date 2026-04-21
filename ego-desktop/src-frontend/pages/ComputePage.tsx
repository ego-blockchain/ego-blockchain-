import React, { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/tauri';

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

  async function terminateReservation(reservationId: string) {
    if (!confirm('End this reservation and get your unused payment back?')) return;
    setBusyRes(reservationId);
    try { await invoke('terminate_reservation', { reservationId }); await load(); }
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

  async function doTerminateCluster(clusterId: string) {
    if (!confirm('Terminate this cluster? Unused escrow will be refunded.')) return;
    setTerminatingCluster(clusterId);
    try { await invoke('terminate_cluster', { clusterId }); await load(); }
    catch (err: any) { alert(String(err)); }
    setTerminatingCluster(null);
  }

  async function sendClusterHeartbeat(clusterId: string) {
    setClusterHeartbeatId(clusterId);
    try { await invoke('send_cluster_node_heartbeat', { clusterId }); await load(); }
    catch (err: any) { alert(String(err)); }
    setClusterHeartbeatId(null);
  }

  if (loading) return <div className="flex items-center justify-center h-64 text-gray-400">Loading…</div>;

  const myAddr           = status?.address ?? '';
  const activeResCount   = reservations.filter(r => r.status === 'active').length;
  const myClusterCount   = clusters.filter(c => c.buyer_address === myAddr && c.status !== 'terminated').length;

  return (
    <div className="p-6 space-y-5 max-w-4xl mx-auto">

      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Compute Marketplace</h1>
        <p className="text-gray-400 text-sm mt-0.5">
          Rent out your CPU, GPU, or RAM and earn EGOC · Rent computing power from anyone on the network
        </p>
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
          { id: 'book',    label: `Book${activeResCount > 0 ? ` (${activeResCount})` : ''}` },
          { id: 'cluster', label: `Clusters${myClusterCount > 0 ? ` (${myClusterCount})` : ''}` },
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

          {/* Setup card */}
          <div className="bg-gray-800 rounded-xl p-5 border border-gray-700 space-y-5">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-white font-semibold">Share your computer</h2>
                <p className="text-gray-400 text-xs mt-0.5">Rent out your CPU, GPU, or RAM to others and earn EGOC — separate from Storage</p>
              </div>
              <button onClick={() => setEnabled(v => !v)}
                className={`relative w-12 h-6 rounded-full transition-colors ${enabled ? 'bg-purple-600' : 'bg-gray-600'}`}>
                <span className={`absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform ${enabled ? 'translate-x-6' : ''}`} />
              </button>
            </div>

            {/* Hardware */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <p className="text-gray-300 text-sm font-medium">Your hardware</p>
                <button onClick={detectHw} disabled={detectingHw}
                  className="text-xs text-purple-400 hover:text-purple-300 disabled:opacity-50">
                  {detectingHw ? 'Scanning…' : 'Auto-detect'}
                </button>
              </div>
              {hw ? (
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div className="bg-gray-750 border border-gray-600 rounded-lg p-3">
                    <p className="text-gray-400 text-xs">Processor</p>
                    <p className="text-white">{hw.cpu_model}</p>
                    <p className="text-gray-400 text-xs mt-0.5">{hw.cpu_cores} cores · {hw.ram_gb}GB RAM</p>
                  </div>
                  <div className="bg-gray-750 border border-gray-600 rounded-lg p-3">
                    <p className="text-gray-400 text-xs">Graphics Card (GPU)</p>
                    <p className="text-white">{gpuLabel(hw)}</p>
                    {hw.has_cuda && <p className="text-green-400 text-xs mt-0.5">✓ CUDA — great for AI</p>}
                  </div>
                </div>
              ) : (
                <button onClick={detectHw} disabled={detectingHw}
                  className="w-full py-3 border-2 border-dashed border-gray-600 rounded-xl text-gray-400 text-sm hover:border-purple-500 hover:text-purple-400 transition-colors">
                  {detectingHw ? 'Scanning your hardware…' : '+ Click to detect your hardware'}
                </button>
              )}
            </div>

            {/* How much to share */}
            <div className="space-y-3">
              <p className="text-gray-300 text-sm font-medium">How much to share</p>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="flex justify-between text-xs text-gray-400 mb-1">
                    <span>CPU cores to share</span>
                    <span className="text-white font-medium">{allocCores} / {hw?.cpu_cores ?? '?'}</span>
                  </div>
                  <input type="range" min={1} max={hw?.cpu_cores ?? 16}
                    value={allocCores} onChange={ev => setAllocCores(Number(ev.target.value))}
                    className="w-full accent-purple-500" />
                </div>
                <div>
                  <div className="flex justify-between text-xs text-gray-400 mb-1">
                    <span>RAM to share</span>
                    <span className="text-white font-medium">{allocRam}GB / {hw?.ram_gb ?? '?'}GB</span>
                  </div>
                  <input type="range" min={1} max={hw?.ram_gb ?? 32}
                    value={allocRam} onChange={ev => setAllocRam(Number(ev.target.value))}
                    className="w-full accent-purple-500" />
                </div>
              </div>
              {((status?.locked_cores ?? 0) > 0 || (status?.locked_ram_gb ?? 0) > 0) && (
                <p className="text-yellow-400 text-xs">
                  ⚠ {status!.locked_cores} cores and {status!.locked_ram_gb}GB RAM are reserved by active bookings.
                </p>
              )}
            </div>

            {/* Pricing */}
            <div className="space-y-3">
              <p className="text-gray-300 text-sm font-medium">Your price</p>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-gray-400 text-xs block mb-1">Per GPU · per hour (EGOC)</label>
                  <div className="flex items-center gap-2">
                    <input type="number" min={0} step={0.1} value={gpuHourEgoc}
                      onChange={ev => setGpuHourEgoc(Number(ev.target.value))}
                      className="flex-1 bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm" />
                    <span className="text-gray-400 text-xs">EGOC/GPU/hr</span>
                  </div>
                </div>
                <div>
                  <label className="text-gray-400 text-xs block mb-1">Per CPU core · per hour (EGOC)</label>
                  <div className="flex items-center gap-2">
                    <input type="number" min={0} step={0.01} value={coreHourEgoc}
                      onChange={ev => setCoreHourEgoc(Number(ev.target.value))}
                      className="flex-1 bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-white text-sm" />
                    <span className="text-gray-400 text-xs">EGOC/core/hr</span>
                  </div>
                </div>
              </div>
              {hw && (
                <p className="text-purple-400 text-xs">
                  Estimated earnings: ~{fmt(u((hw.gpu_count * gpuHourEgoc + hw.cpu_cores * coreHourEgoc) * 24))} EGOC/day if running 24h
                </p>
              )}
            </div>

            {saveErr && <p className="text-red-400 text-sm">{saveErr}</p>}
            {saveMsg && <p className="text-green-400 text-sm">{saveMsg}</p>}
            <button onClick={saveSettings} disabled={saving}
              className="w-full py-2.5 bg-purple-600 hover:bg-purple-500 text-white rounded-xl font-medium text-sm disabled:opacity-60">
              {saving ? 'Saving…' : 'Save Settings'}
            </button>
          </div>

          {/* Sell capacity — time-based bookings */}
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-white font-semibold">List your hardware for rent</h2>
                <p className="text-gray-400 text-xs mt-0.5">
                  Buyers can book your hardware by the minute, hour, day, month, or year. Payment is held in escrow and released to you every period.
                </p>
              </div>
              <button onClick={() => setOfferOpen(true)}
                className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white text-sm rounded-lg font-medium whitespace-nowrap">
                + List My Hardware
              </button>
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
                    <button onClick={() => sendHeartbeat(r.reservation_id)}
                      disabled={busyRes === r.reservation_id}
                      className="w-full py-1.5 bg-green-700 hover:bg-green-600 text-white text-xs rounded-lg disabled:opacity-60">
                      {busyRes === r.reservation_id ? 'Sending…' : 'Send Check-In & Claim Payment'}
                    </button>
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

          <div className="bg-blue-900/20 border border-blue-700/30 rounded-xl px-4 py-3 text-xs text-blue-300 space-y-1">
            <p className="font-semibold text-sm">Rent compute power</p>
            <p>Pick a provider and a duration — from 30 minutes to a full year. Your payment is locked in escrow and released to the provider each period. If they go offline, you get the unused balance back automatically.</p>
          </div>

          <h2 className="text-white font-semibold">Available hardware</h2>

          {offers.filter(o => o.status === 'open').length === 0 ? (
            <div className="bg-gray-800 rounded-xl border border-gray-600 p-8 text-center">
              <p className="text-gray-400 text-sm">No hardware listed yet.</p>
              <p className="text-gray-500 text-xs mt-1">Providers list their hardware in the Earn tab.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {offers.filter(o => o.status === 'open').map(o => {
                const rate = hourlyRate(o);
                return (
                  <div key={o.offer_id} className={`rounded-xl border p-4 space-y-3 ${o.bonded ? 'bg-gray-800 border-gray-700' : 'bg-gray-800 border-orange-800/40'}`}>
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-1 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <p className="text-white font-medium">{gpuLabel(o)}</p>
                          <span className="text-xs text-gray-400">· {o.cpu_cores} CPU cores · {o.ram_gb}GB RAM</span>
                          {o.bonded
                            ? <span className="text-xs bg-green-900 text-green-300 px-2 py-0.5 rounded-full">✓ Protected</span>
                            : <span className="text-xs bg-orange-900 text-orange-300 px-2 py-0.5 rounded-full">Basic</span>}
                        </div>
                        <p className="text-yellow-400 font-semibold">{fmt(rate)} EGOC/hr</p>
                        <p className="text-gray-400 text-xs">
                          {fmtDuration(o.min_duration_hours * 60)}–{fmtDuration(o.max_duration_hours * 60)} · Provider: {fmtAddr(o.provider_address)}
                        </p>
                        {o.bonded
                          ? <p className="text-green-400/70 text-xs">If provider goes offline: unused escrow refunded + security deposit paid to you</p>
                          : <p className="text-orange-400/70 text-xs">If provider goes offline: unused escrow refunded (no extra penalty)</p>}
                      </div>
                      <button onClick={() => { setBookOpen(o); setBookDurationMins(Math.max(o.min_duration_hours * 60, 1_440)); setBookMsg(''); }}
                        className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white text-sm rounded-lg font-medium whitespace-nowrap">
                        Rent
                      </button>
                    </div>
                    <div className="flex gap-4 text-xs text-gray-500 pt-1 border-t border-gray-700 flex-wrap">
                      <span>1 day = <span className="text-white">{fmt(rate * 24)} EGOC</span></span>
                      <span>1 week = <span className="text-white">{fmt(rate * 24 * 7)} EGOC</span></span>
                      <span>1 month = <span className="text-white">{fmt(rate * 24 * 30)} EGOC</span></span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* My reservations as buyer */}
          {reservations.length > 0 && (
            <div className="space-y-3">
              <h2 className="text-white font-semibold">My rentals</h2>
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
                        <p className="text-white font-medium">{gpuLabel(r)} · {r.cpu_cores} cores</p>
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
                            <p className="text-white text-sm font-bold">{fmtDuration(minsLeft)} left</p>
                            <p className="text-gray-400 text-xs">{fmt(r.escrow_remaining)} EGOC in escrow</p>
                          </div>
                        )}
                        {isProvider && (
                          <div>
                            <p className="text-yellow-400 text-sm font-bold">{fmt(r.period_rate_uegoc * r.periods_paid)} EGOC</p>
                            <p className="text-gray-400 text-xs">earned so far</p>
                          </div>
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

                    {r.status === 'active' && isBuyer && r.breach_count >= 1 && (
                      <button onClick={() => terminateReservation(r.reservation_id)}
                        disabled={busyRes === r.reservation_id}
                        className="w-full py-2 bg-red-700 hover:bg-red-600 text-white text-sm rounded-lg disabled:opacity-60">
                        {busyRes === r.reservation_id ? 'Processing…'
                          : r.collateral_uegoc > 0
                            ? 'End Rental — Get Refund + Security Deposit'
                            : 'End Rental — Get Unused Escrow Refunded'}
                      </button>
                    )}
                    {r.status === 'active' && isBuyer && r.breach_count === 0 && (
                      <p className="text-gray-500 text-xs text-center">
                        Payments release automatically each period. If the provider goes offline you'll be refunded.
                      </p>
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
          <div className="bg-blue-900/20 border border-blue-700/30 rounded-xl px-4 py-3 text-xs text-blue-300 space-y-1">
            <p className="font-semibold text-sm">Distributed GPU Clusters</p>
            <p>Rent GPUs from multiple independent providers and link them into one WireGuard mesh. Nodes join automatically. Use Ray for distributed ML training, or SSH into the head node directly.</p>
          </div>

          <div className="flex items-center justify-between">
            <h2 className="text-white font-semibold">My Clusters</h2>
            <button onClick={() => setClusterOpen(true)}
              className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white text-sm rounded-lg font-medium">
              + New Cluster
            </button>
          </div>

          {clusters.filter(c => c.buyer_address === myAddr).length === 0 ? (
            <div className="bg-gray-800 rounded-xl border border-gray-600 p-8 text-center space-y-2">
              <p className="text-4xl">🖥</p>
              <p className="text-gray-300 font-medium">No clusters yet</p>
              <p className="text-gray-500 text-sm">Combine GPUs from multiple providers into one machine — one VPN, one head IP, thousands of GPUs.</p>
              <button onClick={() => setClusterOpen(true)}
                className="mt-2 px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white text-sm rounded-lg">
                Create my first cluster
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              {clusters.filter(c => c.buyer_address === myAddr).map(c => {
                const activeNodes = c.nodes.filter(n => n.status === 'active').length;
                const minsLeft    = Math.max(0, Math.round((c.expires_at - Date.now() / 1000) / 60));
                const statusCls   = c.status === 'active' ? 'bg-green-900 text-green-300'
                                  : c.status === 'forming' || c.status === 'assembling' ? 'bg-yellow-900 text-yellow-300'
                                  : 'bg-gray-700 text-gray-400';
                const statusLabel = c.status === 'active' ? 'Active'
                                  : c.status === 'forming' || c.status === 'assembling' ? 'Assembling…'
                                  : c.status;
                return (
                  <div key={c.cluster_id} className="bg-gray-800 border border-gray-700 rounded-xl p-4 space-y-3">
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
                      {c.status === 'active' && (
                        <>
                          <button onClick={() => showConnectInfo(c.cluster_id)}
                            className="px-3 py-1.5 bg-cyan-700 hover:bg-cyan-600 text-white text-xs rounded-lg font-medium">
                            Connect
                          </button>
                          <button onClick={() => downloadBuyerWgConfig(c.cluster_id)}
                            className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-300 text-xs rounded-lg">
                            WireGuard Config
                          </button>
                        </>
                      )}
                      <button onClick={() => doTerminateCluster(c.cluster_id)}
                        disabled={terminatingCluster === c.cluster_id}
                        className="px-3 py-1.5 bg-gray-700 hover:bg-red-900 text-gray-400 hover:text-red-300 text-xs rounded-lg transition-colors disabled:opacity-50 ml-auto">
                        {terminatingCluster === c.cluster_id ? 'Terminating…' : 'Terminate'}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
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
            <p className="text-gray-400 text-xs">Save as <code className="text-white bg-gray-700 px-1 rounded">wg0.conf</code> then run <code className="text-white bg-gray-700 px-1 rounded">wg-quick up wg0</code> to join the cluster VPN.</p>
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

    </div>
  );
}
