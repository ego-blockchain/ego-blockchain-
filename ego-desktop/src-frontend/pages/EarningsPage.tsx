import React, { useState, useEffect, useRef } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { useNavigate } from 'react-router-dom';

interface EarningsData {
  daily_rewards: number;
  epoch_rewards: number;
  total_earned: number;
  drs_multiplier: number;
  reward_breakdown: {
    storage_rewards: number;
    consensus_rewards: number;
    coverage_rewards: number;
    retrieval_rewards: number;
  };
  pending_rewards: number;
  session_started: number;
  coverage_online: boolean;
  reward_suspended_until: number | null;
}

interface StorageMetrics {
  storage_allocated_bytes: number;
  space_used_bytes: number;
}

interface PocScoreResult {
  drs_score:      number;
  events_24h:     number;
  total_events:   number;
  last_event:     number | null;
  is_validator:   boolean;
  validator_rank: number | null;
}

interface P2pStatus {
  relay_server_active:  boolean;
  community_relays:     string[];
  storage_quota_bytes:  number;
  storage_used_bytes:   number;
}

interface ComputeEarnings {
  total_uegoc:       number;
  jobs_completed:    number;
  avg_per_job_uegoc: number;
  last_24h_uegoc:    number;
}

interface ComputeStatus {
  enabled:     boolean;
  earnings_uegoc: number;
}

function fmtEgoc(uegoc: number, decimals = 4) {
  return (uegoc / 1_000_000).toLocaleString('en-US', {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  });
}

function fmtDuration(secs: number): string {
  if (secs < 60)    return `${secs}s`;
  if (secs < 3600)  return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return `${h}h ${m}m`;
}

const EarningsPage: React.FC = () => {
  const navigate = useNavigate();

  const [earnings, setEarnings]           = useState<EarningsData | null>(null);
  const [storageMeta, setStorageMeta]     = useState<StorageMetrics | null>(null);
  const [pocScore, setPocScore]           = useState<PocScoreResult | null>(null);
  const [p2pStatus, setP2pStatus]         = useState<P2pStatus | null>(null);
  const [lastPocMsg, setLastPocMsg]       = useState<string>('');
  const [coverageQuality, setCoverageQuality] = useState<string>('Good');
  const [coveragePeers, setCoveragePeers]     = useState<number>(0);
  const [computeEarnings, setComputeEarnings] = useState<ComputeEarnings | null>(null);
  const [computeStatus,   setComputeStatus]   = useState<ComputeStatus | null>(null);

  const [sessionEarned, setSessionEarned] = useState(0);

  const [uptime, setUptime]               = useState(0);
  const tickRef    = useRef<ReturnType<typeof setInterval> | null>(null);
  const pocTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    loadAll();
    loadPocScore();
    loadP2pStatus();

    const refresh = setInterval(loadAll, 30_000);
    const scoreRefresh = setInterval(loadPocScore, 5 * 60_000);
    const p2pRefresh = setInterval(loadP2pStatus, 60_000);
    return () => { clearInterval(refresh); clearInterval(scoreRefresh); clearInterval(p2pRefresh); };
  }, []);

  useEffect(() => {
    if (!earnings?.coverage_online) return;
    submitPocBeacon();
    if (pocTimerRef.current) clearInterval(pocTimerRef.current);
    pocTimerRef.current = setInterval(submitPocBeacon, 10 * 60_000);
    return () => { if (pocTimerRef.current) clearInterval(pocTimerRef.current); };
  }, [earnings?.coverage_online]);

  async function submitPocBeacon() {
    try {
      const result = await invoke<{ success: boolean; message: string; reward_uegoc: number }>(
        'submit_poc_event',
        { quality: coverageQuality, peers: coveragePeers, h3Cell: null }
      );
      if (result.success) {
        setLastPocMsg(`+${(result.reward_uegoc / 1_000_000).toFixed(6)} EGOC PoC reward`);
        loadPocScore();
      }
    } catch { }
  }

  async function loadPocScore() {
    try {
      const score = await invoke<PocScoreResult>('get_poc_score');
      setPocScore(score);
    } catch { }
  }

  async function loadP2pStatus() {
    try {
      const s = await invoke<P2pStatus>('get_p2p_status');
      setP2pStatus(s);
    } catch { }
  }

  async function loadAll() {
    try {
      const [e, m, cov, ce, cs] = await Promise.all([
        invoke<EarningsData>('get_earnings_data'),
        invoke<StorageMetrics>('get_storage_metrics'),
        invoke<{ network_quality: string; coverage_synced_count: number }>('get_coverage_status').catch(() => null),
        invoke<ComputeEarnings>('get_compute_earnings').catch(() => null),
        invoke<ComputeStatus>('get_compute_status').catch(() => null),
      ]);
      setEarnings(e);
      setStorageMeta(m);
      if (cov) {
        setCoverageQuality(cov.network_quality);
        setCoveragePeers(cov.coverage_synced_count);
      }
      if (ce) setComputeEarnings(ce);
      if (cs) setComputeStatus(cs);

      const elapsed = Math.floor(Date.now() / 1000) - e.session_started;
      const perSec  = e.daily_rewards / 86_400;
      setSessionEarned(elapsed * perSec);
      setUptime(elapsed);
    } catch (err) {
      console.error('EarningsPage load failed:', err);
    }
  }

  useEffect(() => {
    if (!earnings) return;
    const perSec = earnings.daily_rewards / 86_400;
    if (tickRef.current) clearInterval(tickRef.current);
    tickRef.current = setInterval(() => {
      setSessionEarned(prev => prev + perSec);
      setUptime(prev => prev + 1);
    }, 1_000);
    return () => { if (tickRef.current) clearInterval(tickRef.current); };
  }, [earnings?.daily_rewards]);

  const allocatedGb    = (storageMeta?.storage_allocated_bytes ?? 0) / 1e9;
  const isStorageSetup = allocatedGb > 0;
  const bd             = earnings?.reward_breakdown;
  const totalBuckets   = bd
    ? (bd.storage_rewards + bd.consensus_rewards + bd.coverage_rewards + bd.retrieval_rewards) || 1
    : 1;

  // USD targets (must match tokenomics.rs constants)
  const STORAGE_USD_PER_GB_DAY = 0.002;
  const CONSENSUS_USD_PER_DAY  = 0.20;
  const COVERAGE_USD_PER_DAY   = 0.15;
  const RETRIEVAL_USD_PER_GB   = 0.003;

  // Derive implied EGOC price from backend reward (storage is clearest proxy when allocated > 0)
  // If we can't derive it, we fall back to showing only EGOC amounts
  const impliedEgocPrice: number | null = (() => {
    if (!bd || allocatedGb <= 0 || bd.storage_rewards <= 0) return null;
    const usdTarget = STORAGE_USD_PER_GB_DAY * allocatedGb;
    return usdTarget / (bd.storage_rewards / 1_000_000);
  })();

  const priceStr = impliedEgocPrice !== null
    ? `~$${impliedEgocPrice < 0.01
        ? impliedEgocPrice.toExponential(2)
        : impliedEgocPrice.toFixed(4)}/EGOC`
    : 'live price';

  const buckets = bd ? [
    {
      label: 'Storage',
      val: bd.storage_rewards,
      color: 'bg-blue-500',
      text: 'text-blue-400',
      desc: `~$${STORAGE_USD_PER_GB_DAY}/GB/day → converted to EGOC at ${priceStr}`,
    },
    {
      label: 'Consensus',
      val: bd.consensus_rewards,
      color: 'bg-purple-500',
      text: 'text-purple-400',
      desc: `~$${CONSENSUS_USD_PER_DAY}/day → EGOC at ${priceStr}`,
    },
    {
      label: 'Coverage',
      val: bd.coverage_rewards,
      color: 'bg-green-500',
      text: 'text-green-400',
      desc: earnings?.coverage_online
        ? `~$${COVERAGE_USD_PER_DAY}/day → EGOC at ${priceStr}`
        : 'Offline — criteria not met',
    },
    {
      label: 'Retrieval',
      val: bd.retrieval_rewards,
      color: 'bg-orange-500',
      text: 'text-orange-400',
      desc: `~$${RETRIEVAL_USD_PER_GB}/GB served → EGOC at ${priceStr}`,
    },
  ] : [];

  // Current daily storage potential in EGOC (from backend, not hardcoded)
  const maxStorageEgocPerDay = bd ? bd.storage_rewards / 1_000_000 : 0;

  return (
    <div className="p-6 space-y-5 max-w-4xl mx-auto">

      {/* ── Testnet notice ─────────────────────────────────────────────────── */}
      <div className="bg-indigo-500/5 border border-indigo-500/20 rounded-xl px-5 py-3 flex items-center gap-4 shadow-sm">
        <div className="w-10 h-10 rounded-full bg-indigo-500/10 flex items-center justify-center text-xl shrink-0 border border-indigo-500/20">🧪</div>
        <div className="text-[11px] leading-relaxed text-indigo-200/70">
          <span className="font-bold text-indigo-300 uppercase tracking-widest text-[10px] block mb-0.5">Network Status: Testnet Simulation</span>
          All earnings, DRS scores, and rewards shown here are testnet profits for simulation and testing purposes only. They <span className="text-indigo-300 font-semibold underline decoration-indigo-500/50 underline-offset-2">will not</span> be converted to real EGOC.
        </div>
      </div>

      {/* ── Keep app open warning ──────────────────────────────────────────── */}
      <div className="bg-amber-900/10 border border-amber-500/30 rounded-2xl px-6 py-5 flex items-center gap-5 shadow-lg relative overflow-hidden group">
        <div className="absolute top-0 right-0 p-1">
          <div className="w-1.5 h-1.5 rounded-full bg-amber-500 animate-ping opacity-75"></div>
        </div>
        <div className="w-12 h-12 rounded-full bg-amber-500/10 flex items-center justify-center text-2xl shrink-0 border border-amber-500/20 group-hover:scale-110 transition-transform">⚠️</div>
        <div className="flex-1">
          <div className="font-black text-amber-400 text-xs uppercase tracking-[0.2em] mb-1">Node Activity Required</div>
          <div className="text-[11px] text-amber-200/60 leading-relaxed max-w-lg">
            Your node earns rewards <span className="text-amber-300 font-bold">only while running</span>. Closing the app stops all earnings — 
            storage proofs, coverage beacons, and block validation all require an active node heartbeat.
          </div>
        </div>
        <div className="text-right shrink-0 border-l border-amber-500/20 pl-6">
          <div className="text-[10px] font-bold text-amber-500/50 uppercase tracking-widest mb-1">Session Uptime</div>
          <div className="font-mono text-lg font-black text-amber-300 tabular-nums drop-shadow-[0_0_8px_rgba(251,191,36,0.3)]">{fmtDuration(uptime)}</div>
        </div>
      </div>

      {/* ── Reward suspension warning ──────────────────────────────────────── */}
      {earnings?.reward_suspended_until != null && earnings.reward_suspended_until > Math.floor(Date.now() / 1000) && (
        <div className="bg-red-500/10 border border-red-500/40 rounded-2xl px-5 py-4 flex items-start gap-3">
          <span className="text-2xl shrink-0 mt-0.5">🚫</span>
          <div>
            <div className="font-semibold text-red-400 text-sm">Rewards Suspended — Storage Reduction Penalty</div>
            <div className="text-xs text-red-300/80 mt-0.5">
              You reduced your storage allocation. All rewards are suspended for 14 days as a network penalty.
              Resumes on <span className="font-semibold text-red-300">{new Date(earnings.reward_suspended_until * 1000).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })}</span>.
            </div>
          </div>
        </div>
      )}

      {/* ── Price & reward model explanation ──────────────────────────────── */}
      <div className="bg-cyan-900/20 border border-cyan-500/30 rounded-2xl px-5 py-4 flex items-start gap-3">
        <span className="text-xl shrink-0 mt-0.5">📊</span>
        <div className="text-xs text-cyan-200/80 space-y-1.5">
          <div className="font-semibold text-cyan-300 text-sm">How rewards are calculated</div>
          <div>
            All rewards are <span className="text-cyan-300 font-medium">USD-pegged targets</span> converted
            to EGOC at the live market price. If EGOC rises in value you receive <em>fewer</em> coins for the
            same USD income — if it falls you receive <em>more</em>.
          </div>
          <div>
            Rates also scale down as the <span className="text-cyan-300 font-medium">300M EGOC node pool</span> depletes
            (full-speed until 80% is paid out, then tapers to zero), and block rewards
            <span className="text-cyan-300 font-medium"> halve every ~4 years</span> over a 120-year emission schedule.
          </div>
          {impliedEgocPrice !== null && (
            <div>
              Current implied EGOC price used for your rewards:{' '}
              <span className="text-cyan-300 font-semibold">{priceStr}</span>
            </div>
          )}
        </div>
      </div>

      {/* ── Storage setup prompt ───────────────────────────────────────────── */}
      {!isStorageSetup && (
        <div className="bg-gradient-to-r from-purple-900/50 to-blue-900/50 rounded-2xl border border-purple-500/30 p-5 flex items-center justify-between gap-4">
          <div>
            <div className="font-semibold mb-1">Storage rewards are zero — configure storage first</div>
            <div className="text-sm text-gray-400">
              Share disk space to earn{' '}
              <span className="text-green-400 font-semibold">~${STORAGE_USD_PER_GB_DAY}/GB/day in EGOC</span>
              {' '}— paid when your space is actually used by other peers
            </div>
          </div>
          <button
            onClick={() => navigate('/storage')}
            className="shrink-0 bg-purple-600 hover:bg-purple-500 transition px-4 py-2.5 rounded-xl font-semibold text-sm"
          >
            Configure Storage →
          </button>
        </div>
      )}

      {isStorageSetup && (
        <div className="bg-gray-800 rounded-2xl border border-gray-700 p-4 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="w-2.5 h-2.5 rounded-full bg-green-400 animate-pulse shrink-0"></span>
            <div>
              <div className="text-sm font-semibold text-green-400">Storage Provider Active</div>
              <div className="text-xs text-gray-400">
                {allocatedGb.toFixed(1)} GB · max potential{' '}
                <span className="text-green-300 font-semibold">
                  {maxStorageEgocPerDay.toFixed(4)} EGOC/day
                </span>{' '}
                ≈ <span className="text-gray-500">${(STORAGE_USD_PER_GB_DAY * allocatedGb).toFixed(4)}/day</span>
                {' '}(if fully utilized by peers)
              </div>
            </div>
          </div>
          <button onClick={() => navigate('/storage')} className="text-xs text-blue-400 hover:text-blue-300">Manage →</button>
        </div>
      )}

      {computeStatus?.enabled && (
        <div className="bg-gray-800 rounded-2xl border border-gray-700 p-4 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-400 animate-pulse shrink-0"></span>
            <div>
              <div className="text-sm font-semibold text-purple-400">Compute Sharing Active</div>
              <div className="text-xs text-gray-400">
                Renting out CPU / GPU / RAM ·{' '}
                {computeEarnings && computeEarnings.total_uegoc > 0 ? (
                  <>
                    <span className="text-purple-300 font-semibold">{fmtEgoc(computeEarnings.total_uegoc, 4)} EGOC</span>
                    {' '}earned total · {computeEarnings.jobs_completed} job{computeEarnings.jobs_completed !== 1 ? 's' : ''} completed
                  </>
                ) : (
                  <span className="text-gray-500">waiting for first renter</span>
                )}
              </div>
            </div>
          </div>
          <button onClick={() => navigate('/compute')} className="text-xs text-blue-400 hover:text-blue-300">Manage →</button>
        </div>
      )}

      {!computeStatus?.enabled && (
        <div className="bg-gradient-to-r from-purple-900/30 to-gray-900/30 rounded-2xl border border-purple-500/20 p-4 flex items-center justify-between gap-4">
          <div>
            <div className="font-semibold text-sm mb-0.5">Earn from compute — CPU, GPU, RAM</div>
            <div className="text-xs text-gray-400">
              List your hardware for rent and get paid in EGOC per hour — separate from storage rewards.
            </div>
          </div>
          <button onClick={() => navigate('/compute')}
            className="shrink-0 bg-purple-600 hover:bg-purple-500 transition px-4 py-2.5 rounded-xl font-semibold text-sm">
            Set up Compute →
          </button>
        </div>
      )}

      {/* ── Session earned counter ─────────────────────────────────────────── */}
      <div className="bg-slate-950 border border-slate-800 rounded-2xl p-7 shadow-2xl relative overflow-hidden group">
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-emerald-500 via-cyan-500 to-indigo-500 opacity-50"></div>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="text-[10px] font-black text-slate-500 uppercase tracking-[0.25em] mb-2 flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.8)]"></span>
              Live Session Accrual
            </div>
            <div className="text-5xl font-mono font-black text-emerald-400 tabular-nums tracking-tighter drop-shadow-[0_0_15px_rgba(16,185,129,0.3)]">
              {fmtEgoc(sessionEarned, 6)} <span className="text-xl text-emerald-700/60 ml-1">EGOC</span>
            </div>
          </div>
          <div className="text-left md:text-right space-y-1 border-t md:border-t-0 md:border-l border-slate-800 pt-4 md:pt-0 md:pl-8">
            <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Network Throughput</div>
            <div className="text-sm font-mono font-bold text-slate-300">
              {fmtEgoc(earnings?.daily_rewards ?? 0, 2)} <span className="text-[10px] text-slate-500">EGOC / DAY</span>
            </div>
            <div className="text-[9px] text-slate-600 leading-tight uppercase font-medium">Actual payout subject to <br/>DRS eligibility and uptime</div>
          </div>
        </div>
      </div>

      {/* ── Summary cards ─────────────────────────────────────────────────── */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Settlement Rate', val: earnings ? fmtEgoc(earnings.daily_rewards) : '—',    unit: 'EGOC / 24H', color: 'text-emerald-400', bg: 'bg-emerald-500/5 border-emerald-500/10' },
          { label: 'Epoch Target',   val: earnings ? fmtEgoc(earnings.epoch_rewards)  : '—',    unit: 'EGOC / 7D',  color: 'text-cyan-400',    bg: 'bg-cyan-500/5 border-cyan-500/10'    },
          { label: 'Pending Payout', val: earnings ? fmtEgoc(earnings.pending_rewards): '—',    unit: 'UEGOC UNCONFIRMED', color: 'text-amber-400',   bg: 'bg-amber-500/5 border-amber-500/10'   },
          { label: 'Lifetime Earnings', val: earnings ? fmtEgoc(earnings.total_earned)   : '—',    unit: 'TOTAL EGOC · ALL TIME', color: 'text-indigo-400',  bg: 'bg-indigo-500/5 border-indigo-500/10' },
        ].map(c => (
          <div key={c.label} className={`${c.bg} rounded-xl p-5 border relative overflow-hidden group hover:bg-opacity-10 transition-all`}>
            <div className="text-[10px] font-black text-slate-500 uppercase tracking-[0.15em] mb-3">{c.label}</div>
            <div className={`text-2xl font-mono font-black tabular-nums ${c.color} drop-shadow-[0_0_8px_rgba(0,0,0,0.3)]`}>{c.val}</div>
            <div className="text-[9px] font-bold text-slate-600 uppercase tracking-widest mt-2">{c.unit}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-5 gap-4">

        {/* ── Reward breakdown ────────────────────────────────────────────── */}
        <div className="col-span-3 bg-gray-800 rounded-2xl p-5 border border-gray-700">
          <h3 className="font-semibold mb-1">Potential Reward Breakdown</h3>
          <p className="text-xs text-gray-500 mb-4">
            Maximum rates at current price — amounts change as EGOC price moves or node pool depletes
          </p>
          <div className="space-y-4">
            {buckets.map(bucket => {
              const pct = Math.round((bucket.val / totalBuckets) * 100);
              return (
                <div key={bucket.label}>
                  <div className="flex justify-between text-sm mb-1.5">
                    <div>
                      <span className="text-gray-300 font-medium">{bucket.label}</span>
                      <span className="ml-2 text-xs text-gray-500">{bucket.desc}</span>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className={`${bucket.text} font-semibold`}>{fmtEgoc(bucket.val, 2)}</span>
                      <span className="text-gray-500 text-xs">{pct}%</span>
                    </div>
                  </div>
                  <div className="bg-gray-700 rounded-full h-2">
                    <div
                      className={`${bucket.color} h-2 rounded-full transition-all duration-700`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

          <div className="mt-5 pt-5 border-t border-gray-700">
            <div className="text-xs text-gray-400 mb-3">Criteria to qualify for each reward</div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              {[
                { label: 'Storage',   desc: 'Allocate space AND have it used by network peers — reward tracks USD value, not a fixed EGOC amount' },
                { label: 'Consensus', desc: 'Node must be online and actively participating in block validation rounds' },
                { label: 'Coverage',  desc: 'PoC beacon must be online without VPN and pass geographic proof challenges' },
                { label: 'Retrieval', desc: 'Only paid when other nodes actually request and download data from you' },
                { label: 'Compute',   desc: 'Direct rental income — buyers pay you per hour for your CPU, GPU, or RAM. Managed in the Compute tab, separate from protocol rewards.' },
              ].map(e => (
                <div key={e.label} className="bg-gray-900 rounded-lg p-2.5">
                  <div className="font-medium text-gray-200">{e.label}</div>
                  <div className="text-gray-500 mt-0.5">{e.desc}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── Right column: node status + options ─────────────────────────── */}
        <div className="col-span-2 space-y-4">

          {/* Node status */}
          <div className="bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <h3 className="font-semibold mb-4">Node Status</h3>
            <div className="space-y-3 text-sm">
              <div className="flex justify-between items-center">
                <span className="text-gray-400">App / Node</span>
                <span className="flex items-center gap-1.5 text-green-400 font-medium">
                  <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse"></span> Running
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-400">Coverage beacon</span>
                {earnings?.coverage_online ? (
                  <span className="flex items-center gap-1.5 text-green-400 font-medium">
                    <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse"></span> Online
                  </span>
                ) : (
                  <span className="text-red-400 font-medium">Offline</span>
                )}
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-400">Storage</span>
                {isStorageSetup ? (
                  <span className="text-green-400 font-medium">{allocatedGb.toFixed(1)} GB active</span>
                ) : (
                  <span className="text-yellow-400 font-medium">Not configured</span>
                )}
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-400">Compute sharing</span>
                {computeStatus?.enabled ? (
                  <span className="flex items-center gap-1.5 text-purple-400 font-medium">
                    <span className="w-2 h-2 rounded-full bg-purple-400 animate-pulse"></span> Active
                  </span>
                ) : (
                  <span className="text-gray-500 text-xs">Off</span>
                )}
              </div>
              {computeEarnings && computeEarnings.last_24h_uegoc > 0 && (
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Compute earned (24h)</span>
                  <span className="text-purple-400 font-semibold">{fmtEgoc(computeEarnings.last_24h_uegoc, 4)} EGOC</span>
                </div>
              )}
              <div className="flex justify-between items-center">
                <span className="text-gray-400">Relay server</span>
                {p2pStatus?.relay_server_active ? (
                  <span className="flex items-center gap-1.5 text-purple-400 font-medium">
                    <span className="w-2 h-2 rounded-full bg-purple-400 animate-pulse"></span> Active
                  </span>
                ) : (
                  <span className="text-gray-500 text-xs">NAT (client only)</span>
                )}
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-400">DRS score (relay) <span className="text-blue-400/70 text-xs font-normal">testnet</span></span>
                {pocScore ? (
                  <span className={`font-semibold ${pocScore.drs_score > 0 ? 'text-green-400' : 'text-gray-500'}`}>
                    {pocScore.drs_score.toFixed(2)}
                    {pocScore.validator_rank && (
                      <span className="ml-1.5 text-xs text-blue-400">#{pocScore.validator_rank}</span>
                    )}
                  </span>
                ) : <span className="text-gray-500 text-xs">loading…</span>}
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-400">PoC events (24h)</span>
                <span className="text-gray-300">{pocScore?.events_24h ?? '—'}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-400">Session uptime</span>
                <span className="font-mono text-gray-300">{fmtDuration(uptime)}</span>
              </div>
              {lastPocMsg && (
                <div className="text-xs text-green-400 animate-pulse">{lastPocMsg}</div>
              )}
            </div>
          </div>

          {/* Stake rewards */}
          <div className="bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <h3 className="font-semibold mb-2">Stake Your Rewards</h3>
            <p className="text-xs text-gray-400 mb-4">
              Lock earned EGOC to boost your DRS multiplier, earn staking APR, and gain governance
              rights — as described in the Ego whitepaper.
            </p>
            <div className="space-y-2 text-sm mb-4">
              <div className="flex justify-between">
                <span className="text-gray-400">Staking APR</span>
                <span className="text-green-400 font-bold">12.5%</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Lock bonus (1 yr)</span>
                <span className="text-green-400">+10%</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Reward lock interest</span>
                <span className="text-yellow-400">20% simple</span>
              </div>
            </div>
            <button
              onClick={() => navigate('/staking')}
              className="w-full bg-blue-600 hover:bg-blue-500 py-2.5 rounded-xl font-semibold text-sm transition"
            >
              🔒 Go to Staking →
            </button>
          </div>

          {/* Block production */}
          <div className="bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <h3 className="font-semibold mb-2">Block Production</h3>
            <p className="text-xs text-gray-400 mb-3">
              Every transaction mines a new block. BFT validators earn block rewards that halve every
              ~4 years over a 120-year emission schedule.
            </p>
            <div className="flex justify-between text-sm mb-1">
              <span className="text-gray-400">Era-0 block reward</span>
              <span className="text-green-400 font-bold">0.0832 EGOC</span>
            </div>
            <div className="flex justify-between text-sm mb-1">
              <span className="text-gray-400">Halving interval</span>
              <span className="text-gray-300">~4 years</span>
            </div>
            <div className="flex justify-between text-sm mb-3">
              <span className="text-gray-400">Consensus</span>
              <span className="text-gray-300">sBFT validator</span>
            </div>
            <div className="text-xs text-gray-500 bg-gray-900 rounded-lg p-2.5">
              Block rewards are fixed in EGOC (not USD). As EGOC appreciates, each block reward
              becomes more valuable — the 120-year schedule ensures long-term miner incentives.
            </div>
          </div>

        </div>
      </div>

    </div>
  );
};

export default EarningsPage;
