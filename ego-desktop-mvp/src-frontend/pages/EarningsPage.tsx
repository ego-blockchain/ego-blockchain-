import React, { useState, useEffect, useRef } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { useNavigate } from 'react-router-dom';

// ── Types ─────────────────────────────────────────────────────────────────────

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
  session_started: number;   // unix timestamp
  coverage_online: boolean;
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

// ── Helpers ───────────────────────────────────────────────────────────────────

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

// ── Component ─────────────────────────────────────────────────────────────────

const EarningsPage: React.FC = () => {
  const navigate = useNavigate();

  const [earnings, setEarnings]           = useState<EarningsData | null>(null);
  const [storageMeta, setStorageMeta]     = useState<StorageMetrics | null>(null);
  const [pocScore, setPocScore]           = useState<PocScoreResult | null>(null);
  const [p2pStatus, setP2pStatus]         = useState<P2pStatus | null>(null);
  const [lastPocMsg, setLastPocMsg]       = useState<string>('');
  // Live session-earnings counter (in uEGOC, fractional)
  const [sessionEarned, setSessionEarned] = useState(0);
  // Seconds the node has been running this session
  const [uptime, setUptime]               = useState(0);
  const tickRef    = useRef<ReturnType<typeof setInterval> | null>(null);
  const pocTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    loadAll();
    loadPocScore();
    loadP2pStatus();
    // Refresh from backend every 30 s (also credits elapsed earnings)
    const refresh = setInterval(loadAll, 30_000);
    // Refresh DRS score every 5 minutes
    const scoreRefresh = setInterval(loadPocScore, 5 * 60_000);
    // Refresh P2P status every 60 s
    const p2pRefresh = setInterval(loadP2pStatus, 60_000);
    return () => { clearInterval(refresh); clearInterval(scoreRefresh); clearInterval(p2pRefresh); };
  }, []);

  // PoC beacon: fire once on mount, then every 10 minutes while coverage is online
  useEffect(() => {
    if (!earnings?.coverage_online) return;
    submitPocBeacon(); // fire immediately on first online detection
    if (pocTimerRef.current) clearInterval(pocTimerRef.current);
    pocTimerRef.current = setInterval(submitPocBeacon, 10 * 60_000);
    return () => { if (pocTimerRef.current) clearInterval(pocTimerRef.current); };
  }, [earnings?.coverage_online]);

  async function submitPocBeacon() {
    try {
      const result = await invoke<{ success: boolean; message: string; reward_uegoc: number }>(
        'submit_poc_event',
        { quality: 'Good', peers: 3, h3Cell: null }
      );
      if (result.success) {
        setLastPocMsg(`+${(result.reward_uegoc / 1_000_000).toFixed(6)} EGOC PoC reward`);
        loadPocScore(); // refresh DRS after new event
      }
    } catch {
      // relay unreachable — silent fail (still earns locally)
    }
  }

  async function loadPocScore() {
    try {
      const score = await invoke<PocScoreResult>('get_poc_score');
      setPocScore(score);
    } catch { /* ignore */ }
  }

  async function loadP2pStatus() {
    try {
      const s = await invoke<P2pStatus>('get_p2p_status');
      setP2pStatus(s);
    } catch { /* ignore */ }
  }

  async function loadAll() {
    try {
      const [e, m] = await Promise.all([
        invoke<EarningsData>('get_earnings_data'),
        invoke<StorageMetrics>('get_storage_metrics'),
      ]);
      setEarnings(e);
      setStorageMeta(m);

      // Seed the live counter from the already-elapsed session time
      const elapsed = Math.floor(Date.now() / 1000) - e.session_started;
      const perSec  = e.daily_rewards / 86_400;
      setSessionEarned(elapsed * perSec);
      setUptime(elapsed);
    } catch (err) {
      console.error('EarningsPage load failed:', err);
    }
  }

  // 1-second ticker — increments both the session counter and the uptime
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

  // ── Derived values ─────────────────────────────────────────────────────────

  const allocatedGb    = (storageMeta?.storage_allocated_bytes ?? 0) / 1e9;
  const isStorageSetup = allocatedGb > 0;
  const bd             = earnings?.reward_breakdown;
  const totalBuckets   = bd
    ? (bd.storage_rewards + bd.consensus_rewards + bd.coverage_rewards + bd.retrieval_rewards) || 1
    : 1;

  const buckets = bd ? [
    { label: 'Storage',   val: bd.storage_rewards,   color: 'bg-blue-500',   text: 'text-blue-400',   desc: `Up to ${allocatedGb.toFixed(1)} GB × 0.5 EGOC/day when utilized`      },
    { label: 'Consensus', val: bd.consensus_rewards,  color: 'bg-purple-500', text: 'text-purple-400', desc: 'Requires active node participation in BFT rounds'   },
    { label: 'Coverage',  val: bd.coverage_rewards,   color: 'bg-green-500',  text: 'text-green-400',  desc: earnings?.coverage_online ? 'PoC beacon active — reward eligible' : 'Offline — criteria not met' },
    { label: 'Retrieval', val: bd.retrieval_rewards,  color: 'bg-orange-500', text: 'text-orange-400', desc: 'Paid per-GB only when others fetch your stored data' },
  ] : [];

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="p-6 space-y-5 max-w-4xl mx-auto">

      {/* ── "Keep app open" banner ───────────────────────────────────────── */}
      <div className="bg-yellow-500/10 border border-yellow-500/40 rounded-2xl px-5 py-4 flex items-start gap-3">
        <span className="text-2xl shrink-0 mt-0.5">⚠️</span>
        <div>
          <div className="font-semibold text-yellow-300 text-sm">Keep the app open to earn</div>
          <div className="text-xs text-yellow-200/70 mt-0.5">
            Your node earns rewards only while running. Closing the app stops all earnings —
            storage proofs, coverage beacons, and block validation all require an active node.
          </div>
        </div>
        <div className="ml-auto text-right shrink-0">
          <div className="text-xs text-yellow-400/60 mb-0.5">Session uptime</div>
          <div className="font-mono text-sm font-bold text-yellow-300">{fmtDuration(uptime)}</div>
        </div>
      </div>

      {/* ── Storage setup prompt ────────────────────────────────────────── */}
      {!isStorageSetup && (
        <div className="bg-gradient-to-r from-purple-900/50 to-blue-900/50 rounded-2xl border border-purple-500/30 p-5 flex items-center justify-between gap-4">
          <div>
            <div className="font-semibold mb-1">Storage rewards are zero — configure storage first</div>
            <div className="text-sm text-gray-400">
              Share disk space to qualify for up to <span className="text-green-400 font-semibold">0.5 EGOC / GB / day</span> — paid when your space is actually used
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
                {allocatedGb.toFixed(1)} GB · max potential <span className="text-green-300 font-semibold">{(allocatedGb * 0.5).toFixed(3)} EGOC/day</span> (if fully utilized)
              </div>
            </div>
          </div>
          <button onClick={() => navigate('/storage')} className="text-xs text-blue-400 hover:text-blue-300">Manage →</button>
        </div>
      )}

      {/* ── Live session earnings ────────────────────────────────────────── */}
      <div className="bg-gradient-to-br from-green-900/40 to-blue-900/40 border border-green-500/30 rounded-2xl p-5">
        <div className="text-xs text-gray-400 mb-1">Earned this session</div>
        <div className="text-4xl font-black text-green-400 font-mono tabular-nums">
          {fmtEgoc(sessionEarned, 6)} <span className="text-lg text-green-600">EGOC</span>
        </div>
        <div className="text-xs text-gray-500 mt-1">
          Max rate: {fmtEgoc(earnings?.daily_rewards ?? 0, 2)} EGOC/day — actual payout depends on utilisation &amp; criteria
        </div>
      </div>

      {/* ── Summary cards ───────────────────────────────────────────────── */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Max Rate',     val: earnings ? fmtEgoc(earnings.daily_rewards) : '—',   unit: 'EGOC/day (potential)', color: 'text-green-400',  bg: 'bg-green-500/10'  },
          { label: 'Max / Epoch',  val: earnings ? fmtEgoc(earnings.epoch_rewards)  : '—',   unit: '7 days (potential)',   color: 'text-blue-400',   bg: 'bg-blue-500/10'   },
          { label: 'Pending',      val: earnings ? fmtEgoc(earnings.pending_rewards): '—',   unit: 'EGOC',                 color: 'text-yellow-400', bg: 'bg-yellow-500/10' },
          { label: 'Total Earned', val: earnings ? fmtEgoc(earnings.total_earned)   : '—',   unit: 'EGOC',                 color: 'text-purple-400', bg: 'bg-purple-500/10' },
        ].map(c => (
          <div key={c.label} className={`${c.bg} rounded-2xl p-4 border border-white/5`}>
            <div className="text-xs text-gray-400 mb-1">{c.label}</div>
            <div className={`text-xl font-black ${c.color}`}>{c.val}</div>
            <div className="text-xs text-gray-500">{c.unit}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-5 gap-4">

        {/* ── Reward breakdown ──────────────────────────────────────────── */}
        <div className="col-span-3 bg-gray-800 rounded-2xl p-5 border border-gray-700">
          <h3 className="font-semibold mb-1">Potential Reward Breakdown</h3>
          <p className="text-xs text-gray-500 mb-4">Maximum rates — actual payouts require meeting each category's criteria</p>
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
                { label: 'Storage',   desc: 'Allocate space AND have it used by network peers storing data on your node' },
                { label: 'Consensus', desc: 'Node must be online and actively participating in block validation rounds' },
                { label: 'Coverage',  desc: 'PoC beacon must be online and pass geographic proof challenges' },
                { label: 'Retrieval', desc: 'Only paid when other nodes actually request and download data from you' },
              ].map(e => (
                <div key={e.label} className="bg-gray-900 rounded-lg p-2.5">
                  <div className="font-medium text-gray-200">{e.label}</div>
                  <div className="text-gray-500 mt-0.5">{e.desc}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── Right column: node status + options ──────────────────────── */}
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
                <span className="text-gray-400">DRS score (relay)</span>
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

          {/* Create blocks */}
          <div className="bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <h3 className="font-semibold mb-2">Block Production</h3>
            <p className="text-xs text-gray-400 mb-3">
              Every transaction you send mines a new block and earns a block reward.
              Staying online increases your chance of being selected as a BFT validator.
            </p>
            <div className="flex justify-between text-sm mb-1">
              <span className="text-gray-400">Block reward</span>
              <span className="text-green-400 font-bold">50 EGOC</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Consensus</span>
              <span className="text-gray-300">sBFT validator</span>
            </div>
          </div>

        </div>
      </div>

    </div>
  );
};

export default EarningsPage;
