import React, { useState, useEffect, useRef } from 'react';
import { invoke } from '@tauri-apps/api/tauri';

interface Location {
  latitude: number;
  longitude: number;
  accuracy?: number;
  altitude?: number;
  city?: string;
  region?: string;
  country?: string;
}

interface CoverageStatus {
  location?: Location;
  coverage_synced_count: number;
  last_coverage_event?: number;
  is_online: boolean;
  network_quality: string;
  vpn_detected: boolean;
  vpn_reason: string;
  machine_id: string;
}

interface PeerInfo {
  address:   string;
  name:      string;
  endpoint:  string;
  last_seen: number;
  city?:    string;
  country?: string;
}

// Extract the libp2p peer ID from a multiaddr endpoint string.
// e.g. ".../p2p/12D3KooWAbc..." → "12D3KooWAbc..."
function extractPeerId(endpoint: string): string {
  const m = endpoint.match(/\/p2p\/([A-Za-z0-9]+)$/);
  return m ? m[1] : endpoint;
}

// Short display: first 8 + last 6 chars of peer ID
function shortPeerId(id: string): string {
  if (id.length <= 16) return id;
  return id.slice(0, 8) + '…' + id.slice(-6);
}

interface PocEvent {
  id: number;
  timestamp: number;
  quality: string;
  peers: number;
  reward_uegoc: number;
  h3_cell?: string;
}

function timeAgo(ts: number) {
  const diff = Math.floor(Date.now() / 1000 - ts);
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

function qualityBadge(q: string) {
  if (q === 'Excellent') return 'text-green-400 bg-green-500/15';
  if (q === 'Good')      return 'text-blue-400 bg-blue-500/15';
  if (q === 'Fair')      return 'text-yellow-400 bg-yellow-500/15';
  return 'text-red-400 bg-red-500/15';
}

function fmtCoord(lat: number, lon: number): string {
  const latDir = lat >= 0 ? 'N' : 'S';
  const lonDir = lon >= 0 ? 'E' : 'W';
  return `${Math.abs(lat).toFixed(4)}°${latDir}, ${Math.abs(lon).toFixed(4)}°${lonDir}`;
}

// Derive a deterministic pseudo-H3 cell id from coordinates
function deriveH3Cell(lat: number, lon: number): string {
  const a = Math.abs(Math.round(lat * 1000));
  const b = Math.abs(Math.round(lon * 1000));
  const n = (a * 180000 + b) >>> 0;
  return `892${n.toString(16).padStart(9, '0').slice(-9)}ff`;
}

function locationLabel(loc: Location): string {
  const parts = [loc.city, loc.region, loc.country].filter(Boolean);
  return parts.length > 0 ? parts.join(', ') : 'Unknown';
}

interface P2pStatus {
  public_endpoint: string;
}

interface CombinedDrs {
  address:        string;
  combined_score: number;
  poc_events_24h: number;
  poc_total:      number;
  post_sectors:   number;
  post_windows:   number;
  post_faults:    number;
  staked_uegoc:   number;
  validator_rank: number | null;
  is_eligible:    boolean;
}

function drsColor(score: number) {
  if (score >= 2)   return 'text-green-400';
  if (score >= 0.5) return 'text-yellow-400';
  return 'text-red-400';
}

const CoveragePage: React.FC = () => {
  const [coverage,   setCoverage]   = useState<CoverageStatus | null>(null);
  const [events,     setEvents]     = useState<PocEvent[]>([]);
  const [peers,      setPeers]      = useState<PeerInfo[]>([]);
  const eventLogRef = useRef<HTMLDivElement>(null);
  const [p2pStatus,  setP2pStatus]  = useState<P2pStatus | null>(null);
  const [drs,        setDrs]        = useState<CombinedDrs | null>(null);
  const [loading,    setLoading]    = useState(true);

  useEffect(() => {
    invoke<CoverageStatus>('get_coverage_status')
      .then(setCoverage)
      .catch(() => {})
      .finally(() => setLoading(false));
    invoke<PocEvent[]>('get_poc_events')
      .then(setEvents)
      .catch(() => {});
    invoke<PeerInfo[]>('get_network_peers')
      .then(setPeers)
      .catch(() => {});
    invoke<P2pStatus>('get_p2p_status')
      .then(setP2pStatus)
      .catch(() => {});
    invoke<CombinedDrs>('get_combined_drs')
      .then(setDrs)
      .catch(() => {});
    // Refresh peers + DRS every 60 s
    const t = setInterval(() => {
      invoke<PeerInfo[]>('get_network_peers').then(setPeers).catch(() => {});
      invoke<CombinedDrs>('get_combined_drs').then(setDrs).catch(() => {});
    }, 60_000);
    return () => clearInterval(t);
  }, []);

  // Auto-scroll event log to bottom whenever new events arrive
  useEffect(() => {
    if (eventLogRef.current) {
      eventLogRef.current.scrollTop = eventLogRef.current.scrollHeight;
    }
  }, [events]);


  const quality    = coverage?.network_quality ?? 'Excellent';
  const synced     = coverage?.coverage_synced_count ?? 0;
  const online     = coverage?.is_online ?? false;
  const vpn        = coverage?.vpn_detected ?? false;
  const vpnReason  = coverage?.vpn_reason ?? '';
  const machineId  = coverage?.machine_id ?? '';
  const loc        = coverage?.location;
  const h3Cell     = loc ? deriveH3Cell(loc.latitude, loc.longitude) : null;
  const coordStr   = loc ? fmtCoord(loc.latitude, loc.longitude) : null;
  const cityStr    = loc ? locationLabel(loc) : null;

  // My own peer ID derived from my relay circuit endpoint
  const myPeerId = p2pStatus?.public_endpoint
    ? extractPeerId(p2pStatus.public_endpoint)
    : '';

  // Only show peers that have shared their location
  const visiblePeers = peers.filter(p => p.city || p.country);

  const nowTs      = Math.floor(Date.now() / 1000);
  const todayStart = Math.floor(new Date().setHours(0, 0, 0, 0) / 1000);
  const events24h  = events.filter(e => e.timestamp >= nowTs - 86400);
  const todayRewardsUegoc = events
    .filter(e => e.timestamp >= todayStart)
    .reduce((sum, e) => sum + e.reward_uegoc, 0);
  const todayRewardsStr = online || todayRewardsUegoc > 0
    ? `${(todayRewardsUegoc / 1_000_000).toFixed(4)} EGOC`
    : '—';

  return (
    <div className="p-6 space-y-5 max-w-4xl mx-auto">

      {/* VPN / proxy warning — shown above everything else */}
      {vpn && (
        <div className="rounded-2xl p-4 border border-red-500/50 bg-red-500/10 flex items-start gap-3">
          <div className="text-2xl shrink-0">🚫</div>
          <div className="flex-1 min-w-0">
            <div className="font-bold text-red-400 text-sm">VPN / Proxy Detected — Coverage Paused</div>
            <div className="text-xs text-red-300/80 mt-0.5 leading-relaxed">
              Proof-of-Coverage rewards require a real residential or business IP address.
              VPNs, proxies, and datacenter IPs are not eligible and have been blocked to
              prevent location spoofing.
            </div>
            {vpnReason && (
              <div className="mt-2 text-xs font-mono text-red-400/70 bg-red-900/20 rounded-lg px-3 py-1.5 break-all">
                Reason: {vpnReason}
              </div>
            )}
            <div className="mt-2 text-xs text-red-300/60">
              Disable your VPN and restart the app to resume earning coverage rewards.
            </div>
          </div>
        </div>
      )}

      {/* Status banner */}
      <div className={`rounded-2xl p-5 border flex items-center justify-between ${
        online ? 'bg-green-500/10 border-green-500/30' : 'bg-red-500/10 border-red-500/30'
      }`}>
        <div className="flex items-center gap-4">
          <div className={`w-14 h-14 rounded-2xl flex items-center justify-center text-3xl ${
            online ? 'bg-green-500/20' : 'bg-red-500/20'
          }`}>
            📡
          </div>
          <div>
            <div className="text-lg font-bold">{online ? 'Coverage Active' : 'Coverage Offline'}</div>
            <div className="text-sm text-gray-400">
              PoC beacon · Quality: <span className={qualityBadge(quality).split(' ')[0]}>{quality}</span>
            </div>
          </div>
        </div>
        <div className="text-right">
          <div className="text-3xl font-black text-green-400">{synced}</div>
          <div className="text-xs text-gray-400">witnesses synced</div>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Today PoC Rewards', val: todayRewardsStr,                                       color: 'text-green-400'  },
          { label: 'Events (24h)',       val: `${events24h.length}`,                                 color: 'text-blue-400'   },
          { label: 'Active Nodes',       val: `${peers.length}`,                                     color: 'text-purple-400' },
          { label: 'H3 Cell',            val: h3Cell ? h3Cell.slice(0, 8) + '…' : '—',              color: 'text-orange-400' },
        ].map(c => (
          <div key={c.label} className="bg-gray-800 rounded-2xl p-4 border border-gray-700">
            <div className="text-xs text-gray-400 mb-1">{c.label}</div>
            <div className={`text-xl font-bold ${c.color}`}>{c.val}</div>
          </div>
        ))}
      </div>

      {/* DRS Breakdown */}
      <div className="bg-gray-800 rounded-2xl p-5 border border-gray-700">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-semibold">Deterministic Reward Scoring</h3>
          <div className="flex items-center gap-2">
            {drs?.validator_rank != null && (
              <span className="text-xs bg-purple-500/20 text-purple-400 px-2.5 py-0.5 rounded-full font-medium">
                Rank #{drs.validator_rank}
              </span>
            )}
            <span className={`text-xs px-2.5 py-0.5 rounded-full font-semibold ${
              drs?.is_eligible
                ? 'bg-green-500/20 text-green-400'
                : (drs?.combined_score ?? 0) >= 0.5
                  ? 'bg-yellow-500/20 text-yellow-400'
                  : 'bg-gray-600/30 text-gray-400'
            }`}>
              {drs?.is_eligible ? '✓ Mining Eligible' : (drs?.combined_score ?? 0) >= 0.5 ? '◑ Validator' : 'Building Score'}
            </span>
          </div>
        </div>

        <div className="grid grid-cols-4 gap-4">
          {/* Big score */}
          <div className="col-span-1 flex flex-col justify-center">
            <div className={`text-5xl font-black tabular-nums ${drsColor(drs?.combined_score ?? 0)}`}>
              {(drs?.combined_score ?? 0).toFixed(2)}
            </div>
            <div className="text-xs text-gray-500 mt-1">combined DRS</div>
            <div className="mt-3 h-1.5 bg-gray-700 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${drsColor(drs?.combined_score ?? 0).replace('text-', 'bg-')}`}
                style={{ width: `${Math.min(100, ((drs?.combined_score ?? 0) / 5) * 100)}%` }}
              />
            </div>
            <div className="text-xs text-gray-600 mt-1">0 — 5+ scale</div>
          </div>

          {/* Three signal columns */}
          <div className="col-span-3 grid grid-cols-3 gap-3">
            {/* PoC */}
            <div className="bg-gray-900 rounded-xl p-4 border border-gray-700/50">
              <div className="text-xs text-gray-400 mb-2 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-blue-500 inline-block"/>
                PoC Coverage <span className="text-gray-600">(40%)</span>
              </div>
              <div className="text-2xl font-bold text-blue-400">{drs?.poc_events_24h ?? 0}</div>
              <div className="text-xs text-gray-500">events / 24 h</div>
              <div className="mt-2 text-xs text-gray-500">
                {drs?.poc_total ?? 0} total events
              </div>
            </div>
            {/* PoST */}
            <div className="bg-gray-900 rounded-xl p-4 border border-gray-700/50">
              <div className="text-xs text-gray-400 mb-2 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-purple-500 inline-block"/>
                PoST Storage <span className="text-gray-600">(40%)</span>
              </div>
              <div className="text-2xl font-bold text-purple-400">{drs?.post_sectors ?? 0}</div>
              <div className="text-xs text-gray-500">active sectors</div>
              <div className="mt-2 text-xs text-gray-500">
                {drs?.post_windows ?? 0} windows proved
                {(drs?.post_faults ?? 0) > 0 && (
                  <span className="text-red-400 ml-1">· {drs!.post_faults} faults</span>
                )}
              </div>
            </div>
            {/* Stake */}
            <div className="bg-gray-900 rounded-xl p-4 border border-gray-700/50">
              <div className="text-xs text-gray-400 mb-2 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-orange-500 inline-block"/>
                Stake Weight <span className="text-gray-600">(20%)</span>
              </div>
              <div className="text-2xl font-bold text-orange-400">
                {drs ? (drs.staked_uegoc / 1_000_000).toLocaleString(undefined, { maximumFractionDigits: 0 }) : 0}
              </div>
              <div className="text-xs text-gray-500">EGOC staked</div>
              <div className="mt-2">
                <div className="h-1 bg-gray-700 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-orange-500 rounded-full"
                    style={{ width: `${Math.min(100, ((drs?.staked_uegoc ?? 0) / 1_000_000_000) * 100)}%` }}
                  />
                </div>
                <div className="text-xs text-gray-600 mt-0.5">min 1 000 EGOC to mine</div>
              </div>
            </div>
          </div>
        </div>

        {!drs?.is_eligible && (
          <div className="mt-4 bg-gray-900 rounded-xl p-3 text-xs text-gray-400 space-y-1">
            {(drs?.combined_score ?? 0) < 0.5 && (
              <div>• DRS {(drs?.combined_score ?? 0).toFixed(3)} &lt; 0.5 — send more PoC beacons, store files, or increase stake</div>
            )}
            {(drs?.staked_uegoc ?? 0) < 1_000_000_000 && (
              <div>• Stake {(1000 - (drs?.staked_uegoc ?? 0) / 1_000_000).toFixed(0)} more EGOC to meet the 1 000 EGOC mining minimum</div>
            )}
          </div>
        )}
      </div>

      {/* Live network peers */}
      <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-700 flex items-center justify-between">
          <h3 className="font-semibold">Live Network Nodes</h3>
          <span className="text-xs text-gray-400">
            {`${visiblePeers.length + (myPeerId ? 1 : 0)} online`}
          </span>
        </div>
        <div className="divide-y divide-gray-700/50">
          {/* Own node — always shown at the top */}
          {myPeerId && (
            <div className="flex items-center gap-4 px-5 py-3">
              <div className="w-2 h-2 rounded-full bg-blue-400 shrink-0" />
              <div className="font-mono text-sm text-gray-200">
                {shortPeerId(myPeerId)}
              </div>
              <span className="text-xs bg-blue-500/20 text-blue-400 px-2 py-0.5 rounded-full font-medium">
                me
              </span>
              <div className="text-xs text-gray-400 ml-auto">
                {cityStr ?? '—'}
              </div>
            </div>
          )}
          {/* Other nodes — only shown if they shared location data */}
          {visiblePeers.length === 0 && !myPeerId ? (
            <div className="px-5 py-6 text-center text-gray-500 text-sm">
              No other nodes detected.
              Nodes appear here after they send a heartbeat.
            </div>
          ) : visiblePeers.map(p => {
            const peerId   = extractPeerId(p.endpoint);
            const location = [p.city, p.country].filter(Boolean).join(', ') || p.name || '—';
            return (
              <div key={p.address} className="flex items-center gap-4 px-5 py-3">
                <div className="w-2 h-2 rounded-full bg-green-400 shrink-0" />
                <div className="font-mono text-sm text-gray-200">
                  {shortPeerId(peerId)}
                </div>
                <div className="text-xs text-gray-400 ml-auto">
                  {location}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="grid grid-cols-5 gap-4">
        {/* PoC event log */}
        <div className="col-span-3 bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
          <div className="px-5 py-4 border-b border-gray-700">
            <h3 className="font-semibold">PoC Event Log</h3>
          </div>
          <div ref={eventLogRef} className="divide-y divide-gray-700/50 max-h-96 overflow-y-auto">
            {events.length === 0 ? (
              <div className="px-5 py-8 text-center text-gray-500 text-sm">
                {online ? 'First event will appear in ~4 minutes…' : 'No events — coverage is offline'}
              </div>
            ) : events.map(ev => (
              <div key={ev.id} className="flex items-center justify-between px-5 py-3">
                <div className="flex items-center gap-3">
                  <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${qualityBadge(ev.quality)}`}>
                    {ev.quality}
                  </span>
                  <div>
                    <div className="text-xs text-gray-300">
                      {ev.peers > 0 ? `${ev.peers} peers witnessed` : 'Self-attested (solo node)'}
                    </div>
                    {ev.h3_cell && <div className="text-xs text-gray-500 font-mono">H3: {ev.h3_cell}</div>}
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-sm font-semibold text-green-400">
                    +{(ev.reward_uegoc / 1_000_000).toFixed(4)} EGOC
                  </div>
                  <div className="text-xs text-gray-500">{timeAgo(ev.timestamp)}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right column */}
        <div className="col-span-2 space-y-4">
          <div className="bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <h3 className="font-semibold mb-4">Location</h3>
            <div className="bg-gray-900 rounded-xl p-4 mb-3 flex items-center justify-center min-h-[7rem]">
              {loading ? (
                <div className="text-gray-500 text-sm animate-pulse">Detecting location…</div>
              ) : loc ? (
                <div className="text-center">
                  <div className="text-3xl mb-2">📍</div>
                  <div className="text-sm font-mono text-gray-300">{coordStr}</div>
                  <div className="text-xs text-gray-400 mt-1">{cityStr}</div>
                </div>
              ) : (
                <div className="text-center text-gray-500">
                  <div className="text-3xl mb-1">🌐</div>
                  <div className="text-xs">Location unavailable</div>
                  <div className="text-xs text-gray-600 mt-1">Check internet connection</div>
                </div>
              )}
            </div>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-400">Coordinates</span>
                <span className="font-mono text-xs">{coordStr ?? '—'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">City</span>
                <span>{loc?.city ?? '—'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Country</span>
                <span>{loc?.country ?? '—'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">H3 Cell</span>
                <span className="font-mono text-xs">{h3Cell ?? '—'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Source</span>
                <span className="text-gray-500 text-xs">IP geolocation</span>
              </div>
              <div className="flex justify-between items-center pt-1 border-t border-gray-700/50 mt-1">
                <span className="text-gray-400">VPN / Proxy</span>
                <span className={`text-xs font-semibold ${vpn ? 'text-red-400' : 'text-green-400'}`}>
                  {vpn ? '⚠ Detected' : '✓ None'}
                </span>
              </div>
              {machineId && (
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Machine ID</span>
                  <span className="font-mono text-xs text-gray-500 truncate max-w-[120px]" title={machineId}>
                    {machineId.slice(0, 16)}{machineId.length > 16 ? '…' : ''}
                  </span>
                </div>
              )}
            </div>
          </div>

          <div className="bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <h3 className="font-semibold mb-4">Beacon Settings</h3>
            <div className="space-y-3 text-sm">
              {[
                { label: 'Beacon rate',  val: '1 Hz',  note: 'Batched off-peak' },
                { label: 'Interface',    val: 'Wi-Fi', note: 'Cellular-safe on'  },
                { label: 'Auto-disable', val: 'On',    note: 'On cellular cap'   },
              ].map(s => (
                <div key={s.label} className="flex justify-between items-start">
                  <div>
                    <div className="text-gray-300">{s.label}</div>
                    <div className="text-xs text-gray-500">{s.note}</div>
                  </div>
                  <span className="text-blue-400 font-medium">{s.val}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CoveragePage;
