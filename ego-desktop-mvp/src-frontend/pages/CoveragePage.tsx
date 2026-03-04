import React, { useState, useEffect } from 'react';
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

const CoveragePage: React.FC = () => {
  const [coverage, setCoverage] = useState<CoverageStatus | null>(null);
  const [events,   setEvents]   = useState<PocEvent[]>([]);
  const [peers,    setPeers]    = useState<PeerInfo[]>([]);
  const [loading,  setLoading]  = useState(true);

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
    // Refresh peers every 30 s
    const t = setInterval(() => {
      invoke<PeerInfo[]>('get_network_peers').then(setPeers).catch(() => {});
    }, 30_000);
    return () => clearInterval(t);
  }, []);

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

      {/* Live network peers */}
      <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-700 flex items-center justify-between">
          <h3 className="font-semibold">Live Network Nodes</h3>
          <span className="text-xs text-gray-400">
            {peers.length === 0 ? 'No peers seen yet' : `${peers.length} online`}
          </span>
        </div>
        {peers.length === 0 ? (
          <div className="px-5 py-6 text-center text-gray-500 text-sm">
            No other nodes detected.
            Nodes appear here after they send a heartbeat — add them as contacts first.
          </div>
        ) : (
          <div className="divide-y divide-gray-700/50">
            {peers.map(p => (
              <div key={p.address} className="flex items-center justify-between px-5 py-3">
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 rounded-full bg-green-400 shrink-0" />
                  <div>
                    <div className="text-sm font-medium">{p.name || 'Unknown'}</div>
                    <div className="text-xs text-gray-500 font-mono">
                      {p.address.length > 18 ? p.address.slice(0, 10) + '…' + p.address.slice(-6) : p.address}
                    </div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-xs text-gray-400 font-mono">{p.endpoint}</div>
                  <div className="text-xs text-gray-500">{timeAgo(p.last_seen)}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="grid grid-cols-5 gap-4">
        {/* PoC event log */}
        <div className="col-span-3 bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
          <div className="px-5 py-4 border-b border-gray-700">
            <h3 className="font-semibold">PoC Event Log</h3>
          </div>
          <div className="divide-y divide-gray-700/50 max-h-96 overflow-y-auto">
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
