import React, { useCallback, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/tauri';

interface GatewayStatus {
  enabled: boolean;
  running: boolean;
  port: number;
  endpoint: string | null;
  cert_sha256: string | null;
  bootstrap_listed: boolean;
  last_announce: number | null;
  reached_from_internet_at: number | null;
  router_port_open: boolean | null;
  router_public_ip: string | null;
  reachable: boolean;
  known_gateways: number;
  problem: string | null;
}

const REACHED_RECENTLY_SECS = 60 * 60;

function ago(ts: number): string {
  const s = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (s < 60) return 'just now';
  if (s < 3_600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86_400) return `${Math.floor(s / 3_600)} h ago`;
  return `${Math.floor(s / 86_400)} d ago`;
}

export default function ServePhones() {
  const [status, setStatus] = useState<GatewayStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const load = useCallback(() => {
    invoke<GatewayStatus>('gateway_status')
      .then(s => { setStatus(s); setError(''); })
      .catch(e => setError(String(e)));
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 5_000);
    return () => clearInterval(t);
  }, [load]);

  async function toggle() {
    if (!status) return;
    setBusy(true);
    try {
      setStatus(await invoke<GatewayStatus>('set_gateway_enabled', { enabled: !status.enabled }));
      setError('');
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  const now = Math.floor(Date.now() / 1000);
  const reached = status?.reached_from_internet_at ?? null;
  const reachable = !!status?.reachable || (reached !== null && now - reached < REACHED_RECENTLY_SECS);
  const on = !!status?.enabled;

  return (
    <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
      <div className="px-5 py-4 border-b border-gray-700 flex items-center justify-between gap-4">
        <div>
          <h3 className="font-semibold">Serve phones</h3>
          <div className="text-xs text-gray-400 mt-0.5 max-w-xl">
            On by default. Ego Wallet on iPhone reaches the network through computers like this one. Phones sign
            everything themselves, so this computer never sees their keys, and each phone is rate limited.
          </div>
        </div>
        <button
          id="settings-serve-phones"
          onClick={toggle}
          disabled={busy || !status}
          aria-pressed={on}
          aria-label="Serve phones"
          className={`w-11 h-6 rounded-full transition-colors relative shrink-0 disabled:opacity-50 ${on ? 'bg-blue-600' : 'bg-gray-600'}`}
        >
          <div className={`w-5 h-5 bg-white rounded-full shadow absolute top-0.5 transition-all ${on ? 'left-5' : 'left-0.5'}`} />
        </button>
      </div>

      {status && on && (
        <div className="px-5 py-4 space-y-3 text-sm">
          {status.problem ? (
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-3 text-red-300">{status.problem}</div>
          ) : !status.running ? (
            <div className="text-gray-400">Starting the gateway…</div>
          ) : null}

          {status.running && (
            <>
              <Row label="Status" value={`Serving on port ${status.port}`} tone="good" />
              <Row
                label="From the internet"
                value={reached !== null
                  ? `${now - reached < REACHED_RECENTLY_SECS ? 'Reached' : 'Last reached'} ${ago(reached)}`
                  : status.reachable
                    ? 'Open through the router'
                    : 'Not reached yet'}
                tone={reachable ? 'good' : 'warn'}
              />
              <Row
                label="Router port"
                value={status.router_port_open === null ? 'Checking…' : status.router_port_open ? 'Opened automatically' : 'Router did not open it'}
                tone={status.router_port_open ? 'good' : status.router_port_open === false ? 'warn' : undefined}
              />
              <Row label="Public address" value={status.endpoint ?? 'Looking up…'} mono />
              <Row
                label="Listed for new phones"
                value={status.bootstrap_listed ? 'Yes' : status.last_announce ? 'Not yet' : 'Announcing…'}
                tone={status.bootstrap_listed ? 'good' : undefined}
              />
              <Row label="Other gateways known" value={String(status.known_gateways)} />
              {status.cert_sha256 && (
                <Row label="Certificate" value={`${status.cert_sha256.slice(0, 16)}…`} mono />
              )}
              {!reachable && (
                <div className="text-xs text-gray-400 leading-relaxed bg-gray-900 rounded-xl p-3">
                  Phones can only use this computer if it can be reached from the internet. Ego Desktop asks the router
                  to open the port by itself. If the router doesn't allow that, forward TCP port {status.port} to this
                  computer by hand. Until then it is not announced, so no phone tries it.
                </div>
              )}
            </>
          )}
        </div>
      )}

      {error && <div className="px-5 pb-4 text-xs text-red-400">{error}</div>}
    </div>
  );
}

function Row({ label, value, tone, mono }: { label: string; value: string; tone?: 'good' | 'warn'; mono?: boolean }) {
  const color = tone === 'good' ? 'text-green-400' : tone === 'warn' ? 'text-yellow-400' : 'text-gray-200';
  return (
    <div className="flex items-center justify-between gap-4">
      <span className="text-gray-400">{label}</span>
      <span className={`${color} ${mono ? 'font-mono text-xs' : ''} text-right break-all`}>{value}</span>
    </div>
  );
}
