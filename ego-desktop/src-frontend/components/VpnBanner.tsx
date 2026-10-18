import React, { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';

interface NetStatus {
  vpn_detected: boolean;
  vpn_reason: string;
}

export default function VpnBanner() {
  const [status, setStatus] = useState<NetStatus | null>(null);

  useEffect(() => {
    let alive = true;
    const refresh = () =>
      invoke<NetStatus>('get_coverage_status')
        .then(s => { if (alive) setStatus(s); })
        .catch(() => {});
    refresh();
    const timer = setInterval(refresh, 60_000);
    const unlistenVpn = listen('ego://vpn-status-changed', refresh);
    const unlistenCoverage = listen('ego://coverage-updated', refresh);
    return () => {
      alive = false;
      clearInterval(timer);
      unlistenVpn.then(f => f());
      unlistenCoverage.then(f => f());
    };
  }, []);

  if (!status?.vpn_detected) return null;

  return (
    <div className="pointer-events-none fixed bottom-4 left-1/2 -translate-x-1/2 z-[9999] max-w-[92vw] px-4 py-2 rounded-xl bg-red-600/95 text-white text-sm font-semibold shadow-lg shadow-black/40 text-center">
      Your node is paused{status.vpn_reason ? `: ${status.vpn_reason}` : ''}. Turn off any VPN or proxy to run your node and earn. Your wallet still works.
    </div>
  );
}
