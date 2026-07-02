import React, { useEffect, useState } from 'react';
import { listen } from '@tauri-apps/api/event';

interface SyncStatus {
  state: 'checking' | 'catching_up' | 'synced';
  local: number;
  target: number;
  after_sleep: boolean;
}

export default function SyncBanner() {
  const [status, setStatus] = useState<SyncStatus | null>(null);
  const [showSynced, setShowSynced] = useState(false);

  useEffect(() => {
    let syncedTimer: ReturnType<typeof setTimeout> | undefined;
    const unlisten = listen<SyncStatus>('ego://sync-status', ({ payload }) => {
      if (payload.state === 'synced') {
        setStatus(prev => {
          if (prev && prev.state !== 'synced') {
            setShowSynced(true);
            clearTimeout(syncedTimer);
            syncedTimer = setTimeout(() => setShowSynced(false), 6000);
          }
          return null;
        });
      } else {
        setShowSynced(false);
        setStatus(payload);
      }
    });
    return () => {
      clearTimeout(syncedTimer);
      unlisten.then(f => f());
    };
  }, []);

  if (showSynced) {
    return (
      <div className="fixed top-10 left-1/2 -translate-x-1/2 z-[9999] flex items-center gap-2 px-4 py-2 rounded-xl bg-emerald-600/95 text-white text-sm font-semibold shadow-lg shadow-black/40">
        <span>✓</span>
        <span>Back in sync — your node is creating blocks again</span>
      </div>
    );
  }

  if (!status) return null;

  const pct =
    status.state === 'catching_up' && status.target > 0 && status.target > status.local
      ? Math.min(100, Math.round((status.local / status.target) * 100))
      : null;

  return (
    <div className="fixed top-10 left-1/2 -translate-x-1/2 z-[9999] flex items-center gap-3 px-4 py-2 rounded-xl bg-amber-500/95 text-black text-sm font-semibold shadow-lg shadow-black/40 whitespace-nowrap">
      <span className="w-3.5 h-3.5 rounded-full border-2 border-black/30 border-t-black animate-spin" />
      {status.state === 'checking' ? (
        <span>Woke from sleep — reconnecting to the network…</span>
      ) : (
        <span>
          Catching up — block {status.local.toLocaleString()} of {status.target.toLocaleString()}
          {pct !== null ? ` (${pct}%)` : ''} · block creation paused
        </span>
      )}
    </div>
  );
}
