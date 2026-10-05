import React, { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/tauri';

export interface AutostartState {
  enabled: boolean;
  asked: boolean;
  enabled_without_asking: boolean;
}

export default function StartAtLoginBanner() {
  const [state, setState] = useState<AutostartState | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    invoke<AutostartState>('get_autostart_state').then(setState).catch(() => {});
  }, []);

  if (!state || state.asked) return null;

  async function choose(enabled: boolean) {
    setBusy(true);
    setError('');
    try {
      const now = await invoke<boolean>('set_autostart_enabled', { enabled });
      setState({ enabled: now, asked: true, enabled_without_asking: false });
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  const wasOn = state.enabled_without_asking;

  return (
    <div className="bg-gray-800 border-b border-gray-700 px-5 py-3 flex items-center gap-3">
      <div className="min-w-0 flex-1">
        <div className="text-sm font-semibold text-white">
          {wasOn ? 'Ego Desktop starts when you log in' : 'Start Ego Desktop when you log in?'}
        </div>
        <div className="text-xs text-gray-400">
          {wasOn
            ? 'An earlier version turned this on without asking you. Your node only earns while the app runs. Keep it on?'
            : 'Your node only earns while the app runs. You can change this any time in Settings.'}
        </div>
        {error && <div className="text-xs text-red-400 mt-1">{error}</div>}
      </div>
      <button
        onClick={() => choose(true)}
        disabled={busy}
        className="shrink-0 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 px-4 py-1.5 rounded-xl text-xs font-semibold transition-colors"
      >
        {wasOn ? 'Keep it on' : 'Start at login'}
      </button>
      <button
        onClick={() => choose(false)}
        disabled={busy}
        className="shrink-0 bg-gray-700 hover:bg-gray-600 disabled:opacity-50 px-4 py-1.5 rounded-xl text-xs font-semibold transition-colors"
      >
        {wasOn ? 'Turn it off' : 'No thanks'}
      </button>
    </div>
  );
}
