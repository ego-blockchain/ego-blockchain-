import React, { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/tauri';

const DISMISS_KEY = 'ego.phoneAccess.dismissed';

function dismissed(): boolean {
  try { return localStorage.getItem(DISMISS_KEY) === '1'; } catch { return false; }
}

function remember() {
  try { localStorage.setItem(DISMISS_KEY, '1'); } catch { }
}

export default function PhoneAccessBanner() {
  const [needed, setNeeded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [hidden, setHidden] = useState(dismissed());

  useEffect(() => {
    invoke<{ needed: boolean; port: number }>('get_phone_access')
      .then(r => setNeeded(r.needed))
      .catch(() => {});
  }, []);

  if (!needed || hidden) return null;

  async function allow() {
    setBusy(true);
    setMsg('');
    try {
      await invoke('allow_phone_access');
      setMsg('Done. Phones on your Wi-Fi can now reach this computer.');
      setTimeout(() => setNeeded(false), 4000);
    } catch (e) {
      setMsg(`${String(e).replace(/^.*Error:/, '').trim()}. You can try again any time.`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="bg-blue-500/10 border border-blue-500/30 rounded-2xl p-4 space-y-2">
      <div className="font-semibold text-sm">Let the Ego iPhone app reach this computer</div>
      <p className="text-xs text-gray-300 leading-relaxed">
        Windows is blocking phones on your Wi-Fi from connecting to Ego Desktop, so the iPhone app can't show this
        computer's earnings or use it to reach the network. Press Allow and answer Yes when Windows asks.
      </p>
      <div className="flex gap-2">
        <button onClick={allow} disabled={busy} className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 disabled:opacity-50">
          {busy ? 'Waiting for Windows…' : 'Allow'}
        </button>
        <button onClick={() => { remember(); setHidden(true); }} className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-gray-700 hover:bg-gray-600">
          Not now
        </button>
      </div>
      {msg && <div className="text-xs text-gray-200">{msg}</div>}
    </div>
  );
}
