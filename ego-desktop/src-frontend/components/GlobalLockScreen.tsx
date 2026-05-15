import React, { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import { appWindow } from '@tauri-apps/api/window';

export function GlobalLockScreen({ children }: { children: React.ReactNode }) {
  const [isLocked, setIsLocked] = useState(true);
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [hasPin, setHasPin] = useState(false);

  const checkLock = useCallback(async () => {
    try {
      const status = await invoke<{ has_pin: boolean }>('get_password_status');
      setHasPin(status.has_pin);
      if (status.has_pin) {
        if (sessionStorage.getItem('ego-unlocked') === 'true') {
          setIsLocked(false);
        } else {
          setIsLocked(true);
        }
      } else {
        setIsLocked(false);
      }
    } catch (e) {
      setIsLocked(false);
    }
  }, []);

  useEffect(() => {
    checkLock();
    const unlisten = listen('ego://app-locked', () => {
      sessionStorage.removeItem('ego-unlocked');
      checkLock();
      setPassword('');
      setError('');
    });
    return () => { unlisten.then(f => f()); };
  }, [checkLock]);

  async function handleUnlock(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const ok = await invoke<boolean>('verify_password', { password });
      if (ok) {
        sessionStorage.setItem('ego-unlocked', 'true');
        setIsLocked(false);
        setPassword('');
      } else {
        setError('Incorrect password');
      }
    } catch (err: any) {
      setError(String(err).replace(/^.*Error:/, '').trim());
    } finally {
      setLoading(false);
    }
  }

  if (!hasPin || !isLocked) return <>{children}</>;

  return (
    <div className="fixed inset-0 z-[99999] flex items-center justify-center bg-gray-900/90 backdrop-blur-xl">
      <form onSubmit={handleUnlock} className="relative bg-gray-800 p-8 rounded-3xl shadow-2xl border border-gray-700 max-w-sm w-full text-center">
        <button
          type="button"
          onClick={() => appWindow.close()}
          className="absolute top-5 right-5 text-gray-500 hover:text-white transition-colors text-xl leading-none"
          title="Close App"
        >
          ✕
        </button>
        <div className="w-16 h-16 bg-blue-500/20 text-blue-400 rounded-full flex items-center justify-center mx-auto mb-5 text-2xl">🔒</div>
        <h2 className="text-2xl font-bold text-white mb-2">Ego Desktop Locked</h2>
        <p className="text-sm text-gray-400 mb-6">Enter your password to continue.</p>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" autoFocus className="w-full bg-gray-900 border border-gray-600 rounded-xl px-4 py-3 text-white mb-4 outline-none focus:border-blue-500 transition" />
        {error && <div className="text-red-400 text-sm mb-4 font-semibold">{error}</div>}
        <button type="submit" disabled={loading || !password} className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-3.5 rounded-xl transition disabled:opacity-50 mb-3">{loading ? 'Unlocking...' : 'Unlock'}</button>
      </form>
    </div>
  );
}