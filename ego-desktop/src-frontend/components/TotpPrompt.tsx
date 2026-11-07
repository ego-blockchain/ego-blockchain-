import React, { useEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { registerTotpAsker, TotpAsk } from '../lib/totp';

const TITLES: Record<string, string> = {
  send: 'Confirm this transaction',
  reveal: 'Confirm it is you',
  pin: 'Confirm the password change',
  export: 'Confirm the backup',
};

const TotpPrompt: React.FC = () => {
  const [ask, setAsk] = useState<TotpAsk | null>(null);
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const first = useRef<HTMLInputElement>(null);

  useEffect(() => {
    registerTotpAsker(a => {
      setAsk(a);
      setPassword('');
      setCode('');
      setError('');
    });
    return () => registerTotpAsker(null);
  }, []);

  useEffect(() => {
    if (ask) setTimeout(() => first.current?.focus(), 50);
  }, [ask]);

  if (!ask) return null;

  const ready = (!ask.password || password.length > 0) && (!ask.code || code.length === 6);

  const close = (ok: boolean) => {
    ask.resolve(ok);
    setAsk(null);
    setPassword('');
    setCode('');
    setError('');
  };

  const submit = async () => {
    if (!ready || busy) return;
    setBusy(true);
    setError('');
    try {
      await invoke('authorize_action', {
        password: ask.password ? password : null,
        code: ask.code ? code : null,
        action: ask.action,
      });
      close(true);
    } catch (e: any) {
      setError(String(e?.message ?? e).replace(/^.*?:\s*/, ''));
      setCode('');
      first.current?.focus();
    } finally {
      setBusy(false);
    }
  };

  const keys = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') submit();
    if (e.key === 'Escape') close(false);
  };

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-[100] p-4 backdrop-blur-sm">
      <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-sm border border-gray-700 shadow-2xl">
        <div className="text-3xl mb-2 text-center">🔐</div>
        <h3 className="text-lg font-bold text-center">{TITLES[ask.action] ?? 'Confirm'}</h3>
        <p className="text-sm text-gray-400 text-center mt-1 mb-4">
          {ask.password && ask.code
            ? 'Enter your wallet password and the 6-digit code from your authenticator app.'
            : ask.password
              ? 'Enter your wallet password.'
              : 'Enter the 6-digit code from your authenticator app.'}
        </p>
        <div className="space-y-3">
          {ask.password && (
            <input
              ref={first}
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              onKeyDown={keys}
              placeholder="Wallet password"
              autoComplete="current-password"
              className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 outline-none"
            />
          )}
          {ask.code && (
            <input
              ref={ask.password ? undefined : first}
              value={code}
              onChange={e => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              onKeyDown={keys}
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="000000"
              className="w-full text-center text-2xl tracking-[0.5em] font-mono bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 outline-none"
            />
          )}
        </div>
        {error && <div className="mt-3 text-xs px-3 py-2 rounded-lg bg-red-500/20 text-red-400">{error}</div>}
        <div className="flex gap-3 mt-5">
          <button onClick={() => close(false)} className="flex-1 bg-gray-700 hover:bg-gray-600 rounded-xl py-2.5 text-sm transition">
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={!ready || busy}
            className="flex-1 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-xl py-2.5 text-sm font-semibold transition"
          >
            {busy ? 'Checking…' : 'Confirm'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default TotpPrompt;
