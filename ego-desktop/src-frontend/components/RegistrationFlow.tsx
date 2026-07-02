import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/tauri';

interface Props {
  address: string;
  onComplete: () => void;
}

type Step = 'form' | 'recovery';

const RegistrationFlow: React.FC<Props> = ({ address, onComplete }) => {
  const [step, setStep]         = useState<Step>('form');
  const [name, setName]         = useState('');
  const [pwd, setPwd]           = useState('');
  const [pwd2, setPwd2]         = useState('');
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState('');
  const [recovery, setRecovery] = useState<string[]>([]);
  const [seedHex, setSeedHex]   = useState('');
  const [showSeed, setShowSeed] = useState(false);
  const [checked, setChecked]   = useState(false);

  async function handleCreateAccount() {
    if (!name.trim()) { setError('Please enter your name.'); return; }
    if (pwd.length < 8) { setError('Password must be at least 8 characters.'); return; }
    if (pwd !== pwd2)   { setError('Passwords do not match.'); return; }

    setLoading(true); setError('');
    try {
      await invoke('set_password', { password: pwd });
      if (name.trim()) localStorage.setItem('ego-my-display-name', name.trim());

      const info = await invoke<{ recovery_phrase: string[]; seed_hex: string }>(
        'get_recovery_info', { pin: pwd }
      );
      setRecovery(info.recovery_phrase);
      setSeedHex(info.seed_hex);
      setStep('recovery');
    } catch (e) {
      setError('Failed to create account: ' + String(e));
    } finally {
      setLoading(false);
    }
  }

  function handleConfirm() {
    if (!checked) { setError('Please confirm you have written down your recovery phrase.'); return; }
    localStorage.setItem('ego-registered-account', 'true');
    localStorage.setItem(`ego-registered-${address}`, 'true');
    sessionStorage.setItem('ego-unlocked', 'true');
    if (name.trim()) localStorage.setItem('ego-my-display-name', name.trim());
    onComplete();
  }

  if (step === 'form') return (
    <div className="min-h-full bg-gray-900 flex items-center justify-center p-6">
      <div className="w-full max-w-md bg-gray-800 rounded-2xl shadow-2xl overflow-hidden border border-gray-700">
        <div className="px-8 py-6 border-b border-gray-700 bg-gradient-to-br from-blue-900/40 to-purple-900/40">
          <img src="/ego_logo.png" alt="Ego" className="w-20 h-20 mx-auto mb-3 select-none rounded-full" draggable={false} />
          <h1 className="text-xl font-bold text-white text-center">Welcome to Ego Blockchain</h1>
          <p className="text-sm text-gray-400 mt-1 text-center">Step 1 of 2 — Create Your Account</p>
        </div>
        <div className="px-8 py-6 space-y-5">
          <p className="text-sm text-gray-300 leading-relaxed">
            Choose a display name and a password. Your password protects your private keys on this device
            and confirms transactions. If you forget it, you can reset it using your 24-word recovery phrase.
          </p>
          <div className="space-y-3">
            <div>
              <label className="text-xs text-gray-400 block mb-1.5">Display Name</label>
              <input
                type="text"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="e.g. John Smith"
                className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none transition text-white"
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1.5">Password</label>
              <input
                type="password"
                value={pwd}
                onChange={e => setPwd(e.target.value)}
                placeholder="At least 8 characters"
                className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none transition text-white"
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1.5">Confirm Password</label>
              <input
                type="password"
                value={pwd2}
                onChange={e => setPwd2(e.target.value)}
                placeholder="Re-enter the password"
                className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none transition text-white"
                onKeyDown={e => e.key === 'Enter' && !loading && handleCreateAccount()}
              />
            </div>
          </div>
          <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl px-4 py-3 text-xs text-blue-300">
            🔒 Your password is hashed with Argon2id and stored only on this device. We never see it.
          </div>
          {error && <div className="bg-red-500/20 text-red-400 text-xs px-3 py-2 rounded-lg">{error}</div>}
          <button
            onClick={handleCreateAccount}
            disabled={loading || !name || !pwd || !pwd2}
            className="w-full py-3 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 rounded-xl font-semibold text-sm transition"
          >
            {loading ? 'Creating account…' : 'Create Account →'}
          </button>
          <div className="font-mono text-xs text-gray-600 text-center break-all">{address}</div>
        </div>
      </div>
    </div>
  );

  if (step === 'recovery') return (
    <div className="min-h-full bg-gray-900 flex items-center justify-center p-6">
      <div className="w-full max-w-lg bg-gray-800 rounded-2xl shadow-2xl overflow-hidden border border-gray-700">
        <div className="px-8 py-6 border-b border-gray-700 bg-gradient-to-br from-red-900/40 to-orange-900/40">
          <div className="text-5xl text-center mb-3">🔑</div>
          <h1 className="text-xl font-bold text-white text-center">Your Recovery Phrase</h1>
          <p className="text-sm text-gray-400 mt-1 text-center">Step 2 of 2 — Back Up Your Wallet</p>
        </div>
        <div className="px-8 py-6 space-y-5">
          <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 text-sm text-red-300">
            <strong>⚠️ Critical:</strong> Write these 24 words on paper and store them somewhere safe.
            Anyone with these words can access your wallet — and they're also your only way to reset
            your password if you forget it. Never store them digitally or share them.
          </div>

          <div>
            <div className="text-sm font-semibold mb-3 text-white">24-Word Recovery Phrase</div>
            <div className="grid grid-cols-4 gap-2">
              {recovery.map((word, i) => (
                <div key={i} className="bg-gray-900 rounded-lg px-2 py-2 text-center border border-gray-700">
                  <div className="text-gray-500 text-xs">{i + 1}</div>
                  <div className="font-mono text-xs font-semibold text-green-400 mt-0.5">{word}</div>
                </div>
              ))}
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="text-sm font-semibold text-white">Raw Seed (hex)</div>
              <button onClick={() => setShowSeed(v => !v)} className="text-xs text-blue-400 hover:text-blue-300">
                {showSeed ? 'Hide' : 'Show'}
              </button>
            </div>
            {showSeed ? (
              <div className="bg-gray-900 rounded-xl p-3 font-mono text-xs text-yellow-400 break-all border border-gray-700 select-all">
                {Array.from({ length: 8 }, (_, i) => seedHex.slice(i * 8, i * 8 + 8)).join(' ')}
              </div>
            ) : (
              <div className="bg-gray-900 rounded-xl p-3 text-center text-gray-500 text-sm border border-gray-700">
                Click Show to reveal
              </div>
            )}
          </div>

          <label className="flex items-start gap-3 cursor-pointer group">
            <div className="relative shrink-0 mt-0.5">
              <input type="checkbox" checked={checked} onChange={e => setChecked(e.target.checked)} className="sr-only" />
              <div className={`w-5 h-5 rounded-md border-2 flex items-center justify-center transition-colors ${
                checked ? 'bg-blue-600 border-blue-600' : 'bg-gray-700 border-gray-500 group-hover:border-gray-400'
              }`}>
                {checked && (
                  <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                )}
              </div>
            </div>
            <span className="text-sm text-gray-300 leading-relaxed">
              I have written down my recovery phrase and seed, and stored them in a safe place offline.
              I understand that losing these means losing access to my wallet permanently.
            </span>
          </label>

          {error && <div className="bg-red-500/20 text-red-400 text-xs px-3 py-2 rounded-lg">{error}</div>}

          <button
            onClick={handleConfirm}
            disabled={!checked}
            className="w-full py-3 bg-green-600 hover:bg-green-500 disabled:opacity-40 rounded-xl font-semibold text-sm transition"
          >
            ✓ I've Written It Down — Enter Ego Desktop
          </button>
        </div>
      </div>
    </div>
  );

  return null;
};

export default RegistrationFlow;
