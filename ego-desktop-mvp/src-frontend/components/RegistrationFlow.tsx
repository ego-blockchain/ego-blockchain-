import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { fetch as tauriFetch, Body } from '@tauri-apps/api/http';
import { RELAY_HTTP as RELAY } from '../config';

interface Props {
  address: string;
  onComplete: () => void;
}

type Step = 'form' | 'verify_pending' | 'recovery' | 'confirm_written';

const RegistrationFlow: React.FC<Props> = ({ address, onComplete }) => {
  const [step, setStep]         = useState<Step>('form');
  const [name, setName]         = useState('');
  const [email, setEmail]       = useState('');
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState('');
  const [recovery, setRecovery] = useState<string[]>([]);
  const [seedHex, setSeedHex]   = useState('');
  const [showSeed, setShowSeed] = useState(false);
  const [checked, setChecked]   = useState(false);
  const [polling, setPolling]   = useState(false);

  async function handleRegister() {
    if (!name.trim() || !email.trim()) { setError('Please enter your name and email.'); return; }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { setError('Please enter a valid email address.'); return; }
    setLoading(true); setError('');
    try {
      const res = await tauriFetch<{ success: boolean; message: string }>(
        `${RELAY}/users/register`,
        { method: 'POST', body: Body.json({ address, name: name.trim(), email: email.trim() }) }
      );
      const data = res.data;
      if (!data.success) { setError(data.message); return; }
      setStep('verify_pending');
      startPollingVerification();
    } catch (e) {
      setError('Error: ' + String(e));
    } finally {
      setLoading(false);
    }
  }

  function startPollingVerification() {
    setPolling(true);
    const interval = setInterval(async () => {
      try {
        const res  = await tauriFetch<{ email_verified: boolean }>(`${RELAY}/users/${address}`);
        const data = res.data;
        if (data.email_verified) {
          clearInterval(interval);
          setPolling(false);
          await loadRecovery();
        }
      } catch {}
    }, 3000);
    // Stop polling after 15 min
    setTimeout(() => { clearInterval(interval); setPolling(false); }, 15 * 60 * 1000);
  }

  async function loadRecovery() {
    try {
      const info = await invoke<{ recovery_phrase: string[]; seed_hex: string }>(
        'get_recovery_info', { pin: '' }
      );
      setRecovery(info.recovery_phrase);
      setSeedHex(info.seed_hex);
      setStep('recovery');
    } catch (e) {
      setError('Could not load recovery phrase: ' + String(e));
    }
  }

  function handleConfirm() {
    if (!checked) { setError('Please confirm you have written down your recovery phrase.'); return; }
    // Mark registration complete locally
    localStorage.setItem(`ego-registered-${address}`, 'true');
    onComplete();
  }

  // ── Step: Form ──────────────────────────────────────────────────────────────
  if (step === 'form') return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center p-6">
      <div className="w-full max-w-md bg-gray-800 rounded-2xl shadow-2xl overflow-hidden border border-gray-700">
        <div className="px-8 py-6 border-b border-gray-700 bg-gradient-to-br from-blue-900/40 to-purple-900/40">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-2xl font-black mx-auto mb-3 select-none">E</div>
          <h1 className="text-xl font-bold text-white text-center">Welcome to Ego Blockchain</h1>
          <p className="text-sm text-gray-400 mt-1 text-center">Step 1 of 3 — Create Your Account</p>
        </div>
        <div className="px-8 py-6 space-y-5">
          <p className="text-sm text-gray-300 leading-relaxed">
            Enter your name and email address. We'll send you a verification email, then show you your recovery phrase.
          </p>
          <div className="space-y-3">
            <div>
              <label className="text-xs text-gray-400 block mb-1.5">Full Name</label>
              <input
                type="text"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="e.g. John Smith"
                className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none transition text-white"
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1.5">Email Address</label>
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="e.g. john@example.com"
                className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none transition text-white"
                onKeyDown={e => e.key === 'Enter' && handleRegister()}
              />
            </div>
          </div>
          <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl px-4 py-3 text-xs text-blue-300">
            📧 We use your email only for transaction confirmations and account recovery. We never share it.
          </div>
          {error && <div className="bg-red-500/20 text-red-400 text-xs px-3 py-2 rounded-lg">{error}</div>}
          <button
            onClick={handleRegister}
            disabled={loading || !name || !email}
            className="w-full py-3 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 rounded-xl font-semibold text-sm transition"
          >
            {loading ? 'Sending verification…' : 'Continue →'}
          </button>
          <div className="font-mono text-xs text-gray-600 text-center break-all">{address}</div>
        </div>
      </div>
    </div>
  );

  // ── Step: Email verification pending ───────────────────────────────────────
  if (step === 'verify_pending') return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center p-6">
      <div className="w-full max-w-md bg-gray-800 rounded-2xl shadow-2xl overflow-hidden border border-gray-700">
        <div className="px-8 py-6 border-b border-gray-700 bg-gradient-to-br from-blue-900/40 to-purple-900/40">
          <div className="text-5xl text-center mb-3">📧</div>
          <h1 className="text-xl font-bold text-white text-center">Check Your Email</h1>
          <p className="text-sm text-gray-400 mt-1 text-center">Step 2 of 3 — Verify Email</p>
        </div>
        <div className="px-8 py-6 space-y-5">
          <p className="text-sm text-gray-300 leading-relaxed">
            We sent a verification link to <strong className="text-white">{email}</strong>.
            Click the link in that email to continue.
          </p>
          <div className="bg-gray-900 rounded-xl p-4 space-y-2">
            {polling ? (
              <div className="flex items-center gap-3 text-sm text-gray-400">
                <div className="w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin shrink-0" />
                Waiting for verification…
              </div>
            ) : (
              <div className="text-sm text-yellow-400">Verification timed out. Please try again.</div>
            )}
          </div>
          <div className="text-xs text-gray-500 space-y-1">
            <p>• Check your spam/junk folder if you don't see it</p>
            <p>• The link expires in 24 hours</p>
            <p>• Make sure to click the link on any device — the app will detect it automatically</p>
          </div>
          {error && <div className="bg-red-500/20 text-red-400 text-xs px-3 py-2 rounded-lg">{error}</div>}
          <button
            onClick={() => { setStep('form'); setError(''); }}
            className="w-full py-3 bg-gray-700 hover:bg-gray-600 rounded-xl font-semibold text-sm transition text-gray-300"
          >
            ← Back (change email)
          </button>
        </div>
      </div>
    </div>
  );

  // ── Step: Recovery phrase ──────────────────────────────────────────────────
  if (step === 'recovery') return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center p-6">
      <div className="w-full max-w-lg bg-gray-800 rounded-2xl shadow-2xl overflow-hidden border border-gray-700">
        <div className="px-8 py-6 border-b border-gray-700 bg-gradient-to-br from-red-900/40 to-orange-900/40">
          <div className="text-5xl text-center mb-3">🔑</div>
          <h1 className="text-xl font-bold text-white text-center">Your Recovery Phrase</h1>
          <p className="text-sm text-gray-400 mt-1 text-center">Step 3 of 3 — Back Up Your Wallet</p>
        </div>
        <div className="px-8 py-6 space-y-5 max-h-[70vh] overflow-y-auto">
          <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 text-sm text-red-300">
            <strong>⚠️ Critical:</strong> Write these 24 words on paper and store them somewhere safe.
            Anyone with these words can access your wallet. Never store them digitally or share them.
          </div>

          {/* 24 words grid */}
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

          {/* Seed hex */}
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

          {/* Confirm written */}
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