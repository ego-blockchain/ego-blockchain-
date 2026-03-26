import React, { useState, useMemo, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { open as openUrl } from '@tauri-apps/api/shell';
import { fetch as tauriFetch, Body } from '@tauri-apps/api/http';
import { useWallet } from '../App';
import qrcode from 'qrcode-generator';

import { RELAY_HTTP as RELAY } from '../config';

function makeQR(text: string): string {
  if (!text) return '';
  try {
    const qr = qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    return qr.createDataURL(3, 0);
  } catch { return ''; }
}

interface RecoveryInfo {
  recovery_phrase: string[];
  seed_hex: string;
  address: string;
  has_pin: boolean;
}

const SettingsPage: React.FC = () => {
  const { wallet } = useWallet();
  const [notifications, setNotifications]     = useState(true);
  const [autoStart, setAutoStart]             = useState(true);
  const [minimizeToTray, setMinimizeToTray]   = useState(true);
  const [saved, setSaved]                     = useState(false);

  const [hasPin, setHasPin]                   = useState(false);
  const [showSetPin, setShowSetPin]           = useState(false);
  const [pinInput, setPinInput]               = useState('');
  const [pinConfirm, setPinConfirm]           = useState('');
  const [pinMsg, setPinMsg]                   = useState('');
  const [settingPin, setSettingPin]           = useState(false);
  const [biometricLoading, setBiometricLoading] = useState(false);

  const [resetSent, setResetSent]             = useState(false);
  const [resetLoading, setResetLoading]       = useState(false);
  const [resetMsg, setResetMsg]               = useState('');
  const [maskedEmail, setMaskedEmail]         = useState('');

  const [showChangeEmail, setShowChangeEmail] = useState(false);
  const [emailStep, setEmailStep]             = useState<'send_code' | 'enter_code' | 'new_email' | 'done'>('send_code');
  const [emailCode, setEmailCode]             = useState('');
  const [emailVerifyToken, setEmailVerifyToken] = useState('');
  const [newEmail, setNewEmail]               = useState('');
  const [changeEmailMsg, setChangeEmailMsg]   = useState('');
  const [sendingEmailCode, setSendingEmailCode] = useState(false);
  const [verifyingCode, setVerifyingCode]     = useState(false);
  const [changingEmail, setChangingEmail]     = useState(false);

  const [showRecovery, setShowRecovery]       = useState(false);
  const [recoveryPin, setRecoveryPin]         = useState('');
  const [recoveryInfo, setRecoveryInfo]       = useState<RecoveryInfo | null>(null);
  const [recoveryError, setRecoveryError]     = useState('');
  const [loadingRecovery, setLoadingRecovery] = useState(false);
  const [showSeedHex, setShowSeedHex]         = useState(false);

  const addressQR = useMemo(() => makeQR(wallet?.address ?? ''), [wallet?.address]);

  useEffect(() => {
    console.log('[Settings] wallet address:', wallet?.address);
    invoke<{ has_pin: boolean }>('get_pin_status')
      .then(s => { console.log('[Settings] pin status:', s); setHasPin(s.has_pin); })
      .catch((e) => console.error('[Settings] pin status error:', e));
    invoke<string>('get_account_email')
      .then(e => { if (e) setMaskedEmail(e); })
      .catch(() => {});
  }, [wallet?.address]);

useEffect(() => {
  if (!resetSent || !wallet?.address) return;
  const interval = setInterval(async () => {
    try {
      const res = await tauriFetch<{ confirmed: boolean; new_pin?: string }>(
        `${RELAY}/users/pin-reset-status/${wallet.address}`
      );
      if (res.data.confirmed && res.data.new_pin) {
        clearInterval(interval);

        await invoke('set_security_pin', { pin: res.data.new_pin });
        setHasPin(true);
        setResetSent(false);
        setResetMsg('');
        setShowSetPin(false);

        setPinMsg('✅ PIN updated successfully from email!');
        setTimeout(() => setPinMsg(''), 3000);
      }
    } catch {}
  }, 3000);
  return () => clearInterval(interval);
}, [resetSent, wallet?.address]);

  const Toggle: React.FC<{ value: boolean; onChange: (v: boolean) => void }> = ({ value, onChange }) => (
    <button
      onClick={() => onChange(!value)}
      className={`w-11 h-6 rounded-full transition-colors relative ${value ? 'bg-blue-600' : 'bg-gray-600'}`}
    >
      <div className={`w-5 h-5 bg-white rounded-full shadow absolute top-0.5 transition-all ${value ? 'left-5' : 'left-0.5'}`} />
    </button>
  );

  async function handleSetPin() {
    if (pinInput.length < 4) { setPinMsg('PIN must be at least 4 characters.'); return; }
    if (pinInput !== pinConfirm) { setPinMsg('PINs do not match.'); return; }
    setSettingPin(true); setPinMsg('');
    try {
      await invoke('set_security_pin', { pin: pinInput });
      setHasPin(true);
      setPinMsg('PIN set successfully!');
      setTimeout(() => {
        setShowSetPin(false); setPinInput(''); setPinConfirm(''); setPinMsg('');
      }, 1500);
    } catch (e: any) { setPinMsg('Error: ' + String(e)); }
    finally { setSettingPin(false); }
  }

  async function handleForgotPin() {
    if (!wallet?.address) return;
    setResetLoading(true); setResetMsg('');
    try {
      const res  = await tauriFetch<{ success: boolean; message: string }>(
        `${RELAY}/users/reset-pin`,
        { method: 'POST', body: Body.json({ address: wallet.address }) }
      );
      const data = res.data;
      if (data.success) {
        setResetSent(true);
        setResetMsg(`PIN reset link sent to ${maskedEmail || 'your email'}.`);
      } else {
        setResetMsg('Could not send reset email: ' + data.message);
      }
    } catch {
      setResetMsg('Network error. Please try again.');
    } finally {
      setResetLoading(false);
    }
  }

  async function handleSendEmailCode() {
    if (!wallet?.address) return;
    setSendingEmailCode(true); setChangeEmailMsg('');
    try {
      const res = await tauriFetch<{ success: boolean; message: string }>(
        `${RELAY}/users/send-email-code`,
        { method: 'POST', body: Body.json({ address: wallet.address }) }
      );
      if (res.data.success) {
        setEmailStep('enter_code');
      } else {
        setChangeEmailMsg('Error: ' + res.data.message);
      }
    } catch {
      setChangeEmailMsg('Network error. Please try again.');
    } finally {
      setSendingEmailCode(false);
    }
  }

  async function handleVerifyEmailCode() {
    if (!wallet?.address || !emailCode.trim()) return;
    setVerifyingCode(true); setChangeEmailMsg('');
    try {
      const res = await tauriFetch<{ success: boolean; token: string; message: string }>(
        `${RELAY}/users/verify-email-code`,
        { method: 'POST', body: Body.json({ address: wallet.address, code: emailCode.trim() }) }
      );
      if (res.data.success) {
        setEmailVerifyToken(res.data.token ?? '');
        setEmailStep('new_email');
      } else {
        setChangeEmailMsg('Incorrect code. ' + (res.data.message ?? 'Try again.'));
      }
    } catch {
      setChangeEmailMsg('Network error. Please try again.');
    } finally {
      setVerifyingCode(false);
    }
  }

  async function handleChangeEmail() {
    if (!wallet?.address || !newEmail.trim()) return;
    setChangingEmail(true); setChangeEmailMsg('');
    try {
      const res = await tauriFetch<{ success: boolean; message: string }>(
        `${RELAY}/users/change-email`,
        { method: 'POST', body: Body.json({ address: wallet.address, new_email: newEmail.trim(), verify_token: emailVerifyToken }) }
      );
      if (res.data.success) {
        setEmailStep('done');
        setChangeEmailMsg(`Verification link sent to ${newEmail.trim()}. Click it to confirm the change.`);
      } else {
        setChangeEmailMsg('Error: ' + res.data.message);
      }
    } catch {
      setChangeEmailMsg('Network error. Please try again.');
    } finally {
      setChangingEmail(false);
    }
  }

  async function handleViewRecovery() {
    setLoadingRecovery(true); setRecoveryError('');
    try {
      const info = await invoke<RecoveryInfo>('get_recovery_info', { pin: recoveryPin });
      setRecoveryInfo(info);
    } catch (e: any) { setRecoveryError('Incorrect PIN or error: ' + String(e)); }
    finally { setLoadingRecovery(false); }
  }

  function save() { setSaved(true); setTimeout(() => setSaved(false), 2000); }

  return (
    <div className="p-6 max-w-2xl mx-auto space-y-5">

      {}
      <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-700"><h3 className="font-semibold">General</h3></div>
        <div className="divide-y divide-gray-700/50">
          {[
            { label: 'Auto-start on login',  desc: 'Launch Ego Wallet on system startup', val: autoStart,       set: setAutoStart      },
            { label: 'Minimize to tray',      desc: 'Keep running in system tray on close', val: minimizeToTray, set: setMinimizeToTray },
            { label: 'Notifications',         desc: 'Earnings, file transfers, alerts',     val: notifications,  set: setNotifications  },
          ].map(row => (
            <div key={row.label} className="flex items-center justify-between px-5 py-4">
              <div>
                <div className="text-sm font-medium">{row.label}</div>
                <div className="text-xs text-gray-400">{row.desc}</div>
              </div>
              <Toggle value={row.val} onChange={row.set} />
            </div>
          ))}
        </div>
      </div>

      {}
      <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-700">
          <h3 className="font-semibold">Security & Keys</h3>
          <div className="text-xs text-gray-400 mt-0.5">Quantum-safe cryptography — Dilithium-3 + Ed25519 + Kyber ML-KEM-768</div>
        </div>

        {}
        <div className="px-5 py-4 border-b border-gray-700/50">
          <div className="text-xs text-gray-400 mb-2">Wallet Address</div>
          <div className="flex items-center gap-3">
            {addressQR && <img src={addressQR} alt="QR" className="w-16 h-16 rounded-lg bg-white p-1" style={{ imageRendering: 'pixelated' }} />}
            <div className="flex-1 min-w-0">
              <div className="font-mono text-xs text-green-400 break-all">{wallet?.address ?? '—'}</div>
              <button
                onClick={() => navigator.clipboard.writeText(wallet?.address ?? '')}
                className="text-xs text-blue-400 hover:text-blue-300 mt-1"
              >📋 Copy address</button>
            </div>
          </div>
        </div>

       {}
<div className="px-5 py-4 border-b border-gray-700/50">
  <div className="flex items-center justify-between">
    <div>
      <div className="text-sm font-medium">Security PIN</div>
      <div className="text-xs text-gray-400">
        {hasPin ? '🔒 PIN is set — required to view your keys' : '⚠️ No PIN set — your keys are unprotected'}
      </div>
    </div>
    <button
      disabled={biometricLoading}
      onClick={async () => {
        setBiometricLoading(true);
        try {
          const ok = await invoke<boolean>('verify_biometric', {
            reason: hasPin ? 'Authorize PIN change' : 'Authorize PIN setup',
          });
          if (ok) {
            setPinInput(''); setPinConfirm(''); setPinMsg('');
            setResetSent(false); setResetMsg('');
            setShowSetPin(true);
          } else {
            setPinMsg('Biometric verification failed. Please try again.');
          }
        } catch {
          setPinInput(''); setPinConfirm(''); setPinMsg('');
          setResetSent(false); setResetMsg('');
          setShowSetPin(true);
        } finally {
          setBiometricLoading(false);
        }
      }}
      className="text-xs bg-yellow-600/20 hover:bg-yellow-600/40 disabled:opacity-50 text-yellow-400 px-3 py-1.5 rounded-lg transition"
    >
      {biometricLoading ? '🔐 Verifying…' : hasPin ? 'Change PIN' : 'Set PIN'}
    </button>
  </div>
  {pinMsg && !showSetPin && (
    <div className="mt-2 text-xs px-3 py-2 rounded-lg bg-red-500/20 text-red-400">{pinMsg}</div>
  )}
  {}
  {hasPin && maskedEmail && (
    <div className="mt-3 pt-3 border-t border-gray-700/50">
      <div className="text-xs text-gray-500 mb-2">
        🔑 Account email: <span className="text-gray-400">{maskedEmail}</span>
      </div>
      {resetSent ? (
        <div className="bg-green-500/10 border border-green-500/30 rounded-xl px-3 py-2.5 text-xs text-green-300">
          ✅ Reset link sent to <strong>{maskedEmail}</strong>.
          Click it in your email — the app will automatically open the PIN setup once confirmed.
          <div className="flex items-center gap-2 mt-2 text-green-400">
            <div className="w-3 h-3 border-2 border-green-400 border-t-transparent rounded-full animate-spin" />
            Waiting for confirmation…
          </div>
        </div>
      ) : (
        <button
          onClick={handleForgotPin}
          disabled={resetLoading}
          className="text-xs text-blue-400 hover:text-blue-300 disabled:opacity-50 transition"
        >
          {resetLoading ? '📧 Sending…' : 'Forgot PIN? Send reset link to email'}
        </button>
      )}
      {resetMsg && !resetSent && (
        <div className="mt-2 text-xs px-3 py-2 rounded-lg bg-red-500/20 text-red-400">{resetMsg}</div>
      )}
    </div>
  )}
</div>

        {}
        <div className="px-5 py-4 border-b border-gray-700/50 flex items-center justify-between">
          <div>
            <div className="text-sm font-medium">Account Email</div>
            <div className="text-xs text-gray-400">
              {maskedEmail ? `Current: ${maskedEmail}` : 'No email linked'}
            </div>
          </div>
          <button
            onClick={() => { setShowChangeEmail(true); setEmailStep('send_code'); setEmailCode(''); setEmailVerifyToken(''); setNewEmail(''); setChangeEmailMsg(''); }}
            className="text-xs bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 px-3 py-1.5 rounded-lg transition"
          >
            Change Email
          </button>
        </div>

        {}
        <div className="px-5 py-4 flex items-center justify-between">
          <div>
            <div className="text-sm font-medium">Recovery Phrase & Seed</div>
            <div className="text-xs text-gray-400">24-word phrase + raw seed hex — keep these safe</div>
          </div>
          <button
            onClick={() => { setShowRecovery(true); setRecoveryPin(''); setRecoveryInfo(null); setRecoveryError(''); setShowSeedHex(false); }}
            className="text-xs bg-red-600/20 hover:bg-red-600/40 text-red-400 px-3 py-1.5 rounded-lg transition"
          >
            🔐 View Keys
          </button>
        </div>
      </div>

      {}
      <div className="bg-gray-800 rounded-2xl border border-gray-700 p-5">
        <h3 className="font-semibold mb-4">About</h3>
        <div className="space-y-2 text-sm">
          {[
            { label: 'Version', val: 'v0.1.0' },
            { label: 'Network', val: 'Ego Network' },
            { label: 'Node ID', val: wallet?.address ? wallet.address.slice(0, 26) + '…' : '—' },
            { label: 'Crypto',  val: 'Dilithium-3 + Ed25519 + Kyber + AES-256-GCM' },
          ].map(row => (
            <div key={row.label} className="flex justify-between">
              <span className="text-gray-400">{row.label}</span>
              <span className="font-mono text-xs">{row.val}</span>
            </div>
          ))}
          <div className="flex justify-between pt-1 border-t border-gray-700/50 mt-2">
            <span className="text-gray-400">Website</span>
            <button
              onClick={() => openUrl('https://www.egoblockchain.com').catch(() => {})}
              className="text-blue-400 hover:text-blue-300 text-xs transition"
            >
              www.egoblockchain.com ↗
            </button>
          </div>
          <div className="flex justify-between pt-1 border-t border-gray-700/50">
            <span className="text-gray-400">Discord</span>
            <button
              onClick={() => openUrl('https://discord.gg/D2bEHUYz').catch(() => {})}
              className="text-indigo-400 hover:text-indigo-300 text-xs transition"
            >
              Join our community ↗
            </button>
          </div>
        </div>
      </div>

      <button
        onClick={save}
        className={`w-full py-3 rounded-xl font-semibold transition ${saved ? 'bg-green-600' : 'bg-blue-600 hover:bg-blue-500'}`}
      >
        {saved ? '✓ Saved' : 'Save Settings'}
      </button>

{}
{showSetPin && (
  <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
    <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-sm border border-gray-700 shadow-2xl">
      <div className="flex justify-between items-center mb-5">
        <h3 className="text-lg font-bold">{hasPin ? 'Change Security PIN' : 'Set Security PIN'}</h3>
        <button onClick={() => { setShowSetPin(false); setResetSent(false); setResetMsg(''); }} className="text-gray-400 hover:text-white text-xl">✕</button>
      </div>

      {}
      {hasPin ? (
        <div className="space-y-4">
          <div className="flex items-start gap-2 bg-blue-500/10 border border-blue-500/30 rounded-xl px-3 py-3">
            <span className="text-blue-400 shrink-0 text-lg">📧</span>
        <div className="text-sm text-blue-200 leading-relaxed">
          For security, changing your PIN requires email verification.
          {maskedEmail ? <> We'll send a confirmation link to <strong>{maskedEmail}</strong>.</> : ' We\'ll send a confirmation link to your registered email.'}
        </div>
          </div>
          {resetSent ? (
            <div className="space-y-3">
              <div className="bg-green-500/10 border border-green-500/30 rounded-xl px-4 py-3 text-sm text-green-300">
                ✅ Reset link sent to <strong>{maskedEmail}</strong>.<br />
                Click the link in your email to continue.
              </div>
              <div className="flex items-center gap-2 text-xs text-gray-400">
                <div className="w-3 h-3 border-2 border-blue-400 border-t-transparent rounded-full animate-spin" />
                Waiting for email confirmation…
              </div>
              <button
                onClick={() => { setResetSent(false); setResetMsg(''); }}
                className="w-full bg-gray-700 hover:bg-gray-600 py-2.5 rounded-xl text-sm text-gray-300 transition"
              >
                ← Resend email
              </button>
            </div>
          ) : (
            <button
              onClick={handleForgotPin}
              disabled={resetLoading || !maskedEmail}
              className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-40 py-3 rounded-xl font-semibold text-sm transition"
            >
              {resetLoading ? '📧 Sending…' : '📧 Send PIN Change Link'}
            </button>
          )}
          {resetMsg && !resetSent && (
            <div className="text-xs px-3 py-2 rounded-lg bg-red-500/20 text-red-400">{resetMsg}</div>
          )}
        </div>
      ) : (

        <div className="space-y-4">
          <div className="flex items-start gap-2 bg-yellow-500/10 border border-yellow-500/30 rounded-xl px-3 py-2.5">
            <span className="text-yellow-400 shrink-0">🔒</span>
            <div className="text-xs text-yellow-200 leading-relaxed">
              Your PIN is saved securely on this device. You'll need it to view your private keys.
            </div>
          </div>
          <div className="text-sm text-gray-400">Choose a PIN (minimum 4 characters).</div>
          <input
            type="password"
            value={pinInput}
            onChange={e => setPinInput(e.target.value)}
            placeholder="New PIN"
            className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none transition"
          />
          <input
            type="password"
            value={pinConfirm}
            onChange={e => setPinConfirm(e.target.value)}
            placeholder="Confirm PIN"
            className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none transition"
            onKeyDown={e => e.key === 'Enter' && handleSetPin()}
          />
          {pinMsg && (
            <div className={`text-xs px-3 py-2 rounded-lg ${pinMsg.includes('success') ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
              {pinMsg}
            </div>
          )}
          <button
            onClick={handleSetPin}
            disabled={settingPin || !pinInput || !pinConfirm}
            className="w-full bg-yellow-600 hover:bg-yellow-500 disabled:opacity-40 py-3 rounded-xl font-semibold text-sm transition"
          >
            {settingPin ? 'Saving…' : 'Set PIN'}
          </button>
        </div>
      )}
    </div>
  </div>
)}

      {/* ── View Recovery Info Modal ───────────────────────────────────────── */}
      {showRecovery && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-lg border border-gray-700 shadow-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex justify-between items-center mb-5">
              <h3 className="text-lg font-bold text-red-400">⚠️ Recovery Information</h3>
              <button onClick={() => { setShowRecovery(false); setRecoveryInfo(null); setRecoveryPin(''); }} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>

            {!recoveryInfo ? (
              <div className="space-y-4">
                <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 text-sm text-red-300">
                  <strong>Warning:</strong> Anyone with your recovery phrase can access all your funds.
                  Never share these with anyone.
                </div>
                <div>
                  <label className="text-xs text-gray-400 block mb-1.5">
                    {hasPin ? 'Enter your Security PIN to continue' : 'No PIN set — click Show to reveal'}
                  </label>
                  {hasPin && (
                    <input
                      type="password"
                      value={recoveryPin}
                      onChange={e => setRecoveryPin(e.target.value)}
                      placeholder="Enter your PIN"
                      className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none transition"
                      onKeyDown={e => e.key === 'Enter' && handleViewRecovery()}
                    />
                  )}
                </div>
                {recoveryError && (
                  <div className="bg-red-500/20 text-red-400 text-xs px-3 py-2 rounded-lg">{recoveryError}</div>
                )}
                <button
                  onClick={handleViewRecovery}
                  disabled={loadingRecovery || (hasPin && !recoveryPin)}
                  className="w-full bg-red-700 hover:bg-red-600 disabled:opacity-40 py-3 rounded-xl font-semibold text-sm transition"
                >
                  {loadingRecovery ? 'Verifying…' : 'Show Recovery Info'}
                </button>
              </div>
            ) : (
              <div className="space-y-5">
                <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-3 text-xs text-red-300">
                  ⚠️ Write these down now. Do NOT screenshot or copy to clipboard on untrusted devices.
                </div>
                <div>
                  <div className="text-sm font-semibold mb-3">24-Word Recovery Phrase</div>
                  <div className="grid grid-cols-4 gap-2">
                    {recoveryInfo.recovery_phrase.map((word, i) => (
                      <div key={i} className="bg-gray-900 rounded-lg px-2 py-1.5 text-center">
                        <div className="text-gray-500 text-xs">{i + 1}</div>
                        <div className="font-mono text-xs font-semibold text-green-400">{word}</div>
                      </div>
                    ))}
                  </div>
                </div>
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="text-sm font-semibold">Raw Seed (hex)</div>
                    <button onClick={() => setShowSeedHex(v => !v)} className="text-xs text-blue-400">
                      {showSeedHex ? 'Hide' : 'Show'}
                    </button>
                  </div>
                  {showSeedHex ? (
                    <div className="bg-gray-900 rounded-xl p-3 font-mono text-xs text-yellow-400 break-all select-all">
                      {Array.from({ length: 8 }, (_, i) => recoveryInfo.seed_hex.slice(i * 8, i * 8 + 8)).join(' ')}
                    </div>
                  ) : (
                    <div className="bg-gray-900 rounded-xl p-3 text-center text-gray-500 text-sm">
                      Click Show to reveal
                    </div>
                  )}
                </div>
                <button
                  onClick={() => { setShowRecovery(false); setRecoveryInfo(null); setRecoveryPin(''); setShowSeedHex(false); }}
                  className="w-full bg-gray-700 hover:bg-gray-600 py-3 rounded-xl font-semibold text-sm transition"
                >
                  Close
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Change Email Modal ─────────────────────────────────────────────── */}
      {showChangeEmail && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-sm border border-gray-700 shadow-2xl">
            <div className="flex justify-between items-center mb-5">
              <h3 className="text-lg font-bold">Change Email Address</h3>
              <button onClick={() => setShowChangeEmail(false)} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>

            {/* Step indicator */}
            <div className="flex items-center gap-2 mb-5">
              {(['send_code', 'enter_code', 'new_email'] as const).map((s, i) => (
                <React.Fragment key={s}>
                  <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${
                    emailStep === 'done' || ['send_code','enter_code','new_email'].indexOf(emailStep) > i
                      ? 'bg-blue-600 text-white'
                      : emailStep === s
                      ? 'bg-blue-600 text-white ring-2 ring-blue-400/40'
                      : 'bg-gray-700 text-gray-500'
                  }`}>{i + 1}</div>
                  {i < 2 && <div className={`flex-1 h-px ${['send_code','enter_code','new_email'].indexOf(emailStep) > i || emailStep === 'done' ? 'bg-blue-600' : 'bg-gray-700'}`} />}
                </React.Fragment>
              ))}
            </div>

            {/* Step 1 — send code to current email */}
            {emailStep === 'send_code' && (
              <div className="space-y-4">
                <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl px-4 py-3 text-sm text-blue-200">
                  To protect your account, we'll send a 6-digit verification code to your current email:
                  <div className="font-semibold text-white mt-1">{maskedEmail || '(no email on file)'}</div>
                </div>
                {changeEmailMsg && <div className="text-xs px-3 py-2 rounded-lg bg-red-500/20 text-red-400">{changeEmailMsg}</div>}
                <button
                  onClick={handleSendEmailCode}
                  disabled={sendingEmailCode || !maskedEmail}
                  className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-40 py-3 rounded-xl font-semibold text-sm transition"
                >
                  {sendingEmailCode ? '📧 Sending…' : '📧 Send Verification Code'}
                </button>
              </div>
            )}

            {/* Step 2 — enter the code */}
            {emailStep === 'enter_code' && (
              <div className="space-y-4">
                <div className="bg-green-500/10 border border-green-500/30 rounded-xl px-4 py-3 text-sm text-green-300">
                  Code sent to <strong>{maskedEmail}</strong>. Check your inbox and enter the 6-digit code below.
                </div>
                <input
                  type="text"
                  inputMode="numeric"
                  maxLength={6}
                  value={emailCode}
                  onChange={e => setEmailCode(e.target.value.replace(/\D/g, ''))}
                  onKeyDown={e => e.key === 'Enter' && handleVerifyEmailCode()}
                  placeholder="6-digit code"
                  className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none transition tracking-[0.3em] text-center font-mono text-lg"
                  autoFocus
                />
                {changeEmailMsg && <div className="text-xs px-3 py-2 rounded-lg bg-red-500/20 text-red-400">{changeEmailMsg}</div>}
                <button
                  onClick={handleVerifyEmailCode}
                  disabled={verifyingCode || emailCode.length < 6}
                  className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-40 py-3 rounded-xl font-semibold text-sm transition"
                >
                  {verifyingCode ? 'Verifying…' : 'Verify Code'}
                </button>
                <button
                  onClick={() => { setEmailStep('send_code'); setEmailCode(''); setChangeEmailMsg(''); }}
                  className="w-full text-xs text-gray-400 hover:text-gray-200 transition"
                >
                  Didn't receive it? Send again
                </button>
              </div>
            )}

            {/* Step 3 — enter new email */}
            {emailStep === 'new_email' && (
              <div className="space-y-4">
                <div className="bg-green-500/10 border border-green-500/30 rounded-xl px-4 py-3 text-sm text-green-300">
                  ✅ Current email verified. Enter your new email address below.
                </div>
                <input
                  type="email"
                  value={newEmail}
                  onChange={e => setNewEmail(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleChangeEmail()}
                  placeholder="New email address"
                  className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none transition"
                  autoFocus
                />
                {changeEmailMsg && <div className="text-xs px-3 py-2 rounded-lg bg-red-500/20 text-red-400">{changeEmailMsg}</div>}
                <button
                  onClick={handleChangeEmail}
                  disabled={changingEmail || !newEmail.trim()}
                  className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-40 py-3 rounded-xl font-semibold text-sm transition"
                >
                  {changingEmail ? 'Sending…' : 'Update Email'}
                </button>
              </div>
            )}

            {/* Done */}
            {emailStep === 'done' && (
              <div className="space-y-4">
                <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-4 text-sm text-green-300">
                  ✅ {changeEmailMsg}
                </div>
                <p className="text-xs text-gray-400">Once you click the link in the new email, your address will be updated automatically.</p>
                <button
                  onClick={() => setShowChangeEmail(false)}
                  className="w-full bg-gray-700 hover:bg-gray-600 py-3 rounded-xl font-semibold text-sm transition"
                >
                  Close
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default SettingsPage;
