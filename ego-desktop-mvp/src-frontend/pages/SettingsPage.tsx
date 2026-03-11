import React, { useState, useMemo } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { open as openUrl } from '@tauri-apps/api/shell';
import { useWallet } from '../App';
import qrcode from 'qrcode-generator';

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
  const [notifications, setNotifications] = useState(true);
  const [autoStart, setAutoStart] = useState(true);
  const [minimizeToTray, setMinimizeToTray] = useState(true);
  const [saved, setSaved] = useState(false);

  // Security PIN
  const [showSetPin, setShowSetPin]     = useState(false);
  const [pinInput, setPinInput]         = useState('');
  const [pinConfirm, setPinConfirm]     = useState('');
  const [pinMsg, setPinMsg]             = useState('');
  const [settingPin, setSettingPin]     = useState(false);

  // View recovery info (PIN-gated)
  const [showRecovery, setShowRecovery]     = useState(false);
  const [recoveryPin, setRecoveryPin]       = useState('');
  const [recoveryInfo, setRecoveryInfo]     = useState<RecoveryInfo | null>(null);
  const [recoveryError, setRecoveryError]   = useState('');
  const [loadingRecovery, setLoadingRecovery] = useState(false);
  const [showSeedHex, setShowSeedHex]       = useState(false);


  const addressQR = useMemo(() => makeQR(wallet?.address ?? ''), [wallet?.address]);

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
      setPinMsg('PIN set successfully!');
      setTimeout(() => { setShowSetPin(false); setPinInput(''); setPinConfirm(''); setPinMsg(''); }, 1500);
    } catch (e: any) { setPinMsg('Error: ' + String(e)); }
    finally { setSettingPin(false); }
  }

  async function handleViewRecovery() {
    setLoadingRecovery(true); setRecoveryError('');
    try {
      const info = await invoke<RecoveryInfo>('get_recovery_info', { pin: recoveryPin });
      setRecoveryInfo(info);
    } catch (e: any) { setRecoveryError(String(e)); }
    finally { setLoadingRecovery(false); }
  }

  function save() { setSaved(true); setTimeout(() => setSaved(false), 2000); }

  return (
    <div className="p-6 max-w-2xl mx-auto space-y-5">

      {/* General */}
      <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-700"><h3 className="font-semibold">General</h3></div>
        <div className="divide-y divide-gray-700/50">
          {[
            { label: 'Auto-start on login',  desc: 'Launch Ego Wallet on system startup', val: autoStart,       set: setAutoStart      },
            { label: 'Minimize to tray',      desc: 'Keep running in system tray on close', val: minimizeToTray,  set: setMinimizeToTray },
            { label: 'Notifications',         desc: 'Earnings, file transfers, alerts',     val: notifications,   set: setNotifications  },
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

      {/* Security & Keys */}
      <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-700">
          <h3 className="font-semibold">Security & Keys</h3>
          <div className="text-xs text-gray-400 mt-0.5">Quantum-safe cryptography — Dilithium-3 + Ed25519 + Kyber ML-KEM-768</div>
        </div>

        {/* Wallet address + QR */}
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

        {/* Security PIN */}
        <div className="px-5 py-4 border-b border-gray-700/50">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm font-medium">Security PIN</div>
              <div className="text-xs text-gray-400">Protects access to your private key and seed phrase</div>
            </div>
            <button
              onClick={() => { setShowSetPin(true); setPinInput(''); setPinConfirm(''); setPinMsg(''); }}
              className="text-xs bg-yellow-600/20 hover:bg-yellow-600/40 text-yellow-400 px-3 py-1.5 rounded-lg transition"
            >
              Set / Change PIN
            </button>
          </div>
          <div className="mt-2 text-xs text-gray-500">
            🔒 Changing your PIN requires your device security (Windows Hello / Touch ID).
            If you forgot your PIN, contact support at{' '}
            <span className="text-blue-400">support@egoblockchain.com</span> or visit{' '}
            <span className="text-blue-400">www.egoblockchain.com/support</span>.
          </div>
        </div>

        {/* View private key / seed phrase */}
        <div className="px-5 py-4 flex items-center justify-between">
          <div>
            <div className="text-sm font-medium">Recovery Phrase & Seed</div>
            <div className="text-xs text-gray-400">24-word phrase + raw seed hex — write these down and keep them safe</div>
          </div>
          <button
            onClick={() => { setShowRecovery(true); setRecoveryPin(''); setRecoveryInfo(null); setRecoveryError(''); setShowSeedHex(false); }}
            className="text-xs bg-red-600/20 hover:bg-red-600/40 text-red-400 px-3 py-1.5 rounded-lg transition"
          >
            🔐 View Keys
          </button>
        </div>
      </div>

      {/* About */}
      <div className="bg-gray-800 rounded-2xl border border-gray-700 p-5">
        <h3 className="font-semibold mb-4">About</h3>
        <div className="space-y-2 text-sm">
          {[
            { label: 'Version',    val: 'Testnet v0.1.0' },
            { label: 'Network',    val: 'Ego Testnet' },
            { label: 'Node ID',    val: wallet?.address ? wallet.address.slice(0, 26) + '…' : '—' },
            { label: 'Crypto',     val: 'Dilithium-3 + Ed25519 + Kyber + AES-256-GCM' },
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
        </div>
      </div>

      <button
        onClick={save}
        className={`w-full py-3 rounded-xl font-semibold transition ${saved ? 'bg-green-600' : 'bg-blue-600 hover:bg-blue-500'}`}
      >
        {saved ? '✓ Saved' : 'Save Settings'}
      </button>

      {/* ── Set PIN Modal ──────────────────────────────────────────────── */}
      {showSetPin && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-sm border border-gray-700 shadow-2xl">
            <div className="flex justify-between items-center mb-5">
              <h3 className="text-lg font-bold">Set Security PIN</h3>
              <button onClick={() => setShowSetPin(false)} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>
            <div className="space-y-4">
              <div className="flex items-start gap-2 bg-yellow-500/10 border border-yellow-500/30 rounded-xl px-3 py-2.5">
                <span className="text-yellow-400 shrink-0">🔒</span>
                <div className="text-xs text-yellow-200 leading-relaxed">
                  Your PIN is stored securely and will persist on this device. To change it, your device security (Windows Hello / Touch ID) will be required.
                </div>
              </div>
              <div className="text-sm text-gray-400">Choose a PIN to protect your private key and seed phrase. Minimum 4 characters.</div>
              <input
                type="password"
                value={pinInput}
                onChange={e => setPinInput(e.target.value)}
                placeholder="Enter PIN"
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
                {settingPin ? 'Setting…' : 'Set PIN'}
              </button>
              <div className="text-center text-xs text-gray-500">
                Forgot your PIN?{' '}
                <span className="text-blue-400">support@egoblockchain.com</span>
              </div>
            </div>
          </div>
        </div>
      )}


      {/* ── View Recovery Info Modal ───────────────────────────────────── */}
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
                  <strong>Warning:</strong> Anyone with your recovery phrase or seed can access all your funds.
                  Never share these with anyone. Write them down and store offline.
                </div>
                <div>
                  <label className="text-xs text-gray-400 block mb-1.5">Enter your Security PIN to continue</label>
                  <input
                    type="password"
                    value={recoveryPin}
                    onChange={e => setRecoveryPin(e.target.value)}
                    placeholder="PIN (leave blank if not set)"
                    className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none transition"
                    onKeyDown={e => e.key === 'Enter' && handleViewRecovery()}
                  />
                </div>
                {recoveryError && (
                  <div className="bg-red-500/20 text-red-400 text-xs px-3 py-2 rounded-lg">{recoveryError}</div>
                )}
                <button
                  onClick={handleViewRecovery}
                  disabled={loadingRecovery}
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

                {/* 24-word phrase */}
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

                {/* Raw seed hex */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="text-sm font-semibold">Raw Seed (hex)</div>
                    <button onClick={() => setShowSeedHex(v => !v)} className="text-xs text-blue-400">
                      {showSeedHex ? 'Hide' : 'Show'}
                    </button>
                  </div>
                  {showSeedHex ? (
                    <div className="bg-gray-900 rounded-xl p-3 font-mono text-xs text-yellow-400 break-all select-all">
                      {/* Format as 8 groups of 8 hex chars for readability */}
                      {Array.from({ length: 8 }, (_, i) =>
                        recoveryInfo.seed_hex.slice(i * 8, i * 8 + 8)
                      ).join(' ')}
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

    </div>
  );
};

export default SettingsPage;
