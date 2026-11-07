import React, { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import qrcode from 'qrcode-generator';

function qrData(text: string): string {
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  return qr.createDataURL(4, 0);
}

const AuthenticatorCard: React.FC = () => {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null);
  const [disabling, setDisabling] = useState(false);
  const [code, setCode] = useState('');
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);

  const refresh = () =>
    invoke<{ enabled: boolean }>('totp_status')
      .then(s => {
        setEnabled(s.enabled);
        window.dispatchEvent(new Event('ego-totp-changed'));
      })
      .catch(() => setEnabled(false));

  useEffect(() => {
    refresh();
  }, []);

  const clean = (e: any) => String(e?.message ?? e).replace(/^.*?:\s*/, '');

  const begin = async () => {
    setMsg('');
    setCode('');
    try {
      setSetup(await invoke<{ secret: string; uri: string }>('totp_begin_setup'));
    } catch (e) {
      setMsg(clean(e));
    }
  };

  const confirm = async () => {
    if (code.length !== 6) return;
    setBusy(true);
    setMsg('');
    try {
      await invoke('totp_confirm_setup', { code });
      setSetup(null);
      setCode('');
      await refresh();
    } catch (e) {
      setMsg(clean(e));
      setCode('');
    } finally {
      setBusy(false);
    }
  };

  const disable = async () => {
    if (code.length !== 6) return;
    setBusy(true);
    setMsg('');
    try {
      await invoke('totp_disable', { code });
      setDisabling(false);
      setCode('');
      await refresh();
    } catch (e) {
      setMsg(clean(e));
      setCode('');
    } finally {
      setBusy(false);
    }
  };

  const codeInput = (onEnter: () => void) => (
    <input
      value={code}
      onChange={e => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
      onKeyDown={e => e.key === 'Enter' && onEnter()}
      inputMode="numeric"
      autoComplete="one-time-code"
      placeholder="6-digit code"
      className="w-40 text-center font-mono tracking-widest bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-lg px-3 py-2 text-sm outline-none"
    />
  );

  return (
    <div className="px-5 py-4 border-b border-gray-700/50">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-sm font-medium">Authenticator app</div>
          <div className="text-xs text-gray-400">
            {enabled
              ? '🛡 On: sending, showing your keys and changing the password need a code from your phone'
              : 'Google Authenticator, Authy or any app with 6-digit codes. Works offline, no account needed.'}
          </div>
        </div>
        {enabled === false && !setup && (
          <button onClick={begin} className="text-xs bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 px-3 py-1.5 rounded-lg transition shrink-0">
            Turn on
          </button>
        )}
        {enabled && !disabling && (
          <button
            onClick={() => { setDisabling(true); setCode(''); setMsg(''); }}
            className="text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 px-3 py-1.5 rounded-lg transition shrink-0"
          >
            Turn off
          </button>
        )}
      </div>

      {setup && (
        <div className="mt-4 flex gap-4 items-start">
          <img src={qrData(setup.uri)} alt="Authenticator QR code" className="w-36 h-36 rounded-lg bg-white p-1" style={{ imageRendering: 'pixelated' }} />
          <div className="flex-1 min-w-0 space-y-2">
            <div className="text-xs text-gray-300">1. Scan this code with your authenticator app.</div>
            <div className="text-xs text-gray-400">
              Can't scan? Enter this key by hand:
              <div className="font-mono text-green-400 break-all mt-1 select-all">{setup.secret.replace(/(.{4})/g, '$1 ').trim()}</div>
            </div>
            <div className="text-xs text-gray-300">2. Type the 6-digit code it shows.</div>
            <div className="flex gap-2 items-center">
              {codeInput(confirm)}
              <button
                onClick={confirm}
                disabled={code.length !== 6 || busy}
                className="text-xs bg-blue-600 hover:bg-blue-500 disabled:opacity-50 px-3 py-2 rounded-lg transition"
              >
                {busy ? 'Checking…' : 'Turn on'}
              </button>
              <button onClick={() => { setSetup(null); setMsg(''); }} className="text-xs text-gray-400 hover:text-white px-2">
                Cancel
              </button>
            </div>
            <div className="text-[11px] text-yellow-400/80">
              Keep the key somewhere safe. If you lose your phone you need it, or your recovery phrase, to get back in.
            </div>
          </div>
        </div>
      )}

      {disabling && (
        <div className="mt-3 flex gap-2 items-center">
          <span className="text-xs text-gray-400">Code from your app:</span>
          {codeInput(disable)}
          <button
            onClick={disable}
            disabled={code.length !== 6 || busy}
            className="text-xs bg-red-600/30 hover:bg-red-600/50 disabled:opacity-50 text-red-300 px-3 py-2 rounded-lg transition"
          >
            {busy ? 'Checking…' : 'Turn off'}
          </button>
          <button onClick={() => { setDisabling(false); setMsg(''); }} className="text-xs text-gray-400 hover:text-white px-2">
            Cancel
          </button>
        </div>
      )}

      {msg && <div className="mt-2 text-xs px-3 py-2 rounded-lg bg-red-500/20 text-red-400">{msg}</div>}
    </div>
  );
};

export default AuthenticatorCard;
