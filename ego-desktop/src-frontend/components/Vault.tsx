import React, { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { open as openDialog } from '@tauri-apps/api/dialog';
import qrcode from 'qrcode-generator';

function makeQR(text: string): string {
  try {
    const qr = qrcode(0, 'L');
    qr.addData(text);
    qr.make();
    return qr.createDataURL(3, 2);
  } catch {
    return '';
  }
}

function QR({ text }: { text: string }) {
  const src = makeQR(text);
  return src ? <img src={src} alt="QR code" className="mx-auto rounded bg-white p-1 max-w-[260px]" /> : null;
}

export interface VaultSettings {
  limit: number;
  delay: number;
  high_limit: number;
  high_delay: number;
  recovery: string;
  second_key: string;
  guardians: string[];
}

interface QueuedView { id: string; to: string; amount: number; at: number; mine: boolean; }
interface PendingView { kind: string; at: number; settings: VaultSettings | null; }
interface VaultView {
  owner: string;
  settings: VaultSettings;
  frozen: boolean;
  pending: PendingView | null;
  queue: QueuedView[];
  spent_today: number;
}
interface VaultStatus { active: boolean; address: string; vault: VaultView | null; helping: VaultView[]; key_file: string; }
interface RequestPreview { from: string; to: string; amount: number; kind: string; memo: string; i_am_second_key: boolean; }

const EGOC = 1_000_000;
const HOUR = 3600;

function egoc(u: number): string {
  return (u / EGOC).toLocaleString(undefined, { maximumFractionDigits: 6 });
}

function when(ts: number): string {
  return new Date(ts * 1000).toLocaleString();
}

function short(a: string): string {
  return a.length > 22 ? `${a.slice(0, 12)}…${a.slice(-6)}` : a;
}

function clean(e: any): string {
  return String(e).replace(/^.*Error:/, '').replace(/^\s*(VAULT_LIMIT|VAULT_REFUSED):\s*/, '').trim();
}

const box = 'bg-gray-900/60 border border-gray-700/60 rounded-xl p-4';
const input = 'w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm';
const btn = 'px-3 py-2 rounded-lg text-sm font-semibold transition disabled:opacity-50';

function DeviceApproval({ request, onSubmitted }: { request: any; onSubmitted: (hash: string) => void }) {
  const [code, setCode] = useState('');
  const [answer, setAnswer] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');

  async function make() {
    setBusy(true); setMsg('');
    try { setCode(await invoke<string>('vault_request_code', { request })); }
    catch (e) { setMsg(clean(e)); }
    finally { setBusy(false); }
  }

  async function submit() {
    setBusy(true); setMsg('');
    try { onSubmitted(await invoke<string>('vault_submit_approved', { approval: answer })); }
    catch (e) { setMsg(clean(e)); }
    finally { setBusy(false); }
  }

  return (
    <div className="space-y-2">
      {!code ? (
        <button className={`${btn} bg-gray-700 hover:bg-gray-600 w-full`} disabled={busy} onClick={make}>
          Create an approval request
        </button>
      ) : (
        <>
          <div className="text-xs text-gray-400">Scan this with the Ego iPhone app that holds your second key, or copy it into Wallet → Vault → Approve a request on that device:</div>
          <QR text={code} />
          <textarea readOnly className={`${input} font-mono text-xs h-20`} value={code} onFocus={e => e.currentTarget.select()} />
          <button className={`${btn} bg-gray-700 hover:bg-gray-600`} onClick={() => navigator.clipboard.writeText(code)}>Copy request</button>
          <div className="text-xs text-gray-400 pt-2">Then paste the approval it gives you:</div>
          <input className={`${input} font-mono text-xs`} value={answer} onChange={e => setAnswer(e.target.value)} placeholder="egocosig1:…" />
          <button className={`${btn} bg-blue-600 hover:bg-blue-500 w-full`} disabled={busy || !answer.trim()} onClick={submit}>
            Send with this approval
          </button>
        </>
      )}
      {msg && <div className="text-xs text-red-400">{msg}</div>}
    </div>
  );
}

export function VaultSendChoice({ to, amount, memo, message, onDone, onCancel }: {
  to: string; amount: number; memo: string | null; message: string;
  onDone: (r: { hash: string; success: boolean; message: string }) => void; onCancel: () => void;
}) {
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [mode, setMode] = useState<'pick' | 'device'>('pick');

  async function delay() {
    setBusy(true); setErr('');
    try {
      const r = await invoke<{ id: string; hash: string; wait_secs: number }>('vault_queue_send', { to, amount });
      const hours = Math.round(r.wait_secs / HOUR);
      onDone({ hash: r.hash, success: true, message: `The send waits ${hours} hours, then this app sends it. You can cancel it in Wallet → Vault until then.` });
    } catch (e) { setErr(clean(e)); }
    finally { setBusy(false); }
  }

  async function withPassword() {
    setBusy(true); setErr('');
    try {
      const res = await invoke<any>('send_transaction', { request: { to_address: to, amount, memo, vault_password: password } });
      onDone(res);
    } catch (e) { setErr(clean(e)); }
    finally { setBusy(false); }
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-bold">This send needs your vault</h3>
        <button onClick={onCancel} className="text-gray-400 hover:text-white text-xl">✕</button>
      </div>
      <p className="text-sm text-gray-400">{clean(message)}</p>
      <div className={box}>
        <div className="font-semibold text-sm mb-1">Send with a delay</div>
        <div className="text-xs text-gray-400 mb-3">{egoc(amount)} EGOC waits, then goes out by itself. You and your guardians can cancel it while it waits.</div>
        <button className={`${btn} bg-gray-700 hover:bg-gray-600 w-full`} disabled={busy} onClick={delay}>Send with delay</button>
      </div>
      <div className={box}>
        <div className="font-semibold text-sm mb-1">Approve with your second key</div>
        <div className="text-xs text-gray-400 mb-3">Goes out at once if your second key approves it.</div>
        {mode === 'pick' ? (
          <div className="space-y-2">
            <input type="password" className={input} value={password} onChange={e => setPassword(e.target.value)} placeholder="Second-key password (or key-file password)" />
            <button className={`${btn} bg-blue-600 hover:bg-blue-500 w-full`} disabled={busy || password.length < 10} onClick={withPassword}>Approve with password</button>
            <button className="text-xs text-blue-300 hover:underline" onClick={() => setMode('device')}>My second key is another device</button>
          </div>
        ) : (
          <DeviceApproval request={{ kind: 'send', to, amount, memo }} onSubmitted={hash => onDone({ hash, success: true, message: 'Approved by your second key and sent.' })} />
        )}
      </div>
      {err && <div className="text-sm text-red-400">{err}</div>}
    </div>
  );
}

function SettingsForm({ initial, owner, onSaved, existing }: { initial: VaultSettings | null; owner: string; onSaved: () => void; existing: boolean }) {
  const [limit, setLimit] = useState(String(initial ? initial.limit / EGOC : 100));
  const [delayH, setDelayH] = useState(String(initial ? initial.delay / HOUR : 24));
  const [highLimit, setHighLimit] = useState(String(initial && initial.high_limit ? initial.high_limit / EGOC : ''));
  const [highDelayH, setHighDelayH] = useState(String(initial && initial.high_delay ? initial.high_delay / HOUR : ''));
  const [recovery, setRecovery] = useState(initial?.recovery ?? '');
  const [secondMode, setSecondMode] = useState<'none' | 'password' | 'device' | 'file'>(initial?.second_key ? 'device' : 'none');
  const [folder, setFolder] = useState('');
  const [secondKey, setSecondKey] = useState(initial?.second_key ?? '');
  const [pw, setPw] = useState('');
  const [pw2, setPw2] = useState('');
  const [guardians, setGuardians] = useState((initial?.guardians ?? []).join('\n'));
  const [approvePw, setApprovePw] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');

  async function build(): Promise<VaultSettings> {
    let second = secondMode === 'device' ? secondKey.trim() : '';
    if (secondMode === 'password' || secondMode === 'file') {
      if (pw.length < 10) throw new Error('Use a second-key password of at least 10 characters');
      if (pw !== pw2) throw new Error('The two passwords differ');
    }
    if (secondMode === 'password') {
      second = await invoke<string>('vault_password_address', { password: pw });
    }
    if (secondMode === 'file') {
      if (!folder) throw new Error('Choose the folder for the key file');
      const made = await invoke<{ path: string; address: string }>('vault_create_key_file', { folder, password: pw });
      second = made.address;
    }
    const hl = highLimit.trim() ? Math.round(parseFloat(highLimit) * EGOC) : 0;
    return {
      limit: Math.round(parseFloat(limit || '0') * EGOC),
      delay: Math.round(parseFloat(delayH || '0') * HOUR),
      high_limit: hl,
      high_delay: hl ? Math.round(parseFloat(highDelayH || '0') * HOUR) : 0,
      recovery: recovery.trim(),
      second_key: second,
      guardians: guardians.split(/[\s,]+/).map(g => g.trim()).filter(Boolean),
    };
  }

  async function save() {
    setBusy(true); setMsg('');
    try {
      const settings = await build();
      await invoke('vault_save_settings', { settings, approval: approvePw ? { password: approvePw } : null });
      setMsg(existing ? 'Saved. Stricter settings apply in the next block; looser ones wait out your delay unless your second key approved them.' : 'Your vault is on from the next block.');
      onSaved();
    } catch (e: any) { setMsg(clean(e?.message ?? e)); }
    finally { setBusy(false); }
  }

  return (
    <div className="space-y-3 text-sm">
      <div className="grid grid-cols-2 gap-3">
        <label className="space-y-1"><div className="text-xs text-gray-400">Daily limit without approval (EGOC)</div>
          <input className={input} value={limit} onChange={e => setLimit(e.target.value)} /></label>
        <label className="space-y-1"><div className="text-xs text-gray-400">Delay above it (hours)</div>
          <input className={input} value={delayH} onChange={e => setDelayH(e.target.value)} /></label>
        <label className="space-y-1"><div className="text-xs text-gray-400">Higher limit (EGOC, optional)</div>
          <input className={input} value={highLimit} onChange={e => setHighLimit(e.target.value)} placeholder="e.g. 10000" /></label>
        <label className="space-y-1"><div className="text-xs text-gray-400">Delay above the higher limit (hours)</div>
          <input className={input} value={highDelayH} onChange={e => setHighDelayH(e.target.value)} placeholder="e.g. 72" /></label>
      </div>
      <label className="space-y-1 block"><div className="text-xs text-gray-400">Recovery address (a wallet you keep somewhere else)</div>
        <input className={`${input} font-mono`} value={recovery} onChange={e => setRecovery(e.target.value)} placeholder="egot1…" /></label>
      <div className="space-y-2">
        <div className="text-xs text-gray-400">Second key</div>
        <div className="flex gap-2">
          {(['none', 'device', 'file', 'password'] as const).map(m => (
            <button key={m} onClick={() => setSecondMode(m)}
              className={`${btn} ${secondMode === m ? 'bg-blue-600' : 'bg-gray-700 hover:bg-gray-600'}`}>
              {m === 'none' ? 'None' : m === 'device' ? 'Another device' : m === 'file' ? 'Key file' : 'Password'}
            </button>
          ))}
        </div>
        {secondMode === 'device' && (
          <input className={`${input} font-mono`} value={secondKey} onChange={e => setSecondKey(e.target.value)} placeholder="Address of the wallet on your other device" />
        )}
        {secondMode === 'file' && (
          <div className="space-y-2">
            <div className="flex gap-2">
              <input readOnly className={`${input} font-mono text-xs`} value={folder} placeholder="Folder for the key file" />
              <button className={`${btn} bg-gray-700 hover:bg-gray-600 shrink-0`} onClick={async () => {
                const dir = await openDialog({ directory: true, multiple: false, title: 'Folder for the second-key file' });
                if (typeof dir === 'string') setFolder(dir);
              }}>Choose…</button>
            </div>
            <input type="password" className={input} value={pw} onChange={e => setPw(e.target.value)} placeholder="Password for the key file (10+ characters)" />
            <input type="password" className={input} value={pw2} onChange={e => setPw2(e.target.value)} placeholder="Repeat it" />
            <div className="text-xs text-amber-300">The file is encrypted, so it is useless without this password. Malware on this computer could still find both, so a USB stick or another device is safer, and the Desktop folder is the worst place. Keep a copy of the file: without it and its password, large sends simply wait out the delay.</div>
          </div>
        )}
        {secondMode === 'password' && (
          <div className="space-y-2">
            <input type="password" className={input} value={pw} onChange={e => setPw(e.target.value)} placeholder="Second-key password (10+ characters)" />
            <input type="password" className={input} value={pw2} onChange={e => setPw2(e.target.value)} placeholder="Repeat it" />
            <div className="text-xs text-amber-300">Weaker than another device: malware on this computer could catch it. Nobody can recover it for you.</div>
          </div>
        )}
      </div>
      <label className="space-y-1 block"><div className="text-xs text-gray-400">Guardians (addresses that can cancel and freeze, one per line)</div>
        <textarea className={`${input} font-mono h-16`} value={guardians} onChange={e => setGuardians(e.target.value)} /></label>
      {existing && initial?.second_key && (
        <label className="space-y-1 block"><div className="text-xs text-gray-400">Second-key password, to apply a looser change at once (optional)</div>
          <input type="password" className={input} value={approvePw} onChange={e => setApprovePw(e.target.value)} /></label>
      )}
      <button className={`${btn} bg-blue-600 hover:bg-blue-500 w-full`} disabled={busy} onClick={save}>
        {busy ? 'Saving…' : existing ? 'Save vault settings' : 'Turn on the vault'}
      </button>
      {msg && <div className="text-xs text-gray-300">{msg}</div>}
      <div className="text-xs text-gray-500">Wallet {short(owner)}</div>
    </div>
  );
}

function VaultCard({ v, own, onChange, keyFile = '' }: { v: VaultView; own: boolean; onChange: () => void; keyFile?: string }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [pw, setPw] = useState('');
  const now = Date.now() / 1000;
  const left = Math.max(0, v.settings.limit - v.spent_today);

  async function act(cmd: string, args: any = {}) {
    setBusy(true); setMsg('');
    try { await invoke(cmd, args); setMsg('Sent. It takes effect in the next block.'); onChange(); }
    catch (e) { setMsg(clean(e)); }
    finally { setBusy(false); }
  }

  const ownerArg = own ? null : v.owner;
  return (
    <div className={`${box} space-y-3`}>
      <div className="flex justify-between items-center">
        <div className="font-semibold text-sm">{own ? 'Your vault' : `Vault of ${short(v.owner)}`}</div>
        <span className={`text-xs px-2 py-0.5 rounded-full ${v.frozen ? 'bg-red-500/20 text-red-300' : 'bg-green-500/15 text-green-300'}`}>
          {v.frozen ? 'Frozen' : 'Protected'}
        </span>
      </div>
      {own && (
        <div className="grid grid-cols-2 gap-2 text-xs text-gray-400">
          <div>Left today: <span className="text-gray-200">{egoc(left)} EGOC</span></div>
          <div>Delay: <span className="text-gray-200">{v.settings.delay / HOUR} h{v.settings.high_limit ? `, ${v.settings.high_delay / HOUR} h above ${egoc(v.settings.high_limit)}` : ''}</span></div>
          <div>Recovery: <span className="text-gray-200 font-mono">{v.settings.recovery ? short(v.settings.recovery) : 'none'}</span></div>
          <div>Second key: <span className="text-gray-200 font-mono">{v.settings.second_key ? short(v.settings.second_key) : 'none'}</span></div>
        </div>
      )}
      {v.pending && (
        <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3 text-xs space-y-2">
          <div className="text-amber-200">
            Waiting change: {v.pending.kind === 'off' ? 'turn the vault off' : v.pending.kind === 'unfreeze' ? 'unfreeze' : 'new settings'}, lands {when(v.pending.at)}.
          </div>
          <button className={`${btn} bg-amber-600 hover:bg-amber-500`} disabled={busy} onClick={() => act('vault_cancel', { owner: ownerArg, target: 'change' })}>Cancel this change</button>
        </div>
      )}
      {v.queue.length > 0 && (
        <div className="space-y-2">
          <div className="text-xs text-gray-400">Waiting sends</div>
          {v.queue.map(q => (
            <div key={q.id} className="flex items-center justify-between gap-2 text-xs bg-gray-800/70 rounded-lg p-2">
              <div>
                <div>{egoc(q.amount)} EGOC → <span className="font-mono">{short(q.to)}</span></div>
                <div className="text-gray-500">{q.at <= now ? 'ready, going out' : `goes out ${when(q.at)}`}{q.mine ? '' : ' · not started on this device'}</div>
              </div>
              <button className={`${btn} bg-red-600/80 hover:bg-red-500`} disabled={busy} onClick={() => act('vault_cancel', { owner: ownerArg, target: q.id })}>Cancel</button>
            </div>
          ))}
        </div>
      )}
      <div className="flex flex-wrap gap-2">
        {!v.frozen && (
          <button className={`${btn} bg-red-700 hover:bg-red-600`} disabled={busy} onClick={() => act('vault_freeze', { owner: ownerArg })}>Freeze now</button>
        )}
        {own && v.settings.recovery && (
          <button className={`${btn} bg-gray-700 hover:bg-gray-600`} disabled={busy} onClick={() => act('vault_sweep')}>Sweep all to recovery</button>
        )}
        {own && v.frozen && (
          <button className={`${btn} bg-gray-700 hover:bg-gray-600`} disabled={busy} onClick={() => act('vault_unfreeze', { approval: pw ? { password: pw } : null })}>Unfreeze</button>
        )}
        {own && (
          <button className={`${btn} bg-gray-700 hover:bg-gray-600`} disabled={busy} onClick={() => act('vault_turn_off', { approval: pw ? { password: pw } : null })}>Turn vault off</button>
        )}
      </div>
      {own && v.settings.second_key && (
        <input type="password" className={input} value={pw} onChange={e => setPw(e.target.value)} placeholder="Second-key password: unfreeze or turn off at once (optional)" />
      )}
      {own && keyFile && (
        <div className="text-[11px] text-gray-500 break-all">
          Second-key file: {keyFile}{' '}
          <button className="text-blue-300 hover:underline" onClick={async () => {
            const f = await openDialog({ multiple: false, title: 'Find your second-key file', filters: [{ name: 'Ego key file', extensions: ['json'] }] });
            if (typeof f !== 'string') return;
            try { await invoke('vault_use_key_file', { path: f }); setMsg('Key file found.'); onChange(); }
            catch (e) { setMsg(clean(e)); }
          }}>moved it? choose it again</button>
        </div>
      )}
      {msg && <div className="text-xs text-gray-300">{msg}</div>}
    </div>
  );
}

function ApproveRequest() {
  const [code, setCode] = useState('');
  const [preview, setPreview] = useState<RequestPreview | null>(null);
  const [answer, setAnswer] = useState('');
  const [msg, setMsg] = useState('');

  async function look() {
    setMsg(''); setAnswer('');
    try { setPreview(await invoke<RequestPreview>('vault_preview_request', { code })); }
    catch (e) { setPreview(null); setMsg(clean(e)); }
  }

  async function approve() {
    setMsg('');
    try { setAnswer(await invoke<string>('vault_approve_request', { code })); }
    catch (e) { setMsg(clean(e)); }
  }

  return (
    <div className="space-y-2 text-sm">
      <textarea className={`${input} font-mono text-xs h-16`} value={code} onChange={e => { setCode(e.target.value); setPreview(null); setAnswer(''); }} placeholder="egovault1:…" />
      <button className={`${btn} bg-gray-700 hover:bg-gray-600`} disabled={!code.trim()} onClick={look}>Check request</button>
      {preview && (
        <div className="bg-gray-800/70 rounded-lg p-3 text-xs space-y-1">
          <div>Wallet <span className="font-mono">{short(preview.from)}</span> wants to <b>{preview.kind}</b>.</div>
          {preview.kind === 'send' && <div>{egoc(preview.amount)} EGOC to <span className="font-mono break-all">{preview.to}</span></div>}
          {!preview.i_am_second_key && <div className="text-red-400">This wallet is not that vault's second key.</div>}
          {preview.i_am_second_key && !answer && (
            <button className={`${btn} bg-blue-600 hover:bg-blue-500 mt-2`} onClick={approve}>Approve only if you started this</button>
          )}
        </div>
      )}
      {answer && (
        <div className="space-y-1">
          <div className="text-xs text-gray-400">Give this approval back to the other device:</div>
          <QR text={answer} />
          <input readOnly className={`${input} font-mono text-xs`} value={answer} onFocus={e => e.currentTarget.select()} />
          <button className={`${btn} bg-gray-700 hover:bg-gray-600`} onClick={() => navigator.clipboard.writeText(answer)}>Copy approval</button>
        </div>
      )}
      {msg && <div className="text-xs text-red-400">{msg}</div>}
    </div>
  );
}

export default function VaultPanel() {
  const [open, setOpen] = useState(false);
  const [status, setStatus] = useState<VaultStatus | null>(null);
  const [editing, setEditing] = useState(false);
  const [approving, setApproving] = useState(false);

  async function load() {
    try { setStatus(await invoke<VaultStatus>('get_vault_status')); } catch { }
  }

  useEffect(() => {
    load();
    const id = setInterval(load, 15_000);
    return () => clearInterval(id);
  }, []);

  const alertCount = (status?.vault?.queue.filter(q => !q.mine).length ?? 0)
    + (status?.vault?.pending ? 1 : 0)
    + (status?.helping ?? []).reduce((n, v) => n + v.queue.length + (v.pending ? 1 : 0), 0);

  return (
    <div className="bg-gray-800/60 rounded-2xl border border-gray-700/50 overflow-hidden">
      <button onClick={() => setOpen(o => !o)} className="w-full flex items-center justify-between px-5 py-4 hover:bg-gray-700/30 transition">
        <div className="flex items-center gap-2">
          <span className="font-semibold">Vault</span>
          <span className="text-xs text-gray-400">{status?.vault ? (status.vault.frozen ? 'frozen' : 'on') : 'off'}</span>
          {alertCount > 0 && <span className="text-xs bg-amber-500 text-black font-bold rounded-full px-2">{alertCount}</span>}
        </div>
        <span className="text-gray-400">{open ? '▲' : '▼'}</span>
      </button>
      {open && status && (
        <div className="px-5 pb-5 space-y-4">
          {!status.active && (
            <div className="text-xs text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded-lg p-3">
              The wallet vault is built into this version but not switched on in the network yet. It starts at the block set in a coming release.
            </div>
          )}
          <p className="text-xs text-gray-400 leading-relaxed">
            Sends above your daily limit either wait, so you can cancel them, or need your second key. A thief who copies this wallet's key cannot switch the vault off or change it without waiting out the delay.
          </p>
          {status.vault && !editing && <VaultCard v={status.vault} own onChange={load} keyFile={status.key_file} />}
          {status.active && (!status.vault || editing) && (
            <div className={box}>
              <SettingsForm initial={status.vault?.settings ?? null} owner={status.address} existing={!!status.vault} onSaved={() => { setEditing(false); load(); }} />
            </div>
          )}
          {status.vault && status.active && (
            <button className="text-xs text-blue-300 hover:underline" onClick={() => setEditing(e => !e)}>{editing ? 'Close settings' : 'Change settings'}</button>
          )}
          {status.helping.length > 0 && (
            <div className="space-y-2">
              <div className="text-xs text-gray-400">Vaults you protect as guardian or second key</div>
              {status.helping.map(v => <VaultCard key={v.owner} v={v} own={false} onChange={load} />)}
            </div>
          )}
          {status.active && (
            <div>
              <button className="text-xs text-blue-300 hover:underline" onClick={() => setApproving(a => !a)}>
                {approving ? 'Close' : 'Approve a request from another wallet'}
              </button>
              {approving && <div className="mt-2"><ApproveRequest /></div>}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
