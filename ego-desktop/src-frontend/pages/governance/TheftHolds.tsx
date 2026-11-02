import React, { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/tauri';

interface Tally { stake_yes: number; stake_no: number; stake_voters: number; node_yes: number; node_no: number; node_voters: number; }
interface HoldView {
  id: string; requester: string; victim: string; case: string; bond: number;
  theft: string[]; hops: string[]; created: number; phase: string;
  amounts: [string, number][]; held_at: number; vote_ends: number;
  return_opened: number; return_ends: number; appeals: [string, string][];
  confirm: Tally; ret: Tally;
  my_stake_vote: boolean | null; my_node_vote: boolean | null;
  my_return_stake_vote: boolean | null; my_return_node_vote: boolean | null;
  stake_total: number; node_total: number; committee: number; paid: boolean;
}
interface HoldsStatus {
  active: boolean; me: string; is_node: boolean; my_stake: number; my_locked: number;
  node_pool: number; min_node_pool: number; request_fee: number; min_bond: number; holds: HoldView[];
}

const EGOC = 1_000_000;
const egoc = (u: number) => (u / EGOC).toLocaleString(undefined, { maximumFractionDigits: 6 });
const when = (ts: number) => new Date(ts * 1000).toLocaleString();
const short = (a: string) => (a.length > 22 ? `${a.slice(0, 12)}…${a.slice(-6)}` : a);
const clean = (e: any) => String(e?.message ?? e).replace(/^.*Error:/, '').trim();

const PHASE_TEXT: Record<string, string> = {
  signing: 'Waiting for the random committee',
  failed: 'Committee did not sign; nothing was frozen',
  voting: 'Held, vote open',
  confirmed: 'Confirmed hold',
  return_voting: 'Vote to return the coins',
  returned: 'Coins returned to the victim',
  rejected: 'Rejected; bond paid to the held address',
  lapsed: 'Vote missed quorum; released',
  expired: 'Expired after 90 days',
};

const input = 'w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white';
const btn = 'px-3 py-1.5 rounded-lg text-xs font-semibold transition disabled:opacity-40';

function lines(s: string): string[] {
  return s.split(/[\s,]+/).map(x => x.trim()).filter(Boolean);
}

function TallyBar({ t, label }: { t: Tally; label: string }) {
  const s = t.stake_yes + t.stake_no;
  const n = t.node_yes + t.node_no;
  const pct = (a: number, b: number) => (b ? Math.round((a / b) * 100) : 0);
  return (
    <div className="text-[11px] text-gray-400 grid grid-cols-2 gap-2">
      <div>{label} stake: <span className="text-gray-200">{pct(t.stake_yes, s)}% yes</span> · {t.stake_voters} voters</div>
      <div>{label} nodes: <span className="text-gray-200">{pct(t.node_yes, n)}% yes</span> · {t.node_voters} nodes</div>
    </div>
  );
}

function RequestForm({ status, onDone }: { status: HoldsStatus; onDone: () => void }) {
  const [victim, setVictim] = useState(status.me);
  const [theft, setTheft] = useState('');
  const [hops, setHops] = useState('');
  const [caseText, setCaseText] = useState('');
  const [bond, setBond] = useState(String(status.min_bond / EGOC));
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');

  async function send() {
    setBusy(true); setMsg('');
    try {
      const id = await invoke<string>('hold_request', {
        victim, theft: lines(theft), hops: lines(hops), case: caseText, bond: Math.round(parseFloat(bond || '0') * EGOC),
      });
      setMsg(`Request ${id} sent. A random committee checks it within an hour.`);
      onDone();
    } catch (e) { setMsg(clean(e)); }
    finally { setBusy(false); }
  }

  return (
    <div className="space-y-2 text-sm">
      <label className="block space-y-1"><div className="text-xs text-gray-400">Victim address</div>
        <input className={`${input} font-mono`} value={victim} onChange={e => setVictim(e.target.value)} /></label>
      <label className="block space-y-1"><div className="text-xs text-gray-400">Theft transactions out of the victim (hashes, one per line)</div>
        <textarea className={`${input} font-mono h-16`} value={theft} onChange={e => setTheft(e.target.value)} /></label>
      <label className="block space-y-1"><div className="text-xs text-gray-400">Further hops the coins took (optional)</div>
        <textarea className={`${input} font-mono h-16`} value={hops} onChange={e => setHops(e.target.value)} /></label>
      <label className="block space-y-1"><div className="text-xs text-gray-400">What happened</div>
        <textarea className={`${input} h-20`} value={caseText} onChange={e => setCaseText(e.target.value)} /></label>
      <label className="block space-y-1"><div className="text-xs text-gray-400">Bond (EGOC, at least {egoc(status.min_bond)})</div>
        <input className={input} value={bond} onChange={e => setBond(e.target.value)} /></label>
      <div className="text-[11px] text-gray-500 leading-relaxed">
        The request burns a {egoc(status.request_fee)} EGOC fee. The bond stays locked in your wallet while the hold runs. If the vote rejects
        the hold, the bond goes to the held address. If the vote misses quorum, you keep it.
      </div>
      <button className={`${btn} bg-red-600 hover:bg-red-500 w-full py-2`} disabled={busy || !caseText.trim() || !theft.trim()} onClick={send}>
        {busy ? 'Sending…' : 'Request a theft hold'}
      </button>
      {msg && <div className="text-xs text-gray-300">{msg}</div>}
    </div>
  );
}

function HoldCard({ h, status, onChange }: { h: HoldView; status: HoldsStatus; onChange: () => void }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [appeal, setAppeal] = useState('');
  const amHeld = h.amounts.some(([a]) => a === status.me);
  const appealed = h.appeals.some(([a]) => a === status.me);
  const voting = h.phase === 'voting';
  const returning = h.phase === 'return_voting';
  const phase = voting ? 'confirm' : 'return';
  const myStake = voting ? h.my_stake_vote : h.my_return_stake_vote;
  const myNode = voting ? h.my_node_vote : h.my_return_node_vote;

  async function act(cmd: string, args: any) {
    setBusy(true); setMsg('');
    try { await invoke(cmd, args); setMsg('Sent. It counts from the next block.'); onChange(); }
    catch (e) { setMsg(clean(e)); }
    finally { setBusy(false); }
  }

  const total = h.amounts.reduce((n, [, v]) => n + v, 0);
  return (
    <div className="bg-gray-800/60 border border-gray-700/60 rounded-xl p-4 space-y-3">
      <div className="flex justify-between items-start gap-3">
        <div>
          <div className="text-sm font-semibold text-white">{PHASE_TEXT[h.phase] ?? h.phase}</div>
          <div className="text-[11px] text-gray-500 font-mono">{h.id} · requested {when(h.created)} by {short(h.requester)}</div>
        </div>
        <div className="text-right text-[11px] text-gray-400">
          {(voting || h.phase === 'signing') && <div>until {when(h.vote_ends)}</div>}
          {returning && <div>until {when(h.return_ends)}</div>}
        </div>
      </div>
      <div className="text-xs text-gray-300 whitespace-pre-wrap">{h.case}</div>
      <div className="text-[11px] text-gray-400">Victim <span className="font-mono">{short(h.victim)}</span> · bond {egoc(h.bond)} EGOC · committee of {h.committee}</div>
      {h.amounts.length > 0 && (
        <div className="space-y-1">
          <div className="text-[11px] text-gray-400">Held: {egoc(total)} EGOC</div>
          {h.amounts.map(([a, v]) => (
            <div key={a} className="text-[11px] flex justify-between bg-gray-900/60 rounded px-2 py-1">
              <span className="font-mono">{short(a)}</span><span>{egoc(v)} EGOC</span>
            </div>
          ))}
        </div>
      )}
      {h.held_at > 0 && <TallyBar t={h.confirm} label="Confirm" />}
      {h.return_opened > 0 && <TallyBar t={h.ret} label="Return" />}
      {h.appeals.length > 0 && (
        <div className="space-y-1">
          {h.appeals.map(([a, t]) => (
            <div key={a} className="text-[11px] bg-amber-500/10 border border-amber-500/20 rounded p-2">
              <span className="text-amber-300">Appeal from {short(a)}:</span> <span className="text-gray-300">{t}</span>
            </div>
          ))}
        </div>
      )}
      {(voting || returning) && (
        <div className="flex flex-wrap gap-2 items-center">
          {status.my_stake > 0 && (myStake == null ? (
            <>
              <button className={`${btn} bg-green-700 hover:bg-green-600`} disabled={busy} onClick={() => act('hold_vote', { id: h.id, phase, yes: true, asNode: false })}>Stake: {voting ? 'confirm' : 'return'}</button>
              <button className={`${btn} bg-gray-700 hover:bg-gray-600`} disabled={busy} onClick={() => act('hold_vote', { id: h.id, phase, yes: false, asNode: false })}>Stake: no</button>
            </>
          ) : <span className="text-[11px] text-gray-400">Your stake voted {myStake ? 'yes' : 'no'}</span>)}
          {status.is_node && (myNode == null ? (
            <>
              <button className={`${btn} bg-green-700 hover:bg-green-600`} disabled={busy} onClick={() => act('hold_vote', { id: h.id, phase, yes: true, asNode: true })}>Node: {voting ? 'confirm' : 'return'}</button>
              <button className={`${btn} bg-gray-700 hover:bg-gray-600`} disabled={busy} onClick={() => act('hold_vote', { id: h.id, phase, yes: false, asNode: true })}>Node: no</button>
            </>
          ) : <span className="text-[11px] text-gray-400">Your node voted {myNode ? 'yes' : 'no'}</span>)}
          {status.my_stake === 0 && !status.is_node && <span className="text-[11px] text-gray-500">Stake EGOC or run a node to vote.</span>}
        </div>
      )}
      {h.phase === 'confirmed' && h.victim === status.me && h.return_opened === 0 && (
        <button className={`${btn} bg-blue-600 hover:bg-blue-500`} disabled={busy} onClick={() => act('hold_open_return', { id: h.id })}>Open a vote to return the coins to me</button>
      )}
      {amHeld && !appealed && (voting || h.phase === 'confirmed' || returning) && (
        <div className="space-y-2">
          <textarea className={`${input} h-16`} value={appeal} onChange={e => setAppeal(e.target.value)} placeholder="Your one appeal: why this hold is wrong" />
          <button className={`${btn} bg-amber-600 hover:bg-amber-500`} disabled={busy || !appeal.trim()} onClick={() => act('hold_appeal', { id: h.id, text: appeal })}>Send appeal</button>
        </div>
      )}
      {msg && <div className="text-[11px] text-gray-300">{msg}</div>}
    </div>
  );
}

export default function TheftHolds() {
  const [status, setStatus] = useState<HoldsStatus | null>(null);
  const [showForm, setShowForm] = useState(false);

  async function load() {
    try { setStatus(await invoke<HoldsStatus>('get_holds')); } catch { }
  }

  useEffect(() => {
    load();
    const id = setInterval(load, 20_000);
    return () => clearInterval(id);
  }, []);

  if (!status) return <div className="text-sm text-gray-500">Loading theft holds…</div>;

  return (
    <div className="space-y-4">
      <div className="text-xs text-gray-400 leading-relaxed">
        A theft hold stops only the traced stolen amount from leaving an address, for 72 hours, unless both staked holders and nodes vote to
        confirm it. Nobody can take coins with a hold; returning them to the victim needs a second vote. A random committee of online nodes must
        sign each hold first.
      </div>
      {!status.active && (
        <div className="text-xs text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded-lg p-3">
          Theft holds are built into this version but not switched on in the network. They start only after an outside security review and once
          the node pool is large enough ({status.node_pool} of {status.min_node_pool} nodes today).
        </div>
      )}
      {status.my_locked > 0 && (
        <div className="text-xs text-red-300 bg-red-500/10 border border-red-500/30 rounded-lg p-3">
          {egoc(status.my_locked)} EGOC of your wallet is held by a theft hold or locked as a hold bond.
        </div>
      )}
      {status.active && (
        <div>
          <button className="text-xs text-red-300 hover:underline" onClick={() => setShowForm(f => !f)}>
            {showForm ? 'Close' : 'Request a theft hold'}
          </button>
          {showForm && <div className="mt-2 bg-gray-800/60 border border-gray-700/60 rounded-xl p-4"><RequestForm status={status} onDone={() => { setShowForm(false); load(); }} /></div>}
        </div>
      )}
      {status.holds.length === 0
        ? <div className="text-sm text-gray-500">No theft holds.</div>
        : status.holds.map(h => <HoldCard key={h.id} h={h} status={status} onChange={load} />)}
    </div>
  );
}
