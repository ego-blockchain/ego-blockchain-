import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { listen } from '@tauri-apps/api/event';
import { open as openUrl } from '@tauri-apps/api/shell';
import { useConfirm } from '../../hooks/useConfirm';
import {
  api, assetMeta, ChainAddress, ChatMsg, errText, EscrowStatus, fmtAmount, fmtBase, fmtDuration, fmtFiat,
  Family, fmtUnitPrice, isEgoc, isOpenStatus, methodLabel, nativeDecimals, Profile, Rating, reputationLine, shortAddr,
  STATUS_META, TradeRoomView,
} from './api';
import { AssetBadge, Avatar, Row } from './OfferBook';

const GAS: Partial<Record<Family, string>> = { tron: 'TRX', solana: 'SOL', cardano: 'ADA' };

type Tone = 'neutral' | 'yellow' | 'blue' | 'cyan' | 'orange' | 'red' | 'green';

const TONES: Record<Tone, string> = {
  neutral: 'border-gray-700 bg-gray-800',
  yellow: 'border-yellow-500/40 bg-yellow-500/5',
  blue: 'border-blue-500/40 bg-blue-500/5',
  cyan: 'border-cyan-500/40 bg-cyan-500/5',
  orange: 'border-orange-500/40 bg-orange-500/5',
  red: 'border-red-500/40 bg-red-500/5',
  green: 'border-green-500/40 bg-green-500/5',
};

const STEP_TEXT: Record<string, string> = {
  approve: 'Approving the escrow contract to take the coins…',
  open: 'Locking the coins in escrow…',
  record: 'Recording the escrow on Ego…',
};

const NATIVE_STATE = ['not found', 'funded', 'released to the buyer', 'returned to the seller'];

function Panel({
  tone = 'neutral', title, body, timer, timerLabel, children,
}: {
  tone?: Tone;
  title: string;
  body?: React.ReactNode;
  timer?: number | null;
  timerLabel?: string;
  children?: React.ReactNode;
}) {
  return (
    <div className={`rounded-2xl border p-5 space-y-3 ${TONES[tone]}`}>
      <div className="flex items-start justify-between gap-4">
        <div className="text-lg font-semibold text-white">{title}</div>
        {timer != null && (
          <div className={`text-right shrink-0 ${timer <= 300 ? 'text-orange-400' : 'text-gray-300'}`}>
            <div className="font-mono text-xl font-semibold">{timer > 0 ? fmtDuration(timer) : '0s'}</div>
            <div className="text-[11px] text-gray-500">{timerLabel}</div>
          </div>
        )}
      </div>
      {body && <div className="text-sm text-gray-300 leading-relaxed">{body}</div>}
      {children && <div className="flex flex-wrap gap-2 pt-1">{children}</div>}
    </div>
  );
}

function Btn({
  onClick, children, primary, danger, disabled,
}: {
  onClick: () => void;
  children: React.ReactNode;
  primary?: boolean;
  danger?: boolean;
  disabled?: boolean;
}) {
  const style = primary
    ? 'bg-blue-600 hover:bg-blue-500 text-white'
    : danger
      ? 'bg-red-600/15 hover:bg-red-600/25 text-red-300 border border-red-500/40'
      : 'bg-gray-700 hover:bg-gray-600 text-gray-200';
  return (
    <button onClick={onClick} disabled={disabled} className={`px-4 py-2.5 rounded-xl text-sm font-semibold transition disabled:opacity-40 ${style}`}>
      {children}
    </button>
  );
}

const STEPS = ['Trade opened', 'Escrow funded', 'Paid', 'Released'];

function stepIndex(status: string): number {
  if (status === 'awaiting_lock' || status === 'expired') return 0;
  if (status === 'locked' || status === 'payment_overdue') return 1;
  if (status === 'paid' || status === 'disputed') return 2;
  if (status === 'released') return 4;
  return -1;
}

function Stepper({ status }: { status: string }) {
  const idx = stepIndex(status);
  if (idx < 0) return null;
  return (
    <div className="flex items-center gap-2">
      {STEPS.map((s, i) => {
        const done = i < idx;
        const current = i === idx;
        return (
          <React.Fragment key={s}>
            <div className="flex items-center gap-2">
              <div
                className={`w-6 h-6 rounded-full flex items-center justify-center text-[11px] font-bold ${
                  done ? 'bg-green-500 text-white' : current ? 'bg-blue-500 text-white' : 'bg-gray-700 text-gray-400'
                }`}
              >
                {done ? '✓' : i + 1}
              </div>
              <span className={`text-xs ${done || current ? 'text-white' : 'text-gray-500'}`}>{s}</span>
            </div>
            {i < STEPS.length - 1 && <div className={`flex-1 h-px ${done ? 'bg-green-500/60' : 'bg-gray-700'}`} />}
          </React.Fragment>
        );
      })}
    </div>
  );
}

function ProfileCard({ title, address, profile }: { title: string; address: string; profile: Profile }) {
  const since = profile.first_trade_at ? new Date(profile.first_trade_at * 1000).toLocaleDateString() : null;
  return (
    <div className="bg-gray-800 rounded-2xl border border-gray-700 p-4 space-y-3">
      <div className="text-[11px] uppercase tracking-wider text-gray-500">{title}</div>
      <div className="flex items-center gap-3">
        <Avatar address={address} size={40} />
        <div className="min-w-0">
          <div className="font-mono text-sm text-white truncate" title={address}>{shortAddr(address)}</div>
          <div className="text-xs text-gray-400">{reputationLine(profile)}</div>
        </div>
      </div>
      <div className="grid grid-cols-3 gap-2 text-center">
        <Stat label="Positive" value={profile.positive} tone="text-green-400" />
        <Stat label="Negative" value={profile.negative} tone="text-red-400" />
        <Stat label="Disputes lost" value={profile.disputes_lost} tone="text-orange-400" />
      </div>
      {since && <div className="text-[11px] text-gray-500">Trading since {since}</div>}
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="bg-gray-900 rounded-lg py-2">
      <div className={`font-semibold ${tone}`}>{value}</div>
      <div className="text-[10px] text-gray-500">{label}</div>
    </div>
  );
}

function ExternalLink({ href, children }: { href?: string; children: React.ReactNode }) {
  if (!href) return null;
  return (
    <button onClick={() => openUrl(href)} className="text-blue-400 hover:text-blue-300 text-xs underline-offset-2 hover:underline">
      {children}
    </button>
  );
}

function EscrowCard({ view, status }: { view: TradeRoomView; status: EscrowStatus | null }) {
  const t = view.trade;
  const a = assetMeta(t.asset);
  if (isEgoc(t.asset)) return null;
  if (!status) {
    return <div className="bg-gray-800 rounded-2xl border border-gray-700 p-5 text-sm text-gray-500 animate-pulse">Checking the escrow on {a.chain}…</div>;
  }
  if (status.configured === false) {
    return (
      <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-2xl p-5 text-sm text-yellow-200">
        {a.symbol} on {a.chain} is not set up on this computer, so this app cannot check or move the escrow. {status.reason}
      </div>
    );
  }
  if (!status.funded) {
    return (
      <div className="bg-gray-800 rounded-2xl border border-gray-700 p-5 text-sm text-gray-400">
        Nothing is in escrow on {status.network} yet.
      </div>
    );
  }
  const e = status.escrow!;
  const ok = status.verified;
  return (
    <div className={`rounded-2xl border p-5 space-y-3 ${ok ? 'border-green-500/40 bg-green-500/5' : e.state === 1 ? 'border-red-500/40 bg-red-500/5' : 'border-gray-700 bg-gray-800'}`}>
      <div className="flex items-center justify-between gap-3">
        <div className="font-semibold text-white">
          {e.state === 1 ? (ok ? `✓ Escrow verified on ${status.network}` : `✗ Escrow does not match the trade`) : `Escrow ${NATIVE_STATE[e.state] ?? 'settled'}`}
        </div>
        <AssetBadge asset={t.asset} />
      </div>
      {!ok && e.state === 1 && (status.problems ?? []).length > 0 && (
        <ul className="text-sm text-red-300 list-disc pl-5 space-y-0.5">
          {status.problems!.map(p => <li key={p}>{p}</li>)}
        </ul>
      )}
      <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-xs">
        <span className="text-gray-500">Held in escrow</span>
        <span className="text-gray-200 text-right font-mono">{fmtBase(e.total, status.decimals, a.symbol, a.digits)}</span>
        <span className="text-gray-500">Pays the buyer at</span>
        <span className="text-gray-200 text-right font-mono">{shortAddr(e.buyer)}</span>
        <span className="text-gray-500">State on {status.network}</span>
        <span className="text-gray-200 text-right">{NATIVE_STATE[e.state] ?? e.state}{e.frozen ? ' · frozen' : ''}</span>
      </div>
      <div className="flex gap-4">
        <ExternalLink href={status.explorer_tx}>Funding transaction ↗</ExternalLink>
        <ExternalLink href={status.explorer_contract}>Escrow contract ↗</ExternalLink>
      </div>
    </div>
  );
}

function Reference({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {}
  }
  return (
    <span className="inline-flex items-center gap-2 bg-gray-900 border border-gray-600 rounded-lg px-2.5 py-1 align-middle">
      <span className="font-mono text-white tracking-wider">{value}</span>
      <button type="button" onClick={copy} className="text-xs text-blue-300 hover:text-blue-200">
        {copied ? 'Copied' : 'Copy'}
      </button>
    </span>
  );
}

function paymentOf(m: ChatMsg): { name: string; reference: string } | null {
  if (m.kind !== 'payment') return null;
  try {
    const v = JSON.parse(m.text);
    return typeof v?.name === 'string' && typeof v?.reference === 'string' ? v : null;
  } catch {
    return null;
  }
}

function readName(): string {
  try {
    return localStorage.getItem('p2p.payerName') ?? '';
  } catch {
    return '';
  }
}

function TradeChat({ view }: { view: TradeRoomView }) {
  const t = view.trade;
  const [msgs, setMsgs] = useState<ChatMsg[]>([]);
  const [text, setText] = useState('');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState('');
  const bottom = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    try {
      const list = await api.chat(t.id);
      setMsgs(list);
      if (list.some(m => !m.outgoing && !m.read)) await api.chatRead(t.id);
    } catch {}
  }, [t.id]);

  useEffect(() => {
    load();
    const timer = setInterval(load, 5_000);
    const un = listen<{ trade_id: string }>('ego://market-chat', ev => {
      if (ev.payload?.trade_id === t.id) load();
    });
    return () => {
      clearInterval(timer);
      un.then(f => f());
    };
  }, [load, t.id]);

  useEffect(() => {
    bottom.current?.scrollIntoView({ block: 'end' });
  }, [msgs.length]);

  const who = (addr: string) =>
    addr === t.buyer ? 'Buyer' : addr === t.seller ? 'Seller' : addr === t.arbiter ? 'Arbiter' : shortAddr(addr);

  async function send() {
    const body = text.trim();
    if (!body) return;
    setSending(true);
    setError('');
    try {
      await api.chatSend(t.id, body);
      setText('');
      await load();
    } catch (e) {
      setError(errText(e));
    } finally {
      setSending(false);
    }
  }

  return (
    <div className="bg-gray-800 rounded-2xl border border-gray-700 flex flex-col h-[560px]">
      <div className="px-4 py-3 border-b border-gray-700">
        <div className="font-semibold text-white text-sm">Trade chat</div>
        <div className="text-[11px] text-gray-500">
          End-to-end encrypted between {t.arbiter ? 'the buyer, the seller and the arbiter' : 'the buyer and the seller'}.
        </div>
      </div>
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {msgs.length === 0 && (
          <div className="text-center text-xs text-gray-500 mt-10 leading-relaxed px-4">
            Agree on the payment details here. Never share them in the public offer terms.
          </div>
        )}
        {msgs.map(m => {
          const paid = paymentOf(m);
          if (paid) {
            return (
              <div key={m.id} className="flex justify-center">
                <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-xl px-3 py-2 text-xs text-gray-300 text-center max-w-[90%]">
                  <div className="text-cyan-300 font-semibold mb-0.5">{m.outgoing ? 'You marked the trade paid' : 'The buyer marked the trade paid'}</div>
                  Paid from <b className="text-white">{paid.name}</b> with reference <span className="font-mono text-white">{paid.reference}</span>
                  <div className="text-[10px] text-gray-500 mt-0.5">{new Date(m.ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</div>
                </div>
              </div>
            );
          }
          return (
          <div key={m.id} className={`flex ${m.outgoing ? 'justify-end' : 'justify-start'}`}>
            <div className="max-w-[85%]">
              {!m.outgoing && (
                <div className={`text-[10px] mb-0.5 ${m.from === t.arbiter ? 'text-red-300' : 'text-gray-500'}`}>{who(m.from)}</div>
              )}
              <div
                className={`px-3.5 py-2 rounded-2xl text-sm whitespace-pre-wrap break-words ${
                  m.outgoing ? 'bg-blue-600 text-white rounded-br-sm' : m.from === t.arbiter ? 'bg-red-500/15 text-gray-200 rounded-bl-sm' : 'bg-gray-700 text-gray-200 rounded-bl-sm'
                }`}
              >
                {m.text}
              </div>
              <div className={`text-[10px] text-gray-500 mt-0.5 ${m.outgoing ? 'text-right' : ''}`}>
                {new Date(m.ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                {m.outgoing && (m.pending_to.length === 0 ? ' · delivered' : ' · sending')}
              </div>
            </div>
          </div>
          );
        })}
        <div ref={bottom} />
      </div>
      {error && <div className="px-4 pb-2 text-xs text-red-400">{error}</div>}
      <div className="p-3 border-t border-gray-700 flex gap-2">
        <textarea
          id="p2p-chat-input"
          value={text}
          onChange={e => setText(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              send();
            }
          }}
          rows={1}
          placeholder={view.active ? 'Write a message' : 'Chat opens when the market is live'}
          disabled={!view.active || !view.my_role}
          className="flex-1 bg-gray-900 border border-gray-700 rounded-xl px-3 py-2 text-sm text-white resize-none disabled:opacity-50"
        />
        <button
          onClick={send}
          disabled={sending || !text.trim() || !view.active}
          className="bg-blue-600 hover:bg-blue-500 disabled:opacity-40 px-4 rounded-xl text-sm font-semibold transition"
        >
          Send
        </button>
      </div>
    </div>
  );
}

function FeedbackForm({ view, onDone }: { view: TradeRoomView; onDone: () => void }) {
  const [rating, setRating] = useState<Rating>('positive');
  const [comment, setComment] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const role = view.my_role;
  if (role !== 'buyer' && role !== 'seller') return null;
  const mine = view.feedback[role];
  if (mine) {
    return (
      <div className="text-sm text-gray-400">
        You rated this trade <span className="text-white font-medium">{mine.rating}</span>
        {mine.comment ? `: "${mine.comment}"` : '.'}
      </div>
    );
  }
  async function submit() {
    setBusy(true);
    setError('');
    try {
      await api.feedback(view.trade.id, rating, comment);
      onDone();
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  }
  const options: { r: Rating; label: string; tone: string }[] = [
    { r: 'positive', label: '👍 Positive', tone: 'bg-green-600 border-green-500' },
    { r: 'neutral', label: 'Neutral', tone: 'bg-gray-600 border-gray-500' },
    { r: 'negative', label: '👎 Negative', tone: 'bg-red-600 border-red-500' },
  ];
  return (
    <div className="space-y-3 w-full">
      <div className="text-sm text-gray-300">How was trading with the {role === 'buyer' ? 'seller' : 'buyer'}?</div>
      <div className="flex gap-2">
        {options.map(o => (
          <button
            key={o.r}
            onClick={() => setRating(o.r)}
            className={`px-3 py-1.5 rounded-lg text-sm border transition ${rating === o.r ? `${o.tone} text-white` : 'bg-gray-900 border-gray-700 text-gray-300'}`}
          >
            {o.label}
          </button>
        ))}
      </div>
      <input
        id="p2p-feedback-comment"
        value={comment}
        maxLength={280}
        onChange={e => setComment(e.target.value)}
        placeholder="Optional comment, public"
        className="w-full bg-gray-900 border border-gray-700 rounded-xl px-3 py-2 text-sm text-white"
      />
      {error && <div className="text-xs text-red-400">{error}</div>}
      <Btn primary onClick={submit} disabled={busy}>{busy ? 'Sending…' : 'Leave feedback'}</Btn>
    </div>
  );
}

export default function TradeRoom() {
  const { id = '' } = useParams();
  const [view, setView] = useState<TradeRoomView | null>(null);
  const [escrow, setEscrow] = useState<EscrowStatus | null>(null);
  const [wallet, setWallet] = useState<ChainAddress | null>(null);
  const [misses, setMisses] = useState(0);
  const [fetchedAt, setFetchedAt] = useState(Date.now() / 1000);
  const [, setTick] = useState(0);
  const [busy, setBusy] = useState('');
  const [step, setStep] = useState('');
  const [notice, setNotice] = useState<{ ok: boolean; text: string } | null>(null);
  const [waitingFrom, setWaitingFrom] = useState<string | null>(null);
  const [disputeOpen, setDisputeOpen] = useState(false);
  const [reason, setReason] = useState('');
  const [paidOpen, setPaidOpen] = useState(false);
  const [payerName, setPayerName] = useState(readName);
  const [releaseOpen, setReleaseOpen] = useState(false);
  const [checks, setChecks] = useState([false, false, false]);
  const { confirm, ConfirmDialog } = useConfirm();

  const load = useCallback(async () => {
    try {
      const v = await api.trade(id);
      setView(v);
      setFetchedAt(Date.now() / 1000);
      setMisses(0);
      if (!isEgoc(v.trade.asset)) {
        api.escrowStatus(id).then(setEscrow).catch(() => {});
      }
    } catch {
      setMisses(m => m + 1);
    }
  }, [id]);

  useEffect(() => {
    load();
    const t = setInterval(load, 5_000);
    return () => clearInterval(t);
  }, [load]);

  useEffect(() => {
    const t = setInterval(() => setTick(x => x + 1), 1_000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const un1 = listen<{ trade_id: string }>('ego://market-trade', ev => {
      if (ev.payload?.trade_id === id) load();
    });
    const un2 = listen<{ trade_id: string; step: string }>('ego://market-progress', ev => {
      if (ev.payload?.trade_id === id) setStep(ev.payload.step);
    });
    return () => {
      un1.then(f => f());
      un2.then(f => f());
    };
  }, [id, load]);

  const asset = view?.trade.asset;
  const sellerView = view?.my_role === 'seller';
  useEffect(() => {
    if (!asset || isEgoc(asset) || !sellerView) return;
    api.chainAddress(asset).then(setWallet).catch(() => {});
  }, [asset, sellerView]);

  useEffect(() => {
    if (view && waitingFrom && view.status !== waitingFrom) {
      setWaitingFrom(null);
      setNotice(null);
    }
  }, [view, waitingFrom]);

  if (!view) {
    return (
      <div className="p-6 max-w-3xl">
        <Link to="/p2p" className="text-sm text-blue-400 hover:text-blue-300">← P2P Trade</Link>
        <div className="mt-6 bg-gray-800 rounded-2xl border border-gray-700 p-10 text-center space-y-3">
          <div className="text-3xl animate-pulse">⏳</div>
          <div className="text-white font-semibold">Waiting for the network to record this trade</div>
          <div className="text-sm text-gray-400">
            {misses < 24
              ? 'It appears after the next block, usually within a few seconds.'
              : 'It is taking longer than usual. If the offer was closed or your transaction was refused, the trade will not appear.'}
          </div>
          <div className="text-[11px] text-gray-600 font-mono break-all">{id}</div>
        </div>
      </div>
    );
  }

  const room: TradeRoomView = view;
  const t = room.trade;
  const meta = assetMeta(t.asset);
  const outside = !isEgoc(t.asset);
  const role = room.my_role;
  const status = room.status;
  const nowChain = room.chain_time + (Date.now() / 1000 - fetchedAt);
  const left = (deadline: number | null) => (deadline == null ? null : deadline - nowChain);
  const fiat = fmtFiat(t.fiat_micro, t.fiat);
  const amount = fmtAmount(t.amount_micro, t.asset);
  const locked = fmtAmount(t.locked_micro, t.asset);
  const buyerGets = fmtAmount(t.locked_micro - t.maker_fee_micro, t.asset);
  const method = methodLabel(t.method);
  const meta2 = STATUS_META[status];
  const canAct = room.active && !busy && !waitingFrom;
  const verified = !outside || escrow?.verified === true;
  const where = outside ? ` on ${meta.chain}` : '';

  async function act(label: string, run: () => Promise<string>, ask?: [string, string, string]) {
    if (ask) {
      const ok = await confirm(ask[0], { detail: ask[1], confirmLabel: ask[2] });
      if (!ok) return;
    }
    setBusy(label);
    setStep('');
    setNotice(null);
    try {
      await run();
      setWaitingFrom(status);
      setNotice({ ok: true, text: `${label}: sent. It takes effect with the next block.` });
    } catch (e) {
      setNotice({ ok: false, text: errText(e) });
    } finally {
      setBusy('');
      setStep('');
    }
  }

  const fund = () =>
    act('Fund escrow', () => api.fund(t.id), [
      `Lock ${locked}${where}?`,
      outside
        ? `That is ${amount} for the buyer plus the 1% fee, sent from your ${meta.chain} wallet to the Ego escrow contract. You pay the ${meta.chain} network fee. Only the buyer's cancellation, your release or the arbiter can move it.`
        : `That is ${amount} for the buyer plus the 1% fee. It stays locked until you release it, the buyer cancels, or the payment window runs out.`,
      'Lock now',
    ]);
  const decline = () => act('Cancel', () => api.cancel(t.id), ['Cancel this trade?', 'No money has moved yet.', 'Cancel trade']);
  const reference = room.payment_reference ?? '';
  const note = room.payment_note ?? null;
  const markPaid = () => {
    setReleaseOpen(false);
    setPaidOpen(true);
  };
  async function confirmPaid() {
    const name = payerName.trim();
    if (!name) return;
    try {
      localStorage.setItem('p2p.payerName', name);
    } catch {}
    setPaidOpen(false);
    await act("I've paid", () => api.markPaid(t.id, name));
  }
  const giveBack = () =>
    act('Cancel', () => api.settle(t.id, 'refund'), [
      `Cancel and return the ${meta.symbol} to the seller?`,
      outside
        ? `Do this only if you have not paid. You sign the return and the seller's app sends it${where}, so you pay no network fee. It cannot be undone.`
        : 'Do this only if you have not paid, or the seller already refunded you. It cannot be undone.',
      `Return ${meta.symbol}`,
    ]);
  const release = () => {
    setPaidOpen(false);
    setChecks([false, false, false]);
    setReleaseOpen(true);
  };
  async function confirmRelease() {
    setReleaseOpen(false);
    await act('Release', () => api.settle(t.id, 'release'));
  }
  const checklist = [
    `${fiat} has arrived. I checked in my own ${method} app, not in a screenshot.`,
    note ? `It came from an account named ${note.name}.` : "It came from an account in the buyer's own name.",
    `The amount is exactly ${fiat}${reference ? ` and the description shows ${reference}, or I matched the payment another way` : ''}.`,
  ];
  const reclaim = () =>
    act('Reclaim', () => api.settle(t.id, 'refund'), [
      `Take back ${locked}?`,
      'The buyer did not mark the trade paid in time. Check your account first in case they paid late.',
      'Reclaim',
    ]);
  const ruling = (outcome: 'release' | 'refund') =>
    act(outcome === 'release' ? 'Ruling: release' : 'Ruling: refund', () => api.settle(t.id, outcome), [
      outcome === 'release' ? `Release ${buyerGets} to the buyer?` : `Return ${locked} to the seller?`,
      `Your ruling settles the escrow${where} and the trade on Ego. It cannot be changed.`,
      'Confirm ruling',
    ]);

  async function submitDispute() {
    setDisputeOpen(false);
    await act('Dispute', () => api.dispute(t.id, reason.trim()));
    setReason('');
  }

  const disputeWait = left(room.buyer_may_dispute_at);
  const busyText = busy ? (STEP_TEXT[step] ?? `${busy}…`) : '';

  function fundPanel(): React.ReactNode {
    const short = outside && wallet && wallet.token_balance != null && wallet.decimals != null
      ? BigInt(wallet.token_balance) < BigInt(Math.round(t.locked_micro)) * BigInt(10) ** BigInt(Math.max(0, wallet.decimals - 6))
      : false;
    return (
      <Panel
        tone="yellow"
        title={`Fund the escrow${where} to start the trade`}
        body={
          <div className="space-y-2">
            <div>
              Lock <b className="text-white">{locked}</b> ({amount} plus the 1% fee). The buyer pays you {fiat} only after the escrow is funded.
            </div>
            {outside && wallet && (
              <div className="bg-gray-900/70 rounded-xl p-3 text-xs space-y-1">
                <div className="flex justify-between"><span className="text-gray-500">From your {meta.chain} wallet</span><span className="font-mono text-gray-300">{shortAddr(wallet.address)}</span></div>
                <div className="flex justify-between"><span className="text-gray-500">{meta.symbol} balance</span><span className={short ? 'text-red-300' : 'text-gray-300'}>{fmtBase(wallet.token_balance, wallet.decimals, meta.symbol)}</span></div>
                <div className="flex justify-between"><span className="text-gray-500">{wallet.native_symbol} for network fees</span><span className="text-gray-300">{fmtBase(wallet.native_balance, wallet.native_decimals ?? nativeDecimals(meta.family), wallet.native_symbol ?? '')}</span></div>
              </div>
            )}
            {short && <div className="text-red-300 text-xs">Not enough {meta.symbol} in this wallet yet.</div>}
          </div>
        }
        timer={left(room.lock_expires_at)}
        timerLabel="left to fund"
      >
        <Btn primary onClick={fund} disabled={!canAct || short || (outside && wallet?.escrow_ready === false)}>
          Lock {locked}{where}
        </Btn>
        <Btn onClick={decline} disabled={!canAct}>Decline</Btn>
      </Panel>
    );
  }

  function actions(): React.ReactNode {
    switch (status) {
      case 'awaiting_lock':
        if (role === 'seller') return fundPanel();
        return (
          <Panel
            title={`Waiting for the seller to lock the ${meta.symbol}${where}`}
            body="Do not pay yet. You pay only once this trade shows the escrow as funded and checked."
            timer={left(room.lock_expires_at)}
            timerLabel="for the seller"
          >
            {role === 'buyer' && <Btn onClick={decline} disabled={!canAct}>Cancel trade</Btn>}
          </Panel>
        );
      case 'expired':
        return (
          <Panel title="The seller did not fund the escrow in time" body="No money moved. You can close the trade.">
            {role && role !== 'arbiter' && <Btn onClick={decline} disabled={!canAct}>Close trade</Btn>}
          </Panel>
        );
      case 'locked':
        if (role === 'buyer') {
          if (!verified) {
            return (
              <Panel
                tone="red"
                title="Do not pay yet"
                body={escrow?.problems?.length
                  ? `The escrow${where} does not match this trade, so your payment would not be protected.`
                  : `This app is still checking the escrow${where}. Pay only once it shows as verified.`}
              >
                <Btn onClick={giveBack} disabled={!canAct}>Cancel trade</Btn>
              </Panel>
            );
          }
          return (
            <Panel
              tone="blue"
              title={`Pay ${fiat} with ${method}`}
              body={
                <div className="space-y-2">
                  <div>The {meta.symbol} is locked in escrow{where}. Ask the seller for the payment details in the chat, send exactly <b className="text-white">{fiat}</b>, then mark the trade paid.</div>
                  {reference && <div>Put this reference in the payment description: <Reference value={reference} /></div>}
                  <div className="text-xs text-gray-400">Pay from an account in your own name. The seller has to refund payments from anyone else.</div>
                </div>
              }
              timer={left(room.payment_due_at)}
              timerLabel="left to pay"
            >
              <Btn primary onClick={markPaid} disabled={!canAct}>I've paid</Btn>
              <Btn onClick={giveBack} disabled={!canAct}>Cancel trade</Btn>
            </Panel>
          );
        }
        return (
          <Panel
            title="Escrow funded. Waiting for the buyer's payment"
            body={`The buyer pays ${fiat} with ${method} and then marks the trade paid. Share your payment details in the chat.`}
            timer={left(room.payment_due_at)}
            timerLabel="for the buyer"
          />
        );
      case 'payment_overdue':
        if (role === 'seller') {
          if (outside) {
            return (
              <Panel tone="orange" title="The buyer did not pay in time" body={`Your ${meta.symbol} stays in escrow${where} until the buyer cancels or the arbiter returns it. Open a dispute and the arbiter sends it back to you.`}>
                <Btn primary onClick={() => setDisputeOpen(true)} disabled={!canAct}>Ask the arbiter to return it</Btn>
              </Panel>
            );
          }
          return (
            <Panel tone="orange" title="The buyer did not pay in time" body="You can take your EGOC back. If the buyer says they paid late, check your account first.">
              <Btn primary onClick={reclaim} disabled={!canAct}>Reclaim {locked}</Btn>
            </Panel>
          );
        }
        return (
          <Panel tone="orange" title="Your time to pay has run out" body="The seller can now ask for the coins back. If you already paid, mark the trade paid now and tell the seller in the chat.">
            {role === 'buyer' && <Btn primary onClick={markPaid} disabled={!canAct}>I've paid</Btn>}
            {role === 'buyer' && <Btn onClick={giveBack} disabled={!canAct}>Cancel trade</Btn>}
          </Panel>
        );
      case 'paid':
        if (role === 'seller') {
          return (
            <Panel
              tone="cyan"
              title={`The buyer says they sent ${fiat}`}
              body={
                <div className="space-y-2">
                  <div>
                    {note ? <>Paid from an account named <b className="text-white">{note.name}</b></> : 'Payment sent'}
                    {reference && <> with reference <Reference value={reference} /></>}.
                  </div>
                  <div>Open your {method} app yourself and find this payment. Release only once <b className="text-white">{fiat}</b> is really there. It cannot be undone.</div>
                  <div className="text-xs text-gray-400">Screenshots and pictures prove nothing: they are easy to fake with editing tools or AI.</div>
                </div>
              }
            >
              <Btn primary onClick={release} disabled={!canAct}>Release {amount}</Btn>
              <Btn danger onClick={() => setDisputeOpen(true)} disabled={!canAct}>I did not receive it</Btn>
            </Panel>
          );
        }
        return (
          <Panel
            title="Waiting for the seller to release"
            body="The seller is checking your payment. If they stop responding you can ask an arbiter to step in."
            timer={disputeWait != null && disputeWait > 0 ? disputeWait : null}
            timerLabel="until you can dispute"
          >
            {role === 'buyer' && (
              <Btn danger onClick={() => setDisputeOpen(true)} disabled={!canAct || (disputeWait ?? 0) > 0}>Open a dispute</Btn>
            )}
          </Panel>
        );
      case 'disputed':
        if (role === 'arbiter') {
          return (
            <Panel
              tone="red"
              title="This trade needs your ruling"
              body={
                <div className="space-y-2">
                  <div>Opened by the {t.disputed_by ?? 'trader'}{t.dispute_reason ? <>: <i>“{t.dispute_reason}”</i></> : '.'}</div>
                  {(note || reference) && (
                    <div>
                      The buyer says they paid{note ? <> from an account named <b className="text-white">{note.name}</b></> : null}
                      {reference ? <> with reference <span className="font-mono text-white">{reference}</span></> : null}.
                    </div>
                  )}
                  <div className="text-xs text-gray-400">
                    A screenshot is not proof. Ask for the bank's transfer ID, the original payment email or a live screen share of the banking app.
                    {outside ? ` Your ruling moves the escrow${where}, so keep some ${GAS[meta.family] ?? 'gas'} in your arbiter wallet.` : ''}
                  </div>
                </div>
              }
            >
              <Btn primary onClick={() => ruling('release')} disabled={!canAct}>Release to the buyer</Btn>
              <Btn onClick={() => ruling('refund')} disabled={!canAct}>Return to the seller</Btn>
            </Panel>
          );
        }
        return (
          <Panel
            tone="red"
            title="An arbiter is reviewing this trade"
            body={<>Arbiter <span className="font-mono">{shortAddr(t.arbiter ?? '')}</span>. Explain what happened in the chat and keep your payment proof ready.{t.dispute_reason ? <> Reason given: <i>“{t.dispute_reason}”</i></> : null}</>}
          >
            {role === 'seller' && <Btn onClick={release} disabled={!canAct}>Release to the buyer anyway</Btn>}
            {role === 'buyer' && <Btn onClick={giveBack} disabled={!canAct}>Return the {meta.symbol} to the seller</Btn>}
          </Panel>
        );
      case 'released':
        return (
          <Panel tone="green" title="Trade complete" body={role === 'buyer' ? `${buyerGets} ${outside ? `went to ${shortAddr(t.buyer_payout ?? '')}${where}` : 'arrived in your wallet'}.` : role === 'seller' ? `You released ${amount} and received ${fiat}.` : `Released to the buyer.`}>
            <FeedbackForm view={room} onDone={load} />
          </Panel>
        );
      case 'refunded': {
        const pending = outside && escrow?.escrow?.state === 1;
        return (
          <Panel
            title="The escrow went back to the seller"
            body={pending
              ? `The trade is closed on Ego. The return${where} is being sent by the seller's app and shows here once it confirms.`
              : `${locked} returned${t.closed_by ? ` (${t.closed_by === 'arbiter' ? 'arbiter ruling' : `by the ${t.closed_by}`})` : ''}.`}
          >
            <FeedbackForm view={room} onDone={load} />
          </Panel>
        );
      }
      case 'cancelled':
        return <Panel title="Trade cancelled" body="No money moved." />;
    }
  }

  const otherTitle = role === 'buyer' ? 'Seller' : 'Buyer';
  const otherAddr = role === 'buyer' ? t.seller : t.buyer;
  const otherProfile = role === 'buyer' ? room.seller_profile : room.buyer_profile;

  return (
    <div className="p-6 space-y-5">
      {ConfirmDialog}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="space-y-1">
          <Link to="/p2p" className="text-sm text-blue-400 hover:text-blue-300">← P2P Trade</Link>
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-2xl font-bold text-white">
              {role === 'seller' ? 'Selling' : role === 'buyer' ? 'Buying' : 'Trade'} {amount}
            </h1>
            <span className={`text-[11px] font-bold uppercase tracking-wider px-2.5 py-1 rounded-full ${meta2.tone}`}>{meta2.label}</span>
            {outside && <AssetBadge asset={t.asset} />}
          </div>
          <div className="text-sm text-gray-400">
            {fiat} · {fmtUnitPrice(t.price_micro, t.fiat)} per {meta.symbol} · {method}
          </div>
        </div>
        {!room.active && (
          <div className="text-xs text-yellow-400 bg-yellow-500/10 border border-yellow-500/30 rounded-xl px-3 py-2">
            The market is not live on this chain, so actions are disabled.
          </div>
        )}
      </div>

      <div className="bg-gray-800 rounded-2xl border border-gray-700 px-5 py-4">
        <Stepper status={status} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[1fr_380px] gap-5">
        <div className="space-y-5 min-w-0">
          {actions()}

          {busy && (
            <div className="rounded-xl p-3 text-sm border border-blue-500/30 bg-blue-500/10 text-blue-200 animate-pulse">{busyText}</div>
          )}

          {notice && (
            <div className={`rounded-xl p-3 text-sm border ${notice.ok ? 'bg-green-500/10 border-green-500/30 text-green-300' : 'bg-red-500/10 border-red-500/30 text-red-300'}`}>
              {notice.text}
            </div>
          )}

          {disputeOpen && (
            <div className="bg-gray-800 rounded-2xl border border-red-500/40 p-5 space-y-3">
              <div className="font-semibold text-white">Open a dispute</div>
              <div className="text-sm text-gray-400">
                An impartial arbiter reviews the chat and your proof, then sends the escrow to whoever is right. Describe what happened.
              </div>
              <textarea
                id="p2p-dispute-reason"
                value={reason}
                maxLength={280}
                onChange={e => setReason(e.target.value)}
                rows={3}
                className="w-full bg-gray-900 border border-gray-700 rounded-xl px-3 py-2 text-sm text-white resize-none"
                placeholder={role === 'seller' ? 'The payment never arrived in my account.' : `I paid at 14:05 by SEPA with reference ${reference || 'EGO-…'}. The seller does not answer.`}
              />
              <div className="flex gap-2">
                <Btn danger onClick={submitDispute} disabled={!canAct}>Open dispute</Btn>
                <Btn onClick={() => setDisputeOpen(false)}>Back</Btn>
              </div>
            </div>
          )}

          {paidOpen && (
            <div className="bg-gray-800 rounded-2xl border border-blue-500/40 p-5 space-y-3">
              <div className="font-semibold text-white">Did you send {fiat}?</div>
              <div className="text-sm text-gray-400">
                Confirm only after the money has left your {method} account. Marking a trade paid without paying counts against your reputation if the seller disputes.
              </div>
              <label className="block text-sm">
                <span className="text-gray-300">Name on the account you paid from</span>
                <input
                  id="p2p-payer-name"
                  value={payerName}
                  maxLength={70}
                  onChange={e => setPayerName(e.target.value)}
                  className="mt-1 w-full bg-gray-900 border border-gray-700 rounded-xl px-3 py-2.5 text-sm text-white"
                  placeholder="As it appears on your bank or app account"
                />
                <span className="text-[11px] text-gray-500">Only the seller and the arbiter see it, in the encrypted chat. It must be your own name.</span>
              </label>
              {reference && <div className="text-sm text-gray-300">Reference you should have used: <Reference value={reference} /></div>}
              <div className="flex gap-2">
                <Btn primary onClick={confirmPaid} disabled={!canAct || !payerName.trim()}>Yes, I've paid</Btn>
                <Btn onClick={() => setPaidOpen(false)}>Not yet</Btn>
              </div>
            </div>
          )}

          {releaseOpen && (
            <div className="bg-gray-800 rounded-2xl border border-cyan-500/40 p-5 space-y-3">
              <div className="font-semibold text-white">Release {amount} to the buyer?</div>
              <div className="text-sm text-gray-400">Tick each line after checking it in your own {method} app. Release cannot be undone.</div>
              <div className="space-y-2">
                {checklist.map((line, i) => (
                  <label key={i} className="flex items-start gap-2.5 text-sm text-gray-200 cursor-pointer">
                    <input
                      id={`p2p-release-check-${i}`}
                      type="checkbox"
                      checked={checks[i]}
                      onChange={e => setChecks(c => c.map((v, j) => (j === i ? e.target.checked : v)))}
                      className="mt-0.5 h-4 w-4 accent-blue-500"
                    />
                    <span>{line}</span>
                  </label>
                ))}
              </div>
              <div className="text-xs text-gray-400">
                If the name is different, do not release. Return the money to the account it came from and open a dispute.{outside ? ` You pay the ${meta.chain} network fee.` : ''}
              </div>
              <div className="flex gap-2">
                <Btn primary onClick={confirmRelease} disabled={!canAct || !checks.every(Boolean)}>Release {amount}</Btn>
                <Btn onClick={() => setReleaseOpen(false)}>Back</Btn>
              </div>
            </div>
          )}

          {outside && <EscrowCard view={room} status={escrow} />}

          <div className="bg-gray-800 rounded-2xl border border-gray-700 p-5 space-y-2 text-sm">
            <div className="text-[11px] uppercase tracking-wider text-gray-500 mb-2">Details</div>
            <Row label="Amount" value={amount} strong />
            <Row label="Total to pay" value={fiat} strong />
            <Row label="Price" value={`${fmtUnitPrice(t.price_micro, t.fiat)} per ${meta.symbol}`} />
            <Row label="Payment method" value={method} />
            <Row label={`Locked in escrow${where}`} value={locked} />
            <Row label={outside ? 'Maker fee' : 'Maker fee (burned)'} value={`${fmtAmount(t.maker_fee_micro, t.asset)}, paid by the ${t.maker === t.seller ? 'seller' : 'buyer'}`} />
            <Row label="Buyer receives" value={buyerGets} />
            {outside && t.buyer_payout && <Row label="Paid out to" value={shortAddr(t.buyer_payout)} />}
            <Row label="Opened" value={new Date(Date.now() - (nowChain - t.opened_at) * 1000).toLocaleString()} />
            <div className="flex justify-between gap-4 pt-1">
              <span className="text-gray-400">Trade ID</span>
              <span className="font-mono text-[11px] text-gray-500 break-all text-right">{t.id}</span>
            </div>
          </div>

          {room.offer?.offer.terms && (
            <div className="bg-gray-800 rounded-2xl border border-gray-700 p-5">
              <div className="text-[11px] uppercase tracking-wider text-gray-500 mb-2">Offer terms</div>
              <div className="text-sm text-gray-300 whitespace-pre-wrap">{room.offer.offer.terms}</div>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {role === 'arbiter' ? (
              <>
                <ProfileCard title="Buyer" address={t.buyer} profile={room.buyer_profile} />
                <ProfileCard title="Seller" address={t.seller} profile={room.seller_profile} />
              </>
            ) : (
              <ProfileCard title={otherTitle} address={otherAddr} profile={otherProfile} />
            )}
          </div>
        </div>

        {role ? (
          <TradeChat view={room} />
        ) : (
          <div className="bg-gray-800 rounded-2xl border border-gray-700 p-5 text-sm text-gray-400 h-fit">
            You are not part of this trade, so its chat is private to the people in it.
          </div>
        )}
      </div>
      {isOpenStatus(status) && role && (
        <div className="text-[11px] text-gray-500">
          Times follow the chain clock, which runs a little behind your computer's clock.
        </div>
      )}
    </div>
  );
}
