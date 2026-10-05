import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { listen } from '@tauri-apps/api/event';
import { useWallet } from '../App';
import { useConfirm } from '../hooks/useConfirm';
import {
  api, assetMeta, errText, fmtAmount, fmtEgoc, fmtFiat, fmtNumber, fmtUnitPrice, isEgoc, isOpenStatus, MarketParams,
  marginLabel, methodLabel, OfferView, shortAddr, Side, STATUS_META, TradeView, unitPriceMicro, windowLabel,
} from './p2p/api';
import OfferBook, { AssetBadge, store } from './p2p/OfferBook';
import PostOfferModal from './p2p/PostOfferModal';

type Tab = 'buy' | 'sell' | 'trades' | 'offers' | 'cases';

function TradeList({ load, empty, params }: { load: () => Promise<{ trades: TradeView[] }>; empty: string; params: MarketParams }) {
  const navigate = useNavigate();
  const [trades, setTrades] = useState<TradeView[] | null>(null);
  const [error, setError] = useState('');
  const [onlyOpen, setOnlyOpen] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const page = await load();
      setTrades(page.trades);
      setError('');
    } catch (e) {
      setError(errText(e));
      setTrades([]);
    }
  }, [load]);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 10_000);
    const un1 = listen('ego://market-trade', () => refresh());
    const un2 = listen('ego://market-chat', () => refresh());
    return () => {
      clearInterval(t);
      un1.then(f => f());
      un2.then(f => f());
    };
  }, [refresh]);

  const shown = (trades ?? []).filter(v => !onlyOpen || isOpenStatus(v.status));

  return (
    <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
      <div className="px-5 py-3 border-b border-gray-700 flex items-center justify-between">
        <div className="text-sm text-gray-400">
          {trades ? `${trades.filter(v => isOpenStatus(v.status)).length} open · ${trades.length} total` : 'Loading…'}
        </div>
        <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer">
          <input id="p2p-only-open" type="checkbox" checked={onlyOpen} onChange={e => setOnlyOpen(e.target.checked)} />
          Open trades only
        </label>
      </div>
      {error && <div className="p-4 text-sm text-red-300">{error}</div>}
      {trades && shown.length === 0 && !error && <div className="p-10 text-center text-sm text-gray-500">{empty}</div>}
      {shown.map(v => {
        const t = v.trade;
        const meta = STATUS_META[v.status];
        const role = v.my_role;
        const other = role === 'buyer' ? t.seller : t.buyer;
        return (
          <button
            key={t.id}
            onClick={() => navigate(`/p2p/trade/${t.id}`)}
            className="w-full text-left grid grid-cols-[56px_1fr_150px] md:grid-cols-[56px_minmax(0,1.6fr)_minmax(0,1fr)_minmax(0,0.8fr)_220px] gap-4 px-5 py-3.5 border-b border-gray-700/60 last:border-b-0 items-center hover:bg-gray-700/30 transition"
          >
            <span
              className={`text-[10px] font-bold uppercase w-14 text-center py-1 rounded-md ${
                role === 'buyer' ? 'bg-green-500/15 text-green-400' : role === 'seller' ? 'bg-orange-500/15 text-orange-400' : 'bg-red-500/15 text-red-300'
              }`}
            >
              {role === 'buyer' ? 'Buy' : role === 'seller' ? 'Sell' : 'Judge'}
            </span>
            <div className="min-w-0">
              <div className="text-sm text-white font-medium">
                {fmtAmount(t.amount_micro, t.asset)} <span className="text-gray-400 font-normal">for {fmtFiat(t.fiat_micro, t.fiat)}</span>
              </div>
              <div className="text-xs text-gray-500 font-mono truncate">
                {role === 'arbiter' ? `${shortAddr(t.buyer)} ⇄ ${shortAddr(t.seller)}` : `with ${shortAddr(other)}`}
                {!isEgoc(t.asset) && <span className="font-sans text-gray-600"> · {assetMeta(t.asset).chain}</span>}
              </div>
            </div>
            <div className="hidden md:block text-xs text-gray-400">{methodLabel(t.method)}</div>
            <div className="hidden md:block text-xs text-gray-500">
              {new Date(Date.now() - (v.chain_time - t.opened_at) * 1000).toLocaleDateString()}
            </div>
            <div className="flex items-center gap-2 justify-end">
              {(v.unread ?? 0) > 0 && (
                <span className="text-[10px] font-bold bg-blue-600 text-white rounded-full px-2 py-0.5">{v.unread} new</span>
              )}
              <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-1 rounded-full whitespace-nowrap ${meta.tone}`}>
                {meta.label}
              </span>
            </div>
          </button>
        );
      })}
      {!params.active && trades && trades.length === 0 && (
        <div className="px-5 pb-5 text-xs text-gray-500 text-center">Trades appear here once the market is live.</div>
      )}
    </div>
  );
}

function MyOffers({ params, onPost }: { params: MarketParams; onPost: () => void }) {
  const { confirm, ConfirmDialog } = useConfirm();
  const [offers, setOffers] = useState<OfferView[] | null>(null);
  const [notice, setNotice] = useState<{ ok: boolean; text: string } | null>(null);
  const [closing, setClosing] = useState<string[]>([]);

  const refresh = useCallback(async () => {
    try {
      const v = await api.myOffers();
      setOffers(v.offers);
    } catch (e) {
      setNotice({ ok: false, text: errText(e) });
      setOffers([]);
    }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 10_000);
    return () => clearInterval(t);
  }, [refresh]);

  async function close(o: OfferView) {
    const ok = await confirm('Close this offer?', {
      detail: 'It disappears from the market. Trades already open on it continue.',
      confirmLabel: 'Close offer',
    });
    if (!ok) return;
    try {
      await api.closeOffer(o.offer.id);
      setClosing(c => [...c, o.offer.id]);
      setNotice({ ok: true, text: 'Closing the offer. It leaves the market with the next block.' });
    } catch (e) {
      setNotice({ ok: false, text: errText(e) });
    }
  }

  return (
    <div className="space-y-3">
      {ConfirmDialog}
      {notice && (
        <div className={`rounded-xl p-3 text-sm border ${notice.ok ? 'bg-green-500/10 border-green-500/30 text-green-300' : 'bg-red-500/10 border-red-500/30 text-red-300'}`}>
          {notice.text}
        </div>
      )}
      {offers === null && <div className="p-10 text-center text-sm text-gray-500 animate-pulse">Loading your offers…</div>}
      {offers && offers.length === 0 && (
        <div className="bg-gray-800 rounded-2xl border border-gray-700 p-10 text-center space-y-3">
          <div className="text-sm text-gray-300">You have no offers on the market.</div>
          <button onClick={onPost} disabled={!params.active} className="bg-blue-600 hover:bg-blue-500 disabled:opacity-40 px-4 py-2 rounded-xl text-sm font-semibold">
            Post an offer
          </button>
        </div>
      )}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {offers?.map(v => {
          const o = v.offer;
          const unit = unitPriceMicro(o.price, params.egoc_usd);
          const expired = !v.open && o.closed_height === null;
          const isClosing = closing.includes(o.id);
          const sym = assetMeta(o.asset).symbol;
          return (
            <div key={o.id} className={`bg-gray-800 rounded-2xl border p-5 space-y-3 ${v.open ? 'border-gray-700' : 'border-gray-700/50 opacity-70'}`}>
              <div className="flex items-center justify-between">
                <span className={`text-xs font-bold uppercase tracking-wider px-2.5 py-1 rounded-full ${o.side === 'sell' ? 'bg-orange-500/15 text-orange-400' : 'bg-green-500/15 text-green-400'}`}>
                  {o.side === 'sell' ? 'Selling' : 'Buying'} {sym} · {o.fiat}
                </span>
                <span className="text-xs text-gray-500">{expired ? 'Expired' : v.open ? (isClosing ? 'Closing…' : 'Listed') : 'Closed'}</span>
              </div>
              <AssetBadge asset={o.asset} />
              <div className="flex items-baseline justify-between gap-3">
                <div className="font-mono text-lg text-white">{unit === null ? '—' : fmtUnitPrice(unit, o.fiat)}</div>
                <div className="text-xs text-gray-400">{'margin_bps' in o.price ? marginLabel(o.price.margin_bps) : 'Fixed price'} · per {sym}</div>
              </div>
              <div className="text-sm text-gray-300">
                {fmtNumber(o.min_micro, o.asset)} – {fmtAmount(o.max_micro, o.asset)} · pay within {windowLabel(o.payment_window_secs)}
              </div>
              <div className="flex flex-wrap gap-1.5">
                {o.methods.map(m => (
                  <span key={m} className="text-[11px] px-2 py-0.5 rounded-full bg-gray-700 text-gray-200 border border-gray-600">{methodLabel(m)}</span>
                ))}
              </div>
              {o.closed_height === null && !isClosing && (
                <button onClick={() => close(v)} disabled={!params.active} className="text-sm text-red-300 hover:text-red-200 disabled:opacity-40">
                  {expired ? 'Remove expired offer' : 'Close offer'}
                </button>
              )}
            </div>
          );
        })}
      </div>
      <div className="text-xs text-gray-500">
        You can list up to {params.max_open_offers_per_maker} offers at a time.
      </div>
    </div>
  );
}

function ArbiterPanel({ params, onDone }: { params: MarketParams; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ ok: boolean; text: string } | null>(null);
  const published = params.arbiter_addresses[params.my_address];
  async function publish() {
    setBusy(true);
    setNotice(null);
    try {
      await api.publishArbiter();
      setNotice({ ok: true, text: 'Published. It takes effect with the next block.' });
      onDone();
    } catch (e) {
      setNotice({ ok: false, text: errText(e) });
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="bg-gray-800 rounded-2xl border border-gray-700 p-5 space-y-3">
      <div className="font-semibold text-white">Your arbiter wallets</div>
      <div className="text-sm text-gray-400 leading-relaxed">
        Outside escrows name you as the arbiter by address, so USDT, ETH, TRX, SOL and ADA trades open only once your addresses are on the chain.
        Rulings are sent from these wallets, so keep a little ETH, BNB, POL, TRX, SOL and ADA in them for network fees.
        On Solana and Cardano the market fee is paid to the first arbiter's published address.
      </div>
      {published ? (
        <div className="grid grid-cols-[80px_1fr] gap-y-1 text-xs">
          <span className="text-gray-500">EVM</span><span className="font-mono text-gray-300">{published.evm ?? '—'}</span>
          <span className="text-gray-500">Tron</span><span className="font-mono text-gray-300">{published.tron ?? '—'}</span>
          <span className="text-gray-500">Solana</span><span className="font-mono text-gray-300 break-all">{published.sol ?? '—'}</span>
          <span className="text-gray-500">Cardano</span><span className="font-mono text-gray-300 break-all">{published.ada ?? '—'}</span>
        </div>
      ) : (
        <div className="text-xs text-yellow-300">Not published yet.</div>
      )}
      <button onClick={publish} disabled={busy || !params.active} className="bg-blue-600 hover:bg-blue-500 disabled:opacity-40 px-4 py-2 rounded-xl text-sm font-semibold">
        {busy ? 'Publishing…' : published ? 'Publish again' : 'Publish my arbiter addresses'}
      </button>
      {notice && <div className={`text-sm ${notice.ok ? 'text-green-300' : 'text-red-300'}`}>{notice.text}</div>}
    </div>
  );
}

export default function P2PPage() {
  const { wallet } = useWallet();
  const [params, setParams] = useState<MarketParams | null>(null);
  const [tab, setTab] = useState<Tab>('buy');
  const [asset, setAssetState] = useState(() => {
    try {
      return localStorage.getItem('p2p.asset') || 'EGOC';
    } catch {
      return 'EGOC';
    }
  });
  const [posting, setPosting] = useState<Side | null>(null);
  const [notice, setNotice] = useState('');
  const [unread, setUnread] = useState(0);
  const [error, setError] = useState('');

  const setAsset = (a: string) => {
    setAssetState(a);
    store('p2p.asset', a);
  };

  const loadParams = useCallback(async () => {
    try {
      setParams(await api.params());
      setError('');
    } catch (e) {
      setError(errText(e));
    }
    api.chatUnread().then(m => setUnread(Object.values(m).reduce((a, b) => a + b, 0))).catch(() => {});
  }, []);

  useEffect(() => {
    loadParams();
    const t = setInterval(loadParams, 15_000);
    const un = listen('ego://market-chat', () => loadParams());
    return () => {
      clearInterval(t);
      un.then(f => f());
    };
  }, [loadParams, wallet?.address]);

  const loadTrades = useCallback(() => api.myTrades(), []);
  const loadCases = useCallback(() => api.myCases(), []);

  if (!params) {
    return (
      <div className="p-6">
        <div className="bg-gray-800 rounded-2xl border border-gray-700 p-10 text-center text-sm text-gray-500">
          {error ? <span className="text-red-300">{error}</span> : <span className="animate-pulse">Loading the market…</span>}
        </div>
      </div>
    );
  }

  const isArbiter = params.arbiters.includes(params.my_address);
  const tabs: { id: Tab; label: string; badge?: number }[] = [
    { id: 'buy', label: 'Buy' },
    { id: 'sell', label: 'Sell' },
    { id: 'trades', label: 'My trades', badge: unread },
    { id: 'offers', label: 'My offers' },
    ...(isArbiter ? [{ id: 'cases' as Tab, label: 'Disputes' }] : []),
  ];

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="space-y-1.5">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-white">P2P Trade</h1>
            <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-1 rounded-full ${params.active ? 'bg-green-500/15 text-green-400' : 'bg-yellow-500/15 text-yellow-400'}`}>
              {params.active ? 'Live' : 'Not live yet'}
            </span>
          </div>
          <p className="text-sm text-gray-400 max-w-2xl">
            Buy and sell EGOC, USDT, USDC, ETH, BNB, TRX, POL, SOL and ADA directly with other people for cash, bank transfer or apps.
            The coins wait in escrow until the seller confirms the payment, and an arbiter settles disputes.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-right hidden md:block">
            <div className="text-[11px] text-gray-500 uppercase tracking-wider">EGOC in escrow now</div>
            <div className="text-sm font-mono text-white">{fmtEgoc(params.escrow_held_uegoc)} EGOC · {params.active_trades} trades</div>
          </div>
          <button
            onClick={() => setPosting(tab === 'sell' ? 'sell' : 'buy')}
            disabled={!params.active}
            className="bg-blue-600 hover:bg-blue-500 disabled:opacity-40 px-4 py-2.5 rounded-xl text-sm font-semibold transition"
          >
            + Post an offer
          </button>
        </div>
      </div>

      {!params.active && (
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-2xl p-4 text-sm text-yellow-200 leading-relaxed">
          The P2P market isn't switched on for this network yet. You can look around; posting offers and trading open
          when the network activates it.
        </div>
      )}

      {notice && (
        <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-3 text-sm text-green-300 flex justify-between gap-4">
          <span>{notice}</span>
          <button onClick={() => setNotice('')} className="text-green-400">×</button>
        </div>
      )}

      <div className="flex gap-1 bg-gray-800 border border-gray-700 rounded-xl p-1 w-fit flex-wrap">
        {tabs.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition flex items-center gap-2 ${
              tab === t.id ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-white'
            }`}
          >
            {t.label}
            {(t.badge ?? 0) > 0 && <span className="text-[10px] font-bold bg-blue-600 text-white rounded-full px-1.5 py-0.5">{t.badge}</span>}
          </button>
        ))}
      </div>

      {tab === 'buy' && <OfferBook params={params} takerSide="buy" asset={asset} onAsset={setAsset} onPost={s => setPosting(s)} />}
      {tab === 'sell' && <OfferBook params={params} takerSide="sell" asset={asset} onAsset={setAsset} onPost={s => setPosting(s)} />}
      {tab === 'trades' && <TradeList load={loadTrades} params={params} empty="No trades yet. Take an offer from the Buy or Sell tab." />}
      {tab === 'offers' && <MyOffers params={params} onPost={() => setPosting('sell')} />}
      {tab === 'cases' && (
        <div className="space-y-4">
          <ArbiterPanel params={params} onDone={loadParams} />
          <TradeList load={loadCases} params={params} empty="No disputes have been assigned to you." />
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          ['1', 'Escrow first', 'The seller locks the coins before the buyer pays: EGOC on the Ego chain, USDT and the other coins in the Ego escrow contract on their own network.'],
          ['2', 'Pay off-chain', 'The buyer pays by the agreed method and marks the trade paid. Details stay in the encrypted chat.'],
          ['3', 'Release', 'The seller confirms the money arrived and releases. If something goes wrong, an arbiter decides.'],
        ].map(([n, title, body]) => (
          <div key={n} className="bg-gray-800/60 rounded-2xl border border-gray-700 p-4 flex gap-3">
            <div className="w-7 h-7 rounded-full bg-blue-600/20 text-blue-300 flex items-center justify-center text-sm font-bold shrink-0">{n}</div>
            <div>
              <div className="text-sm font-semibold text-white">{title}</div>
              <div className="text-xs text-gray-400 leading-relaxed mt-0.5">{body}</div>
            </div>
          </div>
        ))}
      </div>

      {posting && (
        <PostOfferModal
          params={params}
          initialSide={posting}
          initialAsset={asset}
          onClose={() => setPosting(null)}
          onPosted={() => {
            setPosting(null);
            setTab('offers');
            setNotice('Offer submitted. It shows up on the market with the next block.');
          }}
        />
      )}
    </div>
  );
}
