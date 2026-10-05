import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  api, assetLabel, assetMeta, ASSETS, ChainAddress, errText, FIATS, fmtAmount, fmtBase, fmtFiat, fmtNumber,
  fmtUnitPrice, isEgoc, MarketParams, marginLabel, methodLabel, METHODS, nativeDecimals, OfferView, payoutProblem,
  positivePct, Quote, reputationLine, shortAddr, Side, toMicro, unitPriceMicro, windowLabel,
} from './api';

interface Props {
  params: MarketParams;
  takerSide: Side;
  asset: string;
  onAsset: (asset: string) => void;
  onPost: (side: Side) => void;
}

function readStored(key: string, fallback: string): string {
  try {
    return localStorage.getItem(key) || fallback;
  } catch {
    return fallback;
  }
}

export function store(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {}
}

export function Avatar({ address, size = 36 }: { address: string; size?: number }) {
  const hue = useMemo(() => {
    let h = 0;
    for (const c of address) h = (h * 31 + c.charCodeAt(0)) % 360;
    return h;
  }, [address]);
  return (
    <div
      className="rounded-full flex items-center justify-center font-bold text-white shrink-0"
      style={{ width: size, height: size, fontSize: size * 0.38, background: `hsl(${hue} 55% 42%)` }}
    >
      {address.slice(5, 7).toUpperCase()}
    </div>
  );
}

export function AssetBadge({ asset, size = 'sm' }: { asset: string; size?: 'sm' | 'md' }) {
  const a = assetMeta(asset);
  return (
    <span className={`inline-flex items-center gap-1.5 ${size === 'md' ? 'text-sm' : 'text-xs'}`}>
      <span className="rounded-full shrink-0" style={{ width: size === 'md' ? 10 : 8, height: size === 'md' ? 10 : 8, background: a.color }} />
      <span className="font-semibold text-white">{a.symbol}</span>
      {a.family !== 'ego' && <span className="text-gray-500">{a.chain}</span>}
    </span>
  );
}

export function Reputation({ profile }: { profile: OfferView['maker_profile'] }) {
  const pct = positivePct(profile);
  return (
    <div className="flex items-center gap-1.5 text-xs text-gray-400">
      {profile.completed > 0 && pct !== null && (
        <span className={`w-1.5 h-1.5 rounded-full ${pct >= 95 ? 'bg-green-400' : pct >= 80 ? 'bg-yellow-400' : 'bg-red-400'}`} />
      )}
      <span>{reputationLine(profile)}</span>
    </div>
  );
}

export function PriceCell({ view, egocUsd }: { view: OfferView; egocUsd: number }) {
  const unit = unitPriceMicro(view.offer.price, egocUsd);
  const symbol = assetMeta(view.offer.asset).symbol;
  return (
    <div>
      <div className="font-mono font-semibold text-white">
        {unit === null ? '—' : fmtUnitPrice(unit, view.offer.fiat)}
      </div>
      <div className="text-[11px] text-gray-500">
        {'margin_bps' in view.offer.price ? marginLabel(view.offer.price.margin_bps) : 'Fixed price'} · per {symbol}
      </div>
    </div>
  );
}

export function AssetSelect({ value, onChange, id }: { value: string; onChange: (asset: string) => void; id: string }) {
  return (
    <select
      id={id}
      value={value}
      onChange={e => onChange(e.target.value)}
      className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white min-w-[220px]"
    >
      <optgroup label="Ego">
        {ASSETS.filter(a => a.family === 'ego').map(a => <option key={a.id} value={a.id}>{a.symbol}</option>)}
      </optgroup>
      <optgroup label="Stablecoins">
        {ASSETS.filter(a => a.symbol === 'USDT' || a.symbol === 'USDC').map(a => (
          <option key={a.id} value={a.id}>{a.symbol} · {a.chain}</option>
        ))}
      </optgroup>
      <optgroup label="Coins">
        {ASSETS.filter(a => a.family !== 'ego' && a.symbol !== 'USDT' && a.symbol !== 'USDC').map(a => (
          <option key={a.id} value={a.id}>{a.symbol} · {a.chain}</option>
        ))}
      </optgroup>
    </select>
  );
}

export default function OfferBook({ params, takerSide, asset, onAsset, onPost }: Props) {
  const navigate = useNavigate();
  const makerSide: Side = takerSide === 'buy' ? 'sell' : 'buy';
  const [fiat, setFiat] = useState(() => readStored('p2p.fiat', 'USD'));
  const [method, setMethod] = useState('');
  const [amount, setAmount] = useState('');
  const [offers, setOffers] = useState<OfferView[] | null>(null);
  const [next, setNext] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [taking, setTaking] = useState<OfferView | null>(null);
  const symbol = assetMeta(asset).symbol;

  const amountMicro = toMicro(amount);

  const load = useCallback(async (cursor?: string) => {
    try {
      const page = await api.offers(asset, fiat, makerSide, method || undefined, undefined, amountMicro || undefined, cursor);
      setOffers(prev => (cursor && prev ? [...prev, ...page.offers] : page.offers));
      setNext(page.next);
      setError('');
    } catch (e) {
      setError(errText(e));
      setOffers([]);
    }
  }, [asset, fiat, makerSide, method, amountMicro]);

  useEffect(() => {
    setOffers(null);
    const t = setTimeout(() => load(), 200);
    return () => clearTimeout(t);
  }, [load]);

  useEffect(() => {
    const t = setInterval(() => load(), 20_000);
    return () => clearInterval(t);
  }, [load]);

  const mine = (o: OfferView) => o.offer.maker === params.my_address;

  return (
    <div className="space-y-4">
      <div className="bg-gray-800 rounded-2xl border border-gray-700 p-4 flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-xs text-gray-400">
          {takerSide === 'buy' ? 'Buy' : 'Sell'}
          <AssetSelect id="p2p-asset" value={asset} onChange={onAsset} />
        </label>
        <label className="flex flex-col gap-1 text-xs text-gray-400">
          {takerSide === 'buy' ? 'Pay with' : 'Get paid in'}
          <select
            id="p2p-fiat"
            value={fiat}
            onChange={e => { setFiat(e.target.value); store('p2p.fiat', e.target.value); }}
            className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white min-w-[150px]"
          >
            {FIATS.map(f => <option key={f.code} value={f.code}>{f.code} · {f.name}</option>)}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs text-gray-400">
          Payment method
          <select
            id="p2p-method"
            value={method}
            onChange={e => setMethod(e.target.value)}
            className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white min-w-[170px]"
          >
            <option value="">Any method</option>
            {METHODS.map(m => <option key={m.id} value={m.id}>{m.label}</option>)}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs text-gray-400">
          Amount
          <div className="relative">
            <input
              id="p2p-amount"
              value={amount}
              onChange={e => setAmount(e.target.value.replace(/[^0-9.,]/g, ''))}
              placeholder="Any"
              className="bg-gray-900 border border-gray-700 rounded-lg pl-3 pr-14 py-2 text-sm text-white w-40"
            />
            <span className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-gray-500">{symbol}</span>
          </div>
        </label>
        <div className="flex-1" />
        <button
          onClick={() => onPost(takerSide === 'buy' ? 'buy' : 'sell')}
          className="text-sm text-blue-400 hover:text-blue-300 px-2 py-2"
        >
          Can't find a deal? Post your own {takerSide === 'buy' ? 'buy' : 'sell'} offer →
        </button>
      </div>

      {!isEgoc(asset) && (
        <div className="text-xs text-gray-400 leading-relaxed px-1">
          {symbol} trades settle on {assetMeta(asset).chain}: the seller locks the coins in the Ego escrow contract there, and
          they go to the buyer only when the seller confirms the payment or an arbiter decides.
        </div>
      )}

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-3 text-sm text-red-300">{error}</div>
      )}

      <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
        <div className="hidden md:grid grid-cols-[1.6fr_1.1fr_1.2fr_1.5fr_auto] gap-4 px-5 py-3 text-[11px] uppercase tracking-wider text-gray-500 border-b border-gray-700">
          <span>{takerSide === 'buy' ? 'Seller' : 'Buyer'}</span>
          <span>Price</span>
          <span>Limits</span>
          <span>Payment</span>
          <span className="w-24" />
        </div>

        {offers === null && (
          <div className="p-10 text-center text-sm text-gray-500 animate-pulse">Loading offers…</div>
        )}

        {offers !== null && offers.length === 0 && !error && (
          <div className="p-10 text-center">
            <div className="text-3xl mb-2">🤝</div>
            <div className="text-sm text-gray-300">
              Nobody is {makerSide === 'sell' ? 'selling' : 'buying'} {assetLabel(asset)} for {fiat}
              {method ? ` by ${methodLabel(method)}` : ''} yet.
            </div>
            <button
              onClick={() => onPost(takerSide === 'buy' ? 'buy' : 'sell')}
              className="mt-4 bg-blue-600 hover:bg-blue-500 px-4 py-2 rounded-xl text-sm font-semibold transition"
            >
              Post the first offer
            </button>
          </div>
        )}

        {offers?.map(v => (
          <div
            key={v.offer.id}
            className="grid md:grid-cols-[1.6fr_1.1fr_1.2fr_1.5fr_auto] gap-4 px-5 py-4 border-b border-gray-700/60 last:border-b-0 items-center hover:bg-gray-700/30 transition"
          >
            <div className="flex items-center gap-3 min-w-0">
              <Avatar address={v.offer.maker} />
              <div className="min-w-0">
                <div className="text-sm font-medium text-white font-mono truncate">
                  {shortAddr(v.offer.maker)}
                  {mine(v) && <span className="ml-2 text-[10px] font-sans font-bold uppercase text-blue-400">You</span>}
                </div>
                <Reputation profile={v.maker_profile} />
              </div>
            </div>
            <PriceCell view={v} egocUsd={params.egoc_usd} />
            <div className="text-sm">
              <div className="text-white">
                {fmtNumber(v.offer.min_micro, v.offer.asset)} – {fmtAmount(v.offer.max_micro, v.offer.asset)}
              </div>
              <div className="text-[11px] text-gray-500">Pay within {windowLabel(v.offer.payment_window_secs)}</div>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {v.offer.methods.map(m => (
                <span key={m} className="text-[11px] px-2 py-0.5 rounded-full bg-gray-700 text-gray-200 border border-gray-600">
                  {methodLabel(m)}
                </span>
              ))}
              {v.offer.country && (
                <span className="text-[11px] px-2 py-0.5 rounded-full bg-gray-900 text-gray-400 border border-gray-700">
                  {v.offer.country}
                </span>
              )}
            </div>
            <div className="w-24 flex justify-end">
              {mine(v) ? (
                <span className="text-xs text-gray-500">Your offer</span>
              ) : (
                <button
                  onClick={() => setTaking(v)}
                  disabled={!params.active}
                  className={`w-full py-2 rounded-xl text-sm font-semibold transition disabled:opacity-40 ${
                    takerSide === 'buy' ? 'bg-green-600 hover:bg-green-500' : 'bg-orange-600 hover:bg-orange-500'
                  }`}
                >
                  {takerSide === 'buy' ? 'Buy' : 'Sell'}
                </button>
              )}
            </div>
          </div>
        ))}

        {next && (
          <button onClick={() => load(next)} className="w-full py-3 text-sm text-blue-400 hover:bg-gray-700/30">
            Show more offers
          </button>
        )}
      </div>

      {taking && (
        <TakeOfferModal
          view={taking}
          params={params}
          initialAmount={amount}
          onClose={() => setTaking(null)}
          onOpened={id => navigate(`/p2p/trade/${id}`)}
        />
      )}
    </div>
  );
}

function TakeOfferModal({
  view, params, initialAmount, onClose, onOpened,
}: {
  view: OfferView;
  params: MarketParams;
  initialAmount: string;
  onClose: () => void;
  onOpened: (id: string) => void;
}) {
  const o = view.offer;
  const a = assetMeta(o.asset);
  const outside = !isEgoc(o.asset);
  const buying = o.side === 'sell';
  const [amount, setAmount] = useState(initialAmount);
  const [method, setMethod] = useState(o.methods[0] ?? '');
  const [payout, setPayout] = useState('');
  const [wallet, setWallet] = useState<ChainAddress | null>(null);
  const [quote, setQuote] = useState<Quote | null>(null);
  const [quoteError, setQuoteError] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const amountMicro = toMicro(amount);

  useEffect(() => {
    if (!outside) return;
    api.chainAddress(o.asset).then(w => {
      setWallet(w);
      if (buying) setPayout(w.address);
    }).catch(e => setError(errText(e)));
  }, [o.asset, outside, buying]);

  useEffect(() => {
    setQuote(null);
    setQuoteError('');
    if (!amountMicro) return;
    const t = setTimeout(() => {
      api.quote(o.id, amountMicro).then(setQuote).catch(e => setQuoteError(errText(e)));
    }, 250);
    return () => clearTimeout(t);
  }, [o.id, amountMicro]);

  async function open() {
    setBusy(true);
    setError('');
    try {
      const id = await api.openTrade(o.id, amountMicro, method, outside && buying ? payout.trim() : undefined);
      onOpened(id);
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  }

  const notReady = outside && wallet !== null && !wallet.escrow_ready;
  const payoutIssue = outside && buying ? payoutProblem(a.family, payout) : null;
  const missingPayout = outside && buying && (!payout.trim() || !!payoutIssue);

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-[150] p-4 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-gray-800 rounded-2xl w-full max-w-lg border border-gray-700 shadow-2xl max-h-[92vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="p-5 border-b border-gray-700 flex items-center gap-3">
          <Avatar address={o.maker} size={40} />
          <div className="flex-1 min-w-0">
            <div className="font-semibold text-white">
              {buying ? `Buy ${a.symbol} from` : `Sell ${a.symbol} to`} <span className="font-mono">{shortAddr(o.maker)}</span>
            </div>
            <Reputation profile={view.maker_profile} />
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-white text-xl leading-none">×</button>
        </div>

        <div className="p-5 space-y-4">
          <div className="flex items-center justify-between">
            <AssetBadge asset={o.asset} size="md" />
            {outside && <span className="text-[11px] text-gray-500">Escrow on {a.chain}</span>}
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-gray-900 rounded-xl p-3">
              <div className="text-[11px] text-gray-500 uppercase tracking-wider">Price</div>
              <PriceCell view={view} egocUsd={params.egoc_usd} />
            </div>
            <div className="bg-gray-900 rounded-xl p-3">
              <div className="text-[11px] text-gray-500 uppercase tracking-wider">Limits</div>
              <div className="text-sm text-white mt-1">{fmtNumber(o.min_micro, o.asset)} – {fmtAmount(o.max_micro, o.asset)}</div>
              <div className="text-[11px] text-gray-500">Pay within {windowLabel(o.payment_window_secs)}</div>
            </div>
          </div>

          <label className="block text-xs text-gray-400">
            How much {a.symbol} do you want to {buying ? 'buy' : 'sell'}?
            <div className="relative mt-1">
              <input
                id="p2p-take-amount"
                autoFocus
                value={amount}
                onChange={e => setAmount(e.target.value.replace(/[^0-9.,]/g, ''))}
                placeholder={fmtNumber(o.min_micro, o.asset)}
                className="w-full bg-gray-900 border border-gray-700 rounded-xl pl-4 pr-16 py-3 text-lg text-white font-mono"
              />
              <span className="absolute right-4 top-1/2 -translate-y-1/2 text-sm text-gray-500">{a.symbol}</span>
            </div>
          </label>

          {o.methods.length > 1 && (
            <div>
              <div className="text-xs text-gray-400 mb-1.5">Payment method</div>
              <div className="flex flex-wrap gap-2">
                {o.methods.map(m => (
                  <button
                    key={m}
                    onClick={() => setMethod(m)}
                    className={`px-3 py-1.5 rounded-lg text-sm border transition ${
                      method === m ? 'bg-blue-600 border-blue-500 text-white' : 'bg-gray-900 border-gray-700 text-gray-300 hover:border-gray-500'
                    }`}
                  >
                    {methodLabel(m)}
                  </button>
                ))}
              </div>
            </div>
          )}

          {outside && buying && (
            <label className="block text-xs text-gray-400">
              Receive the {a.symbol} at this {a.chain} address
              <input
                id="p2p-take-payout"
                value={payout}
                onChange={e => setPayout(e.target.value.trim())}
                className="mt-1 w-full bg-gray-900 border border-gray-700 rounded-xl px-3 py-2.5 text-sm text-white font-mono"
              />
              {payoutIssue ? (
                <span className="text-[11px] text-red-300">{payoutIssue}</span>
              ) : (
                <span className="text-[11px] text-gray-500">Filled in with your Ego wallet's {a.chain} address. Use your own wallet so you can cancel without fees.</span>
              )}
            </label>
          )}

          {outside && !buying && wallet && (
            <div className="bg-gray-900 rounded-xl p-3 text-xs text-gray-400 space-y-1">
              <div className="flex justify-between"><span>Your {a.chain} wallet</span><span className="font-mono text-gray-300">{shortAddr(wallet.address)}</span></div>
              <div className="flex justify-between"><span>{a.symbol} balance</span><span className="text-gray-300">{fmtBase(wallet.token_balance, wallet.decimals, a.symbol)}</span></div>
              <div className="flex justify-between"><span>{wallet.native_symbol} for fees</span><span className="text-gray-300">{fmtBase(wallet.native_balance, wallet.native_decimals ?? nativeDecimals(a.family), wallet.native_symbol ?? '')}</span></div>
            </div>
          )}

          {quote && (
            <div className="bg-gray-900 rounded-xl p-4 space-y-2 text-sm">
              {buying ? (
                <>
                  <Row label="You pay" value={fmtFiat(quote.fiat_micro, quote.fiat)} strong />
                  <Row label="You receive" value={fmtAmount(quote.buyer_receives_micro, o.asset)} strong />
                  <Row label="How" value={`${methodLabel(method)} to the seller, after the escrow is funded`} />
                </>
              ) : (
                <>
                  <Row label={outside ? 'You lock next' : 'You lock now'} value={fmtAmount(quote.taker_locks_micro, o.asset)} strong />
                  <Row label="You receive" value={fmtFiat(quote.fiat_micro, quote.fiat)} strong />
                  <Row label="Buyer gets" value={`${fmtAmount(quote.buyer_receives_micro, o.asset)} after their 1% fee`} />
                </>
              )}
            </div>
          )}
          {quoteError && <div className="text-xs text-red-400">{quoteError}</div>}
          {notReady && (
            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-3 text-xs text-yellow-200">
              {a.symbol} on {a.chain} is not set up on this computer yet, so the escrow cannot be funded or checked.
            </div>
          )}

          {o.terms && (
            <div>
              <div className="text-xs text-gray-400 mb-1">{buying ? 'Seller' : 'Buyer'}'s terms</div>
              <div className="bg-gray-900 rounded-xl p-3 text-sm text-gray-300 whitespace-pre-wrap max-h-32 overflow-y-auto">{o.terms}</div>
            </div>
          )}

          <div className="text-xs text-gray-500 leading-relaxed">
            {buying
              ? `The seller has 30 minutes to lock the ${a.symbol} in escrow${outside ? ` on ${a.chain}` : ''}. Only pay after the trade shows the escrow as funded and checked. The coins are released to you when the seller confirms your payment.`
              : outside
                ? `After you open the trade, lock the ${a.symbol} from your ${a.chain} wallet within 30 minutes. Release it only after the buyer's payment is in your account.`
                : `Your EGOC goes into escrow straight away. Release it only after the buyer's payment is in your account.`}
          </div>

          {error && <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-3 text-sm text-red-300">{error}</div>}

          <button
            onClick={open}
            disabled={busy || !quote || !method || notReady || missingPayout}
            className={`w-full py-3 rounded-xl font-semibold transition disabled:opacity-40 ${
              buying ? 'bg-green-600 hover:bg-green-500' : 'bg-orange-600 hover:bg-orange-500'
            }`}
          >
            {busy ? 'Opening trade…' : buying || outside ? 'Open trade' : 'Lock EGOC and open trade'}
          </button>
        </div>
      </div>
    </div>
  );
}

export function Row({ label, value, strong }: { label: string; value: string; strong?: boolean }) {
  return (
    <div className="flex justify-between gap-4">
      <span className="text-gray-400">{label}</span>
      <span className={`text-right ${strong ? 'text-white font-semibold font-mono' : 'text-gray-300'}`}>{value}</span>
    </div>
  );
}
