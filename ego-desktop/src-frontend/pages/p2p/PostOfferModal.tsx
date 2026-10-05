import React, { useEffect, useMemo, useState } from 'react';
import {
  api, assetMeta, ChainAddress, errText, FIATS, fmtAmount, fmtUnitPrice, isEgoc, MarketParams, METHODS, OfferDraft,
  payoutProblem, Side, toMicro, WINDOWS_MIN,
} from './api';
import { AssetSelect } from './OfferBook';

interface Props {
  params: MarketParams;
  initialSide: Side;
  initialAsset: string;
  onClose: () => void;
  onPosted: (hash: string) => void;
}

const COUNTRY_RE = /^[A-Z]{2}$/;

function defaultPrice(asset: string, egocUsd: number): string {
  if (isEgoc(asset)) return egocUsd ? egocUsd.toFixed(4) : '';
  const symbol = assetMeta(asset).symbol;
  return symbol === 'USDT' || symbol === 'USDC' ? '1.00' : '';
}

export default function PostOfferModal({ params, initialSide, initialAsset, onClose, onPosted }: Props) {
  const [side, setSide] = useState<Side>(initialSide);
  const [asset, setAsset] = useState(initialAsset);
  const [fiat, setFiat] = useState(() => {
    try {
      return localStorage.getItem('p2p.fiat') || 'USD';
    } catch {
      return 'USD';
    }
  });
  const [priceMode, setPriceMode] = useState<'fixed' | 'margin'>('fixed');
  const [price, setPrice] = useState(defaultPrice(initialAsset, params.egoc_usd));
  const [margin, setMargin] = useState('0');
  const [min, setMin] = useState('10');
  const [max, setMax] = useState('1000');
  const [methods, setMethods] = useState<string[]>([]);
  const [windowMin, setWindowMin] = useState(60);
  const [country, setCountry] = useState('');
  const [terms, setTerms] = useState('');
  const [payout, setPayout] = useState('');
  const [wallet, setWallet] = useState<ChainAddress | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const meta = assetMeta(asset);
  const outside = !isEgoc(asset);
  const marginAllowed = !outside && fiat === 'USD';
  const mode = marginAllowed ? priceMode : 'fixed';
  const termsBytes = useMemo(() => new TextEncoder().encode(terms).length, [terms]);

  useEffect(() => {
    setWallet(null);
    setPayout('');
    if (!outside) return;
    api.chainAddress(asset).then(w => {
      setWallet(w);
      setPayout(w.address);
    }).catch(e => setError(errText(e)));
  }, [asset, outside]);

  function pickAsset(next: string) {
    setAsset(next);
    setPrice(defaultPrice(next, params.egoc_usd));
    setPriceMode('fixed');
  }

  const priceMicro = useMemo(() => {
    if (mode === 'fixed') {
      const v = parseFloat(price.replace(/,/g, ''));
      return isFinite(v) && v > 0 ? Math.round(v * 1_000_000) : 0;
    }
    const bps = Math.round((parseFloat(margin) || 0) * 100);
    return Math.round(params.egoc_usd * 1_000_000 * (1 + bps / 10_000));
  }, [mode, price, margin, params.egoc_usd]);

  const marginBps = Math.round((parseFloat(margin) || 0) * 100);
  const minU = toMicro(min);
  const maxU = toMicro(max);
  const lowest = outside ? 1 : params.min_trade_uegoc;

  const problems: string[] = [];
  if (!priceMicro) problems.push('Set a price.');
  if (mode === 'margin' && Math.abs(marginBps) > params.max_margin_bps) {
    problems.push(`The margin is limited to ±${params.max_margin_bps / 100}%.`);
  }
  if (minU < lowest) problems.push(`The minimum is at least ${fmtAmount(lowest, asset)}.`);
  if (maxU < minU) problems.push('The maximum must be at least the minimum.');
  if (!outside && maxU > params.max_trade_uegoc) problems.push(`The maximum is at most ${fmtAmount(params.max_trade_uegoc, asset)}.`);
  if (methods.length === 0) problems.push('Pick at least one payment method.');
  if (country && !COUNTRY_RE.test(country)) problems.push('Country is a two-letter code like DE or US.');
  if (termsBytes > params.max_terms_bytes) problems.push(`Terms are at most ${params.max_terms_bytes} bytes.`);
  if (outside && side === 'buy' && !payout) problems.push(`Say where you receive the ${meta.symbol}.`);
  const payoutIssue = outside && side === 'buy' ? payoutProblem(meta.family, payout) : null;
  if (payoutIssue) problems.push(payoutIssue);
  if (outside && wallet && !wallet.escrow_ready) problems.push(`${meta.symbol} on ${meta.chain} is not set up on this computer yet.`);

  function toggleMethod(id: string) {
    setMethods(prev =>
      prev.includes(id) ? prev.filter(m => m !== id) : prev.length >= params.max_methods ? prev : [...prev, id],
    );
  }

  async function publish() {
    setBusy(true);
    setError('');
    const draft: OfferDraft = {
      side,
      asset,
      fiat,
      price: mode === 'fixed' ? { fixed: priceMicro } : { margin_bps: marginBps },
      min_micro: minU,
      max_micro: maxU,
      methods,
      terms: terms.trim(),
      payment_window_secs: windowMin * 60,
    };
    if (country) draft.country = country;
    if (outside && side === 'buy') draft.payout_address = payout.trim();
    try {
      const hash = await api.postOffer(draft);
      onPosted(hash);
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  }

  const feePct = params.maker_fee_bps / 100;

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-[150] p-4 backdrop-blur-sm" onClick={onClose}>
      <div
        className="bg-gray-800 rounded-2xl w-full max-w-2xl border border-gray-700 shadow-2xl max-h-[90vh] overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
        <div className="p-5 border-b border-gray-700 flex items-center justify-between sticky top-0 bg-gray-800 z-10">
          <div>
            <div className="text-lg font-semibold text-white">Post an offer</div>
            <div className="text-xs text-gray-400">It stays listed for 30 days or until you close it.</div>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-white text-2xl leading-none">×</button>
        </div>

        <div className="p-5 space-y-5">
          <div className="grid grid-cols-2 gap-2 bg-gray-900 p-1 rounded-xl">
            {(['sell', 'buy'] as Side[]).map(s => (
              <button
                key={s}
                onClick={() => setSide(s)}
                className={`py-2.5 rounded-lg text-sm font-semibold transition ${
                  side === s
                    ? s === 'sell' ? 'bg-orange-600 text-white' : 'bg-green-600 text-white'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                I want to {s} {meta.symbol}
              </button>
            ))}
          </div>

          <div className="grid grid-cols-2 gap-4">
            <label className="flex flex-col gap-1 text-xs text-gray-400">
              Coin
              <AssetSelect id="p2p-post-asset" value={asset} onChange={pickAsset} />
            </label>
            <label className="flex flex-col gap-1 text-xs text-gray-400">
              Currency
              <select
                id="p2p-post-fiat"
                value={fiat}
                onChange={e => setFiat(e.target.value)}
                className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white"
              >
                {FIATS.map(f => <option key={f.code} value={f.code}>{f.code} · {f.name}</option>)}
              </select>
            </label>
          </div>

          {!outside && (
            <div className="flex flex-col gap-1 text-xs text-gray-400">
              Price type
              <div className="grid grid-cols-2 gap-1 bg-gray-900 p-1 rounded-lg border border-gray-700 max-w-sm">
                <button
                  onClick={() => setPriceMode('fixed')}
                  className={`py-1.5 rounded-md text-sm ${mode === 'fixed' ? 'bg-gray-700 text-white' : 'text-gray-400'}`}
                >
                  Fixed
                </button>
                <button
                  onClick={() => marginAllowed && setPriceMode('margin')}
                  disabled={!marginAllowed}
                  title={marginAllowed ? '' : 'Market-linked prices are available for EGOC in USD'}
                  className={`py-1.5 rounded-md text-sm disabled:opacity-40 ${mode === 'margin' ? 'bg-gray-700 text-white' : 'text-gray-400'}`}
                >
                  Market-linked
                </button>
              </div>
            </div>
          )}

          {mode === 'fixed' ? (
            <label className="block text-xs text-gray-400">
              Price per {meta.symbol}
              <div className="relative mt-1">
                <input
                  id="p2p-post-price"
                  value={price}
                  onChange={e => setPrice(e.target.value.replace(/[^0-9.,]/g, ''))}
                  className="w-full bg-gray-900 border border-gray-700 rounded-xl pl-4 pr-16 py-2.5 text-white font-mono"
                />
                <span className="absolute right-4 top-1/2 -translate-y-1/2 text-sm text-gray-500">{fiat}</span>
              </div>
              {!outside && fiat === 'USD' && params.egoc_usd > 0 && (
                <span className="text-[11px] text-gray-500 mt-1 inline-block">
                  Network price now: {fmtUnitPrice(Math.round(params.egoc_usd * 1_000_000), 'USD')}
                </span>
              )}
            </label>
          ) : (
            <label className="block text-xs text-gray-400">
              Margin over the network price ({fmtUnitPrice(Math.round(params.egoc_usd * 1_000_000), 'USD')})
              <div className="flex items-center gap-3 mt-1">
                <div className="relative w-40">
                  <input
                    id="p2p-post-margin"
                    value={margin}
                    onChange={e => setMargin(e.target.value.replace(/[^0-9.\-]/g, ''))}
                    className="w-full bg-gray-900 border border-gray-700 rounded-xl pl-4 pr-8 py-2.5 text-white font-mono"
                  />
                  <span className="absolute right-3 top-1/2 -translate-y-1/2 text-sm text-gray-500">%</span>
                </div>
                <span className="text-sm text-gray-300">
                  = {priceMicro ? fmtUnitPrice(priceMicro, 'USD') : '—'} per EGOC today
                </span>
              </div>
            </label>
          )}

          <div className="grid grid-cols-2 gap-4">
            <label className="flex flex-col gap-1 text-xs text-gray-400">
              Minimum per trade
              <div className="relative">
                <input id="p2p-post-min" value={min} onChange={e => setMin(e.target.value.replace(/[^0-9.,]/g, ''))}
                  className="w-full bg-gray-900 border border-gray-700 rounded-xl pl-4 pr-16 py-2.5 text-white font-mono" />
                <span className="absolute right-4 top-1/2 -translate-y-1/2 text-sm text-gray-500">{meta.symbol}</span>
              </div>
            </label>
            <label className="flex flex-col gap-1 text-xs text-gray-400">
              Maximum per trade
              <div className="relative">
                <input id="p2p-post-max" value={max} onChange={e => setMax(e.target.value.replace(/[^0-9.,]/g, ''))}
                  className="w-full bg-gray-900 border border-gray-700 rounded-xl pl-4 pr-16 py-2.5 text-white font-mono" />
                <span className="absolute right-4 top-1/2 -translate-y-1/2 text-sm text-gray-500">{meta.symbol}</span>
              </div>
            </label>
          </div>

          {outside && side === 'buy' && (
            <label className="block text-xs text-gray-400">
              Receive the {meta.symbol} at this {meta.chain} address
              <input
                id="p2p-post-payout"
                value={payout}
                onChange={e => setPayout(e.target.value.trim())}
                className="mt-1 w-full bg-gray-900 border border-gray-700 rounded-xl px-3 py-2.5 text-sm text-white font-mono"
              />
              <span className="text-[11px] text-gray-500">Filled in with your Ego wallet's {meta.chain} address.</span>
            </label>
          )}

          <div>
            <div className="text-xs text-gray-400 mb-2">
              Payment methods <span className="text-gray-500">({methods.length}/{params.max_methods})</span>
            </div>
            <div className="flex flex-wrap gap-2">
              {METHODS.map(m => (
                <button
                  key={m.id}
                  onClick={() => toggleMethod(m.id)}
                  className={`px-3 py-1.5 rounded-lg text-sm border transition ${
                    methods.includes(m.id)
                      ? 'bg-blue-600 border-blue-500 text-white'
                      : 'bg-gray-900 border-gray-700 text-gray-300 hover:border-gray-500'
                  }`}
                >
                  {m.label}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <label className="flex flex-col gap-1 text-xs text-gray-400">
              Time the buyer has to pay
              <select
                id="p2p-post-window"
                value={windowMin}
                onChange={e => setWindowMin(parseInt(e.target.value, 10))}
                className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2.5 text-sm text-white"
              >
                {WINDOWS_MIN.map(m => (
                  <option key={m} value={m}>{m >= 60 ? `${m / 60} hour${m === 60 ? '' : 's'}` : `${m} minutes`}</option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1 text-xs text-gray-400">
              Country (optional)
              <input
                id="p2p-post-country"
                value={country}
                maxLength={2}
                onChange={e => setCountry(e.target.value.toUpperCase().replace(/[^A-Z]/g, ''))}
                placeholder="e.g. DE"
                className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2.5 text-sm text-white uppercase"
              />
            </label>
          </div>

          <label className="block text-xs text-gray-400">
            Terms <span className="text-gray-500">({termsBytes}/{params.max_terms_bytes})</span>
            <textarea
              id="p2p-post-terms"
              value={terms}
              onChange={e => setTerms(e.target.value)}
              rows={4}
              placeholder={side === 'sell'
                ? 'For example: SEPA Instant only. The payment must come from an account in your name. No notes in the reference.'
                : 'For example: I pay by Wise within 10 minutes of the escrow being funded.'}
              className="mt-1 w-full bg-gray-900 border border-gray-700 rounded-xl px-4 py-3 text-sm text-white resize-none"
            />
            <span className="text-[11px] text-gray-500">Terms are public. Share bank details only in the trade chat.</span>
          </label>

          <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-3 text-xs text-blue-200 leading-relaxed">
            {side === 'sell'
              ? outside
                ? `When someone takes this offer you have 30 minutes to lock the ${meta.symbol} plus the ${feePct}% fee in the Ego escrow contract on ${meta.chain}, from this wallet's ${meta.chain} address. You also need a little ${wallet?.native_symbol ?? 'gas'} there for the network fee.${meta.family === 'cardano' ? ' Trades under 100 ADA carry no fee, since Cardano cannot pay out less than 1 ADA.' : ''}`
                : `When someone takes this offer you have 30 minutes to lock the EGOC plus the ${feePct}% fee in escrow from your wallet. The fee is burned only when a trade completes.`
              : outside
                ? `Sellers lock the ${meta.symbol} in the Ego escrow contract on ${meta.chain}. You pay them, they release, and you receive the amount minus the ${feePct}% fee at the address above.${meta.family === 'cardano' ? ' Trades under 100 ADA carry no fee, since Cardano cannot pay out less than 1 ADA.' : ''}`
                : `Sellers lock the EGOC in escrow when they take this offer. You pay them, they release, and you receive the amount minus the ${feePct}% fee, which is burned.`}
          </div>

          {problems.length > 0 && (
            <ul className="text-xs text-yellow-400 space-y-0.5 list-disc pl-4">
              {problems.map(p => <li key={p}>{p}</li>)}
            </ul>
          )}
          {error && <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-3 text-sm text-red-300">{error}</div>}

          <button
            onClick={publish}
            disabled={busy || problems.length > 0 || !params.active}
            className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-40 py-3 rounded-xl font-semibold transition"
          >
            {busy ? 'Publishing…' : 'Publish offer'}
          </button>
        </div>
      </div>
    </div>
  );
}
