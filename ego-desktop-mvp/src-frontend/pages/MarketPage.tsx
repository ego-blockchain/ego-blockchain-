import React, { useEffect, useState, useCallback, useRef } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { EGOC_PRICE_USD, EGOC_SUPPLY } from '../constants';

const EGOC_PRICE = EGOC_PRICE_USD;

function generateEgocHistory(n: number): number[] {
  const seed = [0.3,0.7,0.2,0.9,0.4,0.6,0.1,0.8,0.5,0.3,0.7,0.9,0.2,0.6,0.4,
                0.8,0.1,0.5,0.3,0.7,0.2,0.9,0.6,0.4,0.8,0.1,0.5,0.3,0.7,0.9,
                0.2,0.6,0.4,0.8,0.1,0.5,0.3,0.7,0.9,0.2,0.6,0.4,0.8,0.1,0.5,
                0.3,0.7,0.2,0.9,0.4,0.6,0.1,0.8,0.5,0.3,0.7,0.9,0.2,0.6,0.4,
                0.8,0.1,0.5,0.3,0.7,0.2,0.9,0.6,0.4,0.8,0.1,0.5,0.3,0.7,0.9,
                0.2,0.6,0.4,0.8,0.1,0.5,0.3,0.7,0.2,0.9,0.4,0.6,0.1,0.8,0.5];
  let p = 0.80;
  const all: number[] = [];
  for (let i = 0; i < 90; i++) {
    p = p * (1 + 0.018 + (seed[i % seed.length] - 0.5) * 0.18);
    all.push(Math.max(0.1, p));
  }
  const scale = EGOC_PRICE / all[all.length - 1];
  const scaled = all.map(v => v * scale);
  return scaled.slice(Math.max(0, scaled.length - n));
}

// Derive fake OHLC from a close-only series (for EGOC simulated data)
function closeToOhlc(closes: number[]): [number,number,number,number][] {
  return closes.map((c, i) => {
    const prev = closes[i - 1] ?? c;
    const o = prev;
    const swing = c * 0.012;
    const h = Math.max(o, c) + Math.random() * swing;
    const l = Math.min(o, c) - Math.random() * swing;
    return [o, h, l, c];
  });
}

const COIN_MAP = [
  { id: 'btc',   symbol: 'BTC',  name: 'Bitcoin',   cgId: 'bitcoin',      icon: '₿', color: '#f7931a' },
  { id: 'eth',   symbol: 'ETH',  name: 'Ethereum',  cgId: 'ethereum',     icon: 'Ξ', color: '#627EEA' },
  { id: 'bnb',   symbol: 'BNB',  name: 'BNB',       cgId: 'binancecoin',  icon: '◆', color: '#F3BA2F' },
  { id: 'sol',   symbol: 'SOL',  name: 'Solana',    cgId: 'solana',       icon: '◎', color: '#9945FF' },
  { id: 'ada',   symbol: 'ADA',  name: 'Cardano',   cgId: 'cardano',      icon: '₳', color: '#3CC8C8' },
  { id: 'xrp',   symbol: 'XRP',  name: 'XRP',       cgId: 'ripple',       icon: 'X', color: '#00AAE4' },
  { id: 'trx',   symbol: 'TRX',  name: 'Tron',      cgId: 'tron',         icon: 'T', color: '#EF0027' },
  { id: 'ltc',   symbol: 'LTC',  name: 'Litecoin',  cgId: 'litecoin',     icon: 'Ł', color: '#A5A5A5' },
  { id: 'doge',  symbol: 'DOGE', name: 'Dogecoin',  cgId: 'dogecoin',     icon: 'Ð', color: '#C2A633' },
  { id: 'usdt',  symbol: 'USDT', name: 'Tether',    cgId: 'tether',       icon: '₮', color: '#26a17b' },
  { id: 'usdc',  symbol: 'USDC', name: 'USD Coin',  cgId: 'usd-coin',     icon: '$', color: '#2775CA' },
];

const RANGES = [
  { key: '1S',  label: '1 Second',  interval: '',    limit: 0,    minPerBar: 0,     isLive: true,  isAllTime: false },
  { key: '1H',  label: '1 Hour',    interval: '1m',  limit: 60,   minPerBar: 1,     isLive: false, isAllTime: false },
  { key: '4H',  label: '4 Hours',   interval: '5m',  limit: 48,   minPerBar: 5,     isLive: false, isAllTime: false },
  { key: '1W',  label: '1 Week',    interval: '1h',  limit: 168,  minPerBar: 60,    isLive: false, isAllTime: false },
  { key: '1M',  label: '1 Month',   interval: '1d',  limit: 30,   minPerBar: 1440,  isLive: false, isAllTime: false },
  { key: '2M',  label: '2 Months',  interval: '1d',  limit: 60,   minPerBar: 1440,  isLive: false, isAllTime: false },
  { key: '3M',  label: '3 Months',  interval: '1d',  limit: 90,   minPerBar: 1440,  isLive: false, isAllTime: false },
  { key: 'ALL', label: 'All Time',  interval: '1w',  limit: 0,    minPerBar: 10080, isLive: false, isAllTime: true  },
] as const;
type RangeKey = typeof RANGES[number]['key'];
type ChartType = 'line' | 'candle';

const LIVE_MAX = 120;

function fmtPrice(p: number): string {
  if (!p) return '—';
  if (p >= 1000) return '$' + p.toLocaleString(undefined, { maximumFractionDigits: 0 });
  if (p >= 1)    return '$' + p.toFixed(2);
  if (p >= 0.01) return '$' + p.toFixed(4);
  return '$' + p.toFixed(8);
}

function fmtTooltipDate(idx: number, totalBars: number, minPerBar: number, isLive: boolean): string {
  if (isLive) { return idx === totalBars - 1 ? 'Now' : `${totalBars - 1 - idx}s ago`; }
  const now    = new Date();
  const totalMs = (totalBars - 1) * minPerBar * 60 * 1000;
  const d       = new Date(now.getTime() - totalMs + idx * minPerBar * 60 * 1000);
  if (minPerBar < 1440)
    return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

const W = 680, H = 160;

// ── Line chart ────────────────────────────────────────────────────────────────
function LineChart({ data, color, gradId, minPerBar, isLive }: {
  data: number[]; color: string; gradId: string; minPerBar: number; isLive: boolean;
}) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);

  if (data.length < 2) return (
    <div className="flex items-center justify-center h-40 text-gray-600 text-sm">
      {isLive ? 'Waiting for live data…' : 'No chart data available'}
    </div>
  );

  const min = Math.min(...data), max = Math.max(...data), range = max - min || 1;
  const toX = (i: number) => (i / (data.length - 1)) * W;
  const toY = (v: number) => H - ((v - min) / range) * (H - 16) - 8;
  const pts  = data.map((v, i) => `${toX(i)},${toY(v)}`).join(' ');

  function onMouseMove(e: React.MouseEvent<SVGSVGElement>) {
    if (!svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    setHoverIdx(Math.max(0, Math.min(data.length - 1, Math.round((e.clientX - rect.left) / rect.width * (data.length - 1)))));
  }

  let overlay: React.ReactNode = null;
  if (hoverIdx !== null) {
    const hx = toX(hoverIdx), hy = toY(data[hoverIdx]);
    const TW = 160, TH = 40, PAD = 10;
    const tx = hx + PAD + TW > W ? hx - PAD - TW : hx + PAD;
    const ty = Math.max(4, Math.min(hy - TH / 2, H - TH - 4));
    overlay = (
      <g>
        <line x1={hx} y1={0} x2={hx} y2={H} stroke={color} strokeWidth="1" strokeDasharray="4 3" opacity="0.5" />
        <circle cx={hx} cy={hy} r="4" fill={color} stroke="#1f2937" strokeWidth="2" />
        <rect x={tx} y={ty} width={TW} height={TH} rx="6" fill="#111827" stroke={color} strokeWidth="1" opacity="0.96" />
        <text x={tx+TW/2} y={ty+15} textAnchor="middle" fill="white" fontSize="13" fontWeight="bold">{fmtPrice(data[hoverIdx])}</text>
        <text x={tx+TW/2} y={ty+30} textAnchor="middle" fill="#9ca3af" fontSize="10">{fmtTooltipDate(hoverIdx, data.length, minPerBar, isLive)}</text>
      </g>
    );
  }

  return (
    <svg ref={svgRef} viewBox={`0 0 ${W} ${H}`} className="w-full cursor-crosshair"
      style={{ height: '160px' }} preserveAspectRatio="none"
      onMouseMove={onMouseMove} onMouseLeave={() => setHoverIdx(null)}>
      <defs>
        <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.3" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polygon points={`0,${H} ${pts} ${W},${H}`} fill={`url(#${gradId})`} />
      <polyline points={pts} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" />
      {isLive && <circle cx={toX(data.length-1)} cy={toY(data[data.length-1])} r="4" fill={color} opacity="0.9" />}
      {overlay}
    </svg>
  );
}

// ── Candle chart ──────────────────────────────────────────────────────────────
function CandleChart({ data, minPerBar, isLive }: {
  data: [number,number,number,number][]; minPerBar: number; isLive: boolean;
}) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);

  if (data.length < 2) return (
    <div className="flex items-center justify-center h-40 text-gray-600 text-sm">
      {isLive ? 'Waiting for live data…' : 'No chart data available'}
    </div>
  );

  const allPrices = data.flatMap(([o,h,l,c]) => [o,h,l,c]);
  const min = Math.min(...allPrices), max = Math.max(...allPrices), range = max - min || 1;
  const toY = (v: number) => H - ((v - min) / range) * (H - 16) - 8;

  const candleW = Math.max(1, W / data.length - 1);
  const gap     = W / data.length;

  function onMouseMove(e: React.MouseEvent<SVGSVGElement>) {
    if (!svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    setHoverIdx(Math.max(0, Math.min(data.length - 1, Math.floor((e.clientX - rect.left) / rect.width * data.length))));
  }

  let overlay: React.ReactNode = null;
  if (hoverIdx !== null) {
    const [o, h, l, c] = data[hoverIdx];
    const cx = hoverIdx * gap + gap / 2;
    const TW = 180, TH = 68, PAD = 10;
    const tx = cx + PAD + TW > W ? cx - PAD - TW : cx + PAD;
    const ty = Math.max(4, Math.min(toY(h) - TH / 2, H - TH - 4));
    const bullish = c >= o;
    overlay = (
      <g>
        <line x1={cx} y1={0} x2={cx} y2={H} stroke="#6b7280" strokeWidth="1" strokeDasharray="4 3" opacity="0.5" />
        <rect x={tx} y={ty} width={TW} height={TH} rx="6" fill="#111827" stroke="#374151" strokeWidth="1" opacity="0.97" />
        <text x={tx+6} y={ty+14} fill={bullish ? '#22c55e' : '#ef4444'} fontSize="10" fontWeight="bold">{bullish ? '▲' : '▼'} {fmtPrice(c)}</text>
        <text x={tx+6} y={ty+28} fill="#9ca3af" fontSize="9">O: <tspan fill="white">{fmtPrice(o)}</tspan>  H: <tspan fill="#22c55e">{fmtPrice(h)}</tspan></text>
        <text x={tx+6} y={ty+40} fill="#9ca3af" fontSize="9">L: <tspan fill="#ef4444">{fmtPrice(l)}</tspan>  C: <tspan fill="white">{fmtPrice(c)}</tspan></text>
        <text x={tx+6} y={ty+56} fill="#6b7280" fontSize="9">{fmtTooltipDate(hoverIdx, data.length, minPerBar, isLive)}</text>
      </g>
    );
  }

  return (
    <svg ref={svgRef} viewBox={`0 0 ${W} ${H}`} className="w-full cursor-crosshair"
      style={{ height: '160px' }} preserveAspectRatio="none"
      onMouseMove={onMouseMove} onMouseLeave={() => setHoverIdx(null)}>
      {data.map(([o, h, l, c], i) => {
        const x    = i * gap + gap / 2;
        const bull = c >= o;
        const clr  = bull ? '#22c55e' : '#ef4444';
        const bodyY1 = toY(Math.max(o, c));
        const bodyY2 = toY(Math.min(o, c));
        const bodyH  = Math.max(1, bodyY2 - bodyY1);
        return (
          <g key={i}>
            <line x1={x} y1={toY(h)} x2={x} y2={toY(l)} stroke={clr} strokeWidth="1" opacity="0.8" />
            <rect x={x - candleW / 2} y={bodyY1} width={candleW} height={bodyH}
              fill={bull ? clr : clr} opacity={hoverIdx === i ? 1 : 0.85}
              stroke={hoverIdx === i ? 'white' : clr} strokeWidth={hoverIdx === i ? 0.5 : 0} />
          </g>
        );
      })}
      {overlay}
    </svg>
  );
}

// ── Range popup ───────────────────────────────────────────────────────────────
function RangeDropdown({ value, onChange }: { value: RangeKey; onChange: (k: RangeKey) => void }) {
  const [open, setOpen] = useState(false);
  const current = RANGES.find(r => r.key === value)!;
  return (
    <>
      <button onClick={() => setOpen(true)}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gray-700 hover:bg-gray-600 text-xs font-medium text-gray-200 transition">
        {current.isLive && <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />}
        {current.label} <span className="text-gray-400 text-[10px]">▼</span>
      </button>
      {open && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-[9999]"
          onClick={() => setOpen(false)}>
          <div className="bg-gray-800 border border-gray-600 rounded-2xl shadow-2xl w-56 overflow-hidden"
            onClick={e => e.stopPropagation()}>
            <div className="px-4 py-3 border-b border-gray-700">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide">Select Time Range</p>
            </div>
            {RANGES.map(r => (
              <button key={r.key} onClick={() => { onChange(r.key); setOpen(false); }}
                className={`w-full text-left px-4 py-3 text-sm transition flex items-center justify-between ${
                  r.key === value ? 'bg-blue-600/20 text-blue-300 font-semibold' : 'text-gray-300 hover:bg-gray-700/60'
                }`}>
                <div className="flex items-center gap-2">
                  {r.isLive && <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse shrink-0" />}
                  {r.label}
                </div>
                {r.key === value && <span className="text-blue-400">✓</span>}
              </button>
            ))}
          </div>
        </div>
      )}
    </>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
const MarketPage: React.FC = () => {
  const [rates, setRates]               = useState<Record<string, number>>({});
  const [ratesLoading, setRatesLoading] = useState(true);
  const [selected, setSelected]         = useState<typeof COIN_MAP[0] | null>(null);
  const [rangeKey, setRangeKey]         = useState<RangeKey>('3M');
  const [chartType, setChartType]       = useState<ChartType>('line');

  // Line data (close prices)
  const [lineData, setLineData]         = useState<number[]>([]);
  // Candle data [o,h,l,c]
  const [candleData, setCandleData]     = useState<[number,number,number,number][]>([]);

  const [chartLoading, setChartLoading] = useState(false);
  const [chartError, setChartError]     = useState('');
  const liveRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    invoke<Record<string, number>>('fetch_swap_rates')
      .then(r => { setRates(r); setRatesLoading(false); })
      .catch(() => setRatesLoading(false));
  }, []);

  function stopLive() {
    if (liveRef.current) { clearInterval(liveRef.current); liveRef.current = null; }
  }
  useEffect(() => () => stopLive(), []);

  const fetchChart = useCallback(async (
    coin: typeof COIN_MAP[0] | null,
    rk: RangeKey,
    ct: ChartType,
  ) => {
    stopLive();
    const rng = RANGES.find(r => r.key === rk)!;

    if (rng.isLive) {
      setLineData([]); setCandleData([]); setChartError(''); setChartLoading(false);
      const tick = async () => {
        try {
          const price = !coin
            ? EGOC_PRICE * (1 + (Math.random() - 0.5) * 0.0002)
            : await invoke<number>('fetch_single_price', { coinId: coin.cgId });
          if (ct === 'line') {
            setLineData(p => { const n = [...p, price]; return n.length > LIVE_MAX ? n.slice(-LIVE_MAX) : n; });
          } else {
            setCandleData(p => {
              const prev = p[p.length - 1]?.[3] ?? price;
              const swing = price * 0.001;
              const entry: [number,number,number,number] = [prev, Math.max(prev,price)+swing, Math.min(prev,price)-swing, price];
              const n = [...p, entry];
              return n.length > LIVE_MAX ? n.slice(-LIVE_MAX) : n;
            });
          }
        } catch {}
      };
      tick();
      liveRef.current = setInterval(tick, 1000);
      return;
    }

    if (!coin) {
      const closes = generateEgocHistory(rng.limit === 0 ? 90 : rng.limit);
      setLineData(closes);
      setCandleData(closeToOhlc(closes));
      setChartError('');
      return;
    }

    setChartLoading(true); setChartError('');
    try {
      if (ct === 'line') {
        const d = await invoke<number[]>('fetch_coin_chart', {
          coinId: coin.cgId, klineInterval: rng.interval, limit: rng.limit,
        });
        if (d.length < 2) throw new Error('empty');
        setLineData(d);
      } else {
        const d = await invoke<[number,number,number,number][]>('fetch_coin_candles', {
          coinId: coin.cgId, klineInterval: rng.interval, limit: rng.limit,
        });
        if (d.length < 2) throw new Error('empty');
        setCandleData(d);
      }
    } catch {
      setChartError('Chart data unavailable');
      setLineData([]); setCandleData([]);
    }
    setChartLoading(false);
  }, []);

  useEffect(() => { fetchChart(null, rangeKey, chartType); }, []);

  function selectCoin(coin: typeof COIN_MAP[0] | null) { setSelected(coin); fetchChart(coin, rangeKey, chartType); }
  function changeRange(rk: RangeKey) { setRangeKey(rk); fetchChart(selected, rk, chartType); }
  function toggleChartType(ct: ChartType) { setChartType(ct); fetchChart(selected, rangeKey, ct); }

  const currentRange = RANGES.find(r => r.key === rangeKey)!;
  const activeColor  = selected ? selected.color : '#3b82f6';
  const activePrice  = selected ? (rates[selected.cgId] ?? 0) : EGOC_PRICE;
  const pctBase = chartType === 'line' ? lineData : candleData.map(c => c[3]);
  const pct = pctBase.length > 1
    ? (pctBase[pctBase.length-1] - pctBase[0]) / (pctBase[0] || 1) * 100 : 0;

  return (
    <div className="p-6 space-y-5 max-w-4xl mx-auto">

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Market</h1>
          <p className="text-xs text-gray-400 mt-0.5">Click a coin to view its chart • Hover for price &amp; date</p>
        </div>
        <button onClick={() => { setRatesLoading(true); invoke<Record<string,number>>('fetch_swap_rates').then(r=>{setRates(r);setRatesLoading(false);}).catch(()=>setRatesLoading(false)); }}
          disabled={ratesLoading}
          className="px-3 py-1.5 rounded-lg bg-gray-700 hover:bg-gray-600 text-xs text-gray-300 transition disabled:opacity-50">
          {ratesLoading ? '⟳ Updating…' : '⟳ Refresh'}
        </button>
      </div>

      {/* Chart Card */}
      <div className="bg-gray-800 border border-gray-700 rounded-2xl overflow-hidden">
        <div className="p-5 pb-3">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              {!selected
                ? <img src="/egoc.png" alt="EGOC" className="w-10 h-10 rounded-xl object-contain" style={{ background: '#0a0f1e' }} />
                : <div className="w-10 h-10 rounded-xl flex items-center justify-center text-xl font-bold"
                    style={{ background: activeColor+'22', color: activeColor }}>{selected.icon}</div>
              }
              <div>
                <div className="text-xs text-gray-400 font-medium uppercase tracking-wide flex items-center gap-1.5">
                  {selected ? selected.name : 'Ego Coin'}
                  {currentRange.isLive && <span className="flex items-center gap-1 text-green-400 font-semibold"><span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse"/>LIVE</span>}
                </div>
                <div className="text-3xl font-bold">
                  {currentRange.isLive
                    ? fmtPrice(chartType==='line' ? lineData[lineData.length-1] : candleData[candleData.length-1]?.[3])
                    : fmtPrice(activePrice)}
                </div>
              </div>
            </div>

            <div className="flex flex-col items-end gap-2">
              {pctBase.length > 1 && !currentRange.isLive && (
                <div className={`text-sm font-semibold ${pct>=0?'text-green-400':'text-red-400'}`}>
                  {pct>=0?'▲':'▼'} {Math.abs(pct).toFixed(2)}%
                </div>
              )}
              {!selected && <div className="text-xs text-gray-500">Mkt Cap: ${(EGOC_PRICE*EGOC_SUPPLY/1e9).toFixed(2)}B</div>}

              {/* Chart type toggle */}
              <div className="flex items-center gap-1 bg-gray-900 rounded-lg p-0.5">
                <button onClick={() => toggleChartType('line')}
                  title="Line chart"
                  className={`px-2.5 py-1 rounded-md text-xs font-medium transition ${chartType==='line'?'bg-blue-600 text-white':'text-gray-400 hover:text-gray-200'}`}>
                  〰 Line
                </button>
                <button onClick={() => toggleChartType('candle')}
                  title="Candlestick chart"
                  className={`px-2.5 py-1 rounded-md text-xs font-medium transition ${chartType==='candle'?'bg-blue-600 text-white':'text-gray-400 hover:text-gray-200'}`}>
                  📊 Candles
                </button>
              </div>

              <RangeDropdown value={rangeKey} onChange={changeRange} />
            </div>
          </div>
        </div>

        <div className="px-0 pb-0 min-h-[160px] flex items-center">
          {chartLoading
            ? <div className="w-full flex items-center justify-center h-40 text-gray-500 text-sm">Loading chart…</div>
            : chartError
              ? <div className="w-full flex items-center justify-center h-40 text-gray-600 text-sm">{chartError}</div>
              : chartType === 'line'
                ? <LineChart data={lineData} color={activeColor} gradId="chartGrad" minPerBar={currentRange.minPerBar} isLive={currentRange.isLive} />
                : <CandleChart data={candleData} minPerBar={currentRange.minPerBar} isLive={currentRange.isLive} />
          }
        </div>
      </div>

      {/* Coin list */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wide">Live Prices</h2>
          {selected && <button onClick={() => selectCoin(null)} className="text-xs text-blue-400 hover:text-blue-300 transition">← Back to EGOC</button>}
        </div>

        <button onClick={() => selectCoin(null)}
          className={`w-full flex items-center justify-between rounded-xl px-4 py-3 mb-1.5 transition border ${!selected?'bg-blue-600/10 border-blue-600/40':'bg-gray-800 border-gray-700/50 hover:border-gray-600'}`}>
          <div className="flex items-center gap-3">
            <img src="/egoc.png" alt="EGOC" className="w-8 h-8 rounded-full object-contain shrink-0" style={{ background: '#0a0f1e' }} />
            <div className="text-left">
              <div className="flex items-center gap-1.5">
                <span className="text-sm font-semibold">EGOC</span>
                <span className="text-yellow-400 text-[9px] font-bold bg-yellow-400/15 px-1 py-px rounded">TEST</span>
              </div>
              <div className="text-xs text-gray-500">Ego Coin</div>
            </div>
          </div>
          <div className="text-right">
            <div className="text-sm font-semibold">{fmtPrice(EGOC_PRICE)}</div>
            <div className="text-xs text-green-400">▲ simulated</div>
          </div>
        </button>

        <div className="space-y-1">
          {COIN_MAP.map(coin => {
            const price = rates[coin.cgId] ?? 0;
            const isActive = selected?.id === coin.id;
            return (
              <button key={coin.id} onClick={() => selectCoin(coin)}
                className={`w-full flex items-center justify-between rounded-xl px-4 py-3 transition border ${isActive?'bg-blue-600/10 border-blue-600/40':'bg-gray-800 border-gray-700/50 hover:border-gray-600'}`}>
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold shrink-0"
                    style={{ background: coin.color+'22', color: coin.color }}>{coin.icon}</div>
                  <div className="text-left"><div className="text-sm font-semibold">{coin.symbol}</div><div className="text-xs text-gray-500">{coin.name}</div></div>
                </div>
                <div className="text-sm font-semibold">
                  {ratesLoading && !price ? <span className="text-gray-500 text-xs">Loading…</span> : fmtPrice(price)}
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default MarketPage;
