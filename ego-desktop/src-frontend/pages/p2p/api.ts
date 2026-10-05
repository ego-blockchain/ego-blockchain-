import { invoke } from '@tauri-apps/api/tauri';

export type Side = 'sell' | 'buy';
export type Price = { fixed: number } | { margin_bps: number };
export type Rating = 'positive' | 'neutral' | 'negative';
export type Role = 'buyer' | 'seller' | 'arbiter';
export type Family = 'ego' | 'evm' | 'tron' | 'solana' | 'cardano';
export type TradeState =
  | 'awaiting_lock' | 'locked' | 'paid' | 'disputed' | 'cancelled' | 'released' | 'refunded';
export type TradeStatus = TradeState | 'expired' | 'payment_overdue';

export interface ArbiterAddresses {
  evm: string | null;
  tron: string | null;
  sol?: string | null;
  ada?: string | null;
}

export interface MarketParams {
  active: boolean;
  escrow_address: string;
  chain_time: number;
  wall_time: number;
  maker_fee_bps: number;
  min_trade_uegoc: number;
  max_trade_uegoc: number;
  max_open_offers_per_maker: number;
  max_pending_trades_per_taker: number;
  max_methods: number;
  max_terms_bytes: number;
  max_note_bytes: number;
  payment_window_secs: [number, number];
  accept_window_secs: number;
  buyer_dispute_delay_secs: number;
  offer_ttl_secs: number;
  feedback_window_secs: number;
  max_margin_bps: number;
  arbiters: string[];
  arbiter_addresses: Record<string, ArbiterAddresses | null>;
  escrow_held_uegoc: number;
  active_trades: number;
  egoc_usd: number;
  my_address: string;
}

export interface Offer {
  id: string;
  maker: string;
  side: Side;
  asset: string;
  fiat: string;
  price: Price;
  min_micro: number;
  max_micro: number;
  methods: string[];
  country: string | null;
  terms: string;
  payment_window_secs: number;
  created_height: number;
  created_at: number;
  expires_at: number;
  closed_height: number | null;
  payout_address: string | null;
}

export interface ProfileSummary {
  completed: number;
  partners: number;
  positive: number;
  neutral: number;
  negative: number;
  volume_uegoc: number;
  disputes_lost: number;
  first_trade_at: number | null;
}

export interface Profile extends ProfileSummary {
  as_buyer: number;
  as_seller: number;
  cancelled: number;
  timed_out: number;
  disputes_opened: number;
  disputes_won: number;
  last_trade_at: number | null;
}

export interface OfferView {
  offer: Offer;
  open: boolean;
  maker_profile: ProfileSummary;
}

export interface OfferPage {
  offers: OfferView[];
  next: string | null;
  chain_time: number;
}

export interface EscrowRef {
  contract: string;
  funder: string;
  tx: string;
}

export interface Trade {
  id: string;
  offer_id: string;
  maker: string;
  taker: string;
  seller: string;
  buyer: string;
  asset: string;
  amount_micro: number;
  maker_fee_micro: number;
  locked_micro: number;
  fiat: string;
  fiat_micro: number;
  price_micro: number;
  method: string;
  payment_window_secs: number;
  state: TradeState;
  opened_height: number;
  opened_at: number;
  locked_at: number | null;
  paid_at: number | null;
  disputed_at: number | null;
  disputed_by: Role | null;
  dispute_reason: string;
  arbiter: string | null;
  closed_at: number | null;
  closed_height: number | null;
  closed_by: Role | null;
  settle_tx: string | null;
  buyer_payout: string | null;
  arbiter_payout: string | null;
  escrow: EscrowRef | null;
  native_sig: string | null;
}

export interface Feedback {
  trade_id: string;
  from: string;
  about: string;
  rating: Rating;
  comment: string;
  height: number;
  at: number;
}

export interface PaymentNote {
  name: string;
  reference: string;
  ts: number;
}

export interface TradeView {
  trade: Trade;
  status: TradeStatus;
  payment_reference?: string;
  lock_expires_at: number | null;
  payment_due_at: number | null;
  buyer_may_dispute_at: number | null;
  feedback: { buyer: Feedback | null; seller: Feedback | null };
  chain_time: number;
  my_role?: Role | null;
  unread?: number;
}

export interface TradeRoomView extends TradeView {
  my_role: Role | null;
  my_address: string;
  offer: OfferView | null;
  buyer_profile: Profile;
  seller_profile: Profile;
  counterparty: string;
  can_chat_arbiter: boolean;
  active: boolean;
  payment_note?: PaymentNote | null;
}

export interface TradePage {
  trades: TradeView[];
  next: string | null;
  chain_time: number;
}

export interface Quote {
  offer_id: string;
  fiat: string;
  amount_micro: number;
  price_micro: number;
  fiat_micro: number;
  maker_fee_micro: number;
  taker_locks_micro: number;
  buyer_receives_micro: number;
  taker_side: Side;
}

export interface ChatMsg {
  id: string;
  from: string;
  kind?: string;
  text: string;
  ts: number;
  outgoing: boolean;
  read: boolean;
  pending_to: string[];
}

export interface OfferDraft {
  side: Side;
  asset: string;
  fiat: string;
  price: Price;
  min_micro: number;
  max_micro: number;
  methods: string[];
  country?: string;
  terms: string;
  payment_window_secs: number;
  payout_address?: string;
}

export interface NativeEscrow {
  seller: string;
  opened_at: number;
  state: number;
  frozen: boolean;
  buyer: string;
  fallback_at: number;
  arbiter: string;
  token: string;
  total: string;
  fee: string;
}

export interface EscrowStatus {
  kind: 'ego' | 'outside';
  configured?: boolean;
  reason?: string;
  funded?: boolean;
  network?: string;
  family?: Family;
  native_symbol?: string;
  decimals?: number;
  escrow?: NativeEscrow;
  contract?: string;
  funder?: string;
  funding_tx?: string;
  explorer_tx?: string;
  explorer_contract?: string;
  verified?: boolean;
  problems?: string[];
}

export interface ChainAddress {
  asset: string;
  address: string;
  network: string;
  family?: Family;
  native_symbol?: string;
  native_balance?: string | null;
  token_balance?: string | null;
  decimals?: number | null;
  native_decimals?: number;
  escrow_ready?: boolean;
  explorer_address?: string;
}

export const api = {
  params: () => invoke<MarketParams>('market_params'),
  offers: (asset: string, fiat: string, side: Side, method?: string, country?: string, amountMicro?: number, cursor?: string) =>
    invoke<OfferPage>('market_offers', { asset, fiat, side, method, country, amountMicro, cursor }),
  offer: (id: string) => invoke<OfferView>('market_offer', { id }),
  quote: (offerId: string, amountMicro: number) => invoke<Quote>('market_quote', { offerId, amountMicro }),
  trade: (id: string) => invoke<TradeRoomView>('market_trade', { id }),
  myTrades: (cursor?: string) => invoke<TradePage>('market_my_trades', { cursor }),
  myCases: (cursor?: string) => invoke<TradePage>('market_my_cases', { cursor }),
  myOffers: () => invoke<{ offers: OfferView[]; chain_time: number }>('market_my_offers'),
  profile: (address: string) => invoke<{ address: string; profile: Profile }>('market_profile', { address }),
  postOffer: (offer: OfferDraft) => invoke<string>('market_post_offer', { offer }),
  closeOffer: (offerId: string) => invoke<string>('market_close_offer', { offerId }),
  openTrade: (offerId: string, amountMicro: number, method: string, payoutAddress?: string) =>
    invoke<string>('market_open_trade', { offerId, amountMicro, method, payoutAddress }),
  fund: (tradeId: string) => invoke<string>('market_fund', { tradeId }),
  cancel: (tradeId: string) => invoke<string>('market_cancel', { tradeId }),
  markPaid: (tradeId: string, payerName: string) => invoke<string>('market_mark_paid', { tradeId, payerName }),
  dispute: (tradeId: string, reason: string) => invoke<string>('market_dispute', { tradeId, reason }),
  feedback: (tradeId: string, rating: Rating, comment: string) =>
    invoke<string>('market_feedback', { tradeId, rating, comment }),
  settle: (tradeId: string, outcome: 'release' | 'refund') => invoke<string>('market_settle', { tradeId, outcome }),
  escrowStatus: (tradeId: string) => invoke<EscrowStatus>('market_escrow_status', { tradeId }),
  chainAddress: (asset: string) => invoke<ChainAddress>('market_chain_address', { asset }),
  publishArbiter: () => invoke<string>('market_publish_arbiter'),
  chat: (tradeId: string) => invoke<ChatMsg[]>('market_chat', { tradeId }),
  chatRead: (tradeId: string) => invoke<void>('market_chat_read', { tradeId }),
  chatUnread: () => invoke<Record<string, number>>('market_chat_unread'),
  chatSend: (tradeId: string, text: string) => invoke<ChatMsg>('market_chat_send', { tradeId, text }),
};

export interface AssetMeta {
  id: string;
  symbol: string;
  chain: string;
  family: Family;
  color: string;
  digits: number;
}

export const ASSETS: AssetMeta[] = [
  { id: 'EGOC', symbol: 'EGOC', chain: 'Ego', family: 'ego', color: '#d2eb2b', digits: 2 },
  { id: 'USDT-TRC20', symbol: 'USDT', chain: 'Tron · TRC-20', family: 'tron', color: '#26A17B', digits: 2 },
  { id: 'USDT-ERC20', symbol: 'USDT', chain: 'Ethereum · ERC-20', family: 'evm', color: '#26A17B', digits: 2 },
  { id: 'USDT-BEP20', symbol: 'USDT', chain: 'BNB Chain · BEP-20', family: 'evm', color: '#26A17B', digits: 2 },
  { id: 'USDT-POLYGON', symbol: 'USDT', chain: 'Polygon', family: 'evm', color: '#26A17B', digits: 2 },
  { id: 'USDC-ERC20', symbol: 'USDC', chain: 'Ethereum · ERC-20', family: 'evm', color: '#2775CA', digits: 2 },
  { id: 'USDC-BEP20', symbol: 'USDC', chain: 'BNB Chain · BEP-20', family: 'evm', color: '#2775CA', digits: 2 },
  { id: 'USDC-POLYGON', symbol: 'USDC', chain: 'Polygon', family: 'evm', color: '#2775CA', digits: 2 },
  { id: 'ETH', symbol: 'ETH', chain: 'Ethereum', family: 'evm', color: '#627EEA', digits: 6 },
  { id: 'BNB', symbol: 'BNB', chain: 'BNB Chain', family: 'evm', color: '#F3BA2F', digits: 6 },
  { id: 'TRX', symbol: 'TRX', chain: 'Tron', family: 'tron', color: '#EF0027', digits: 2 },
  { id: 'POL', symbol: 'POL', chain: 'Polygon', family: 'evm', color: '#8247E5', digits: 4 },
  { id: 'USDC-SPL', symbol: 'USDC', chain: 'Solana', family: 'solana', color: '#2775CA', digits: 2 },
  { id: 'USDT-SPL', symbol: 'USDT', chain: 'Solana', family: 'solana', color: '#26A17B', digits: 2 },
  { id: 'SOL', symbol: 'SOL', chain: 'Solana', family: 'solana', color: '#9945FF', digits: 4 },
  { id: 'ADA', symbol: 'ADA', chain: 'Cardano', family: 'cardano', color: '#3CC8C8', digits: 2 },
];

const BASE58 = /^[1-9A-HJ-NP-Za-km-z]+$/;

export function payoutProblem(family: Family, address: string): string | null {
  const a = address.trim();
  if (!a) return null;
  switch (family) {
    case 'evm':
      return /^0x[0-9a-fA-F]{40}$/.test(a) ? null : 'An EVM address is 0x followed by 40 hex digits.';
    case 'tron':
      return a.length === 34 && a.startsWith('T') && BASE58.test(a) ? null : 'A Tron address starts with T and has 34 characters.';
    case 'solana':
      return a.length >= 32 && a.length <= 44 && BASE58.test(a) ? null : 'A Solana address is 32 to 44 base58 characters.';
    case 'cardano':
      return /^addr_test1[02-9ac-hj-np-z]{50,110}$/.test(a) ? null : 'Use a Cardano testnet address that starts with addr_test1.';
    default:
      return null;
  }
}

export function nativeDecimals(family: Family): number {
  if (family === 'evm') return 18;
  if (family === 'solana') return 9;
  return 6;
}

export function assetMeta(id: string): AssetMeta {
  return ASSETS.find(a => a.id === id) ?? { id, symbol: id, chain: id, family: 'evm', color: '#9ca3af', digits: 2 };
}

export function isEgoc(asset: string): boolean {
  return asset === 'EGOC';
}

export function assetLabel(id: string): string {
  const a = assetMeta(id);
  return a.family === 'ego' ? a.symbol : `${a.symbol} on ${a.chain}`;
}

export const FIATS: { code: string; name: string; decimals: number }[] = [
  { code: 'USD', name: 'US dollar', decimals: 2 },
  { code: 'EUR', name: 'Euro', decimals: 2 },
  { code: 'GBP', name: 'British pound', decimals: 2 },
  { code: 'CHF', name: 'Swiss franc', decimals: 2 },
  { code: 'CAD', name: 'Canadian dollar', decimals: 2 },
  { code: 'AUD', name: 'Australian dollar', decimals: 2 },
  { code: 'JPY', name: 'Japanese yen', decimals: 0 },
  { code: 'INR', name: 'Indian rupee', decimals: 2 },
  { code: 'BRL', name: 'Brazilian real', decimals: 2 },
  { code: 'MXN', name: 'Mexican peso', decimals: 2 },
  { code: 'TRY', name: 'Turkish lira', decimals: 2 },
  { code: 'NGN', name: 'Nigerian naira', decimals: 2 },
  { code: 'KES', name: 'Kenyan shilling', decimals: 2 },
  { code: 'ZAR', name: 'South African rand', decimals: 2 },
  { code: 'AED', name: 'UAE dirham', decimals: 2 },
  { code: 'PLN', name: 'Polish zloty', decimals: 2 },
  { code: 'SEK', name: 'Swedish krona', decimals: 2 },
  { code: 'ALL', name: 'Albanian lek', decimals: 2 },
];

export const METHODS: { id: string; label: string }[] = [
  { id: 'bank_transfer', label: 'Bank transfer' },
  { id: 'sepa', label: 'SEPA' },
  { id: 'sepa_instant', label: 'SEPA Instant' },
  { id: 'wise', label: 'Wise' },
  { id: 'revolut', label: 'Revolut' },
  { id: 'paypal', label: 'PayPal' },
  { id: 'zelle', label: 'Zelle' },
  { id: 'venmo', label: 'Venmo' },
  { id: 'cash_app', label: 'Cash App' },
  { id: 'interac', label: 'Interac e-Transfer' },
  { id: 'pix', label: 'Pix' },
  { id: 'upi', label: 'UPI' },
  { id: 'mpesa', label: 'M-Pesa' },
  { id: 'alipay', label: 'Alipay' },
  { id: 'cash_in_person', label: 'Cash in person' },
];

export const WINDOWS_MIN = [15, 30, 60, 120, 240, 720, 1440];

export function methodLabel(id: string): string {
  const m = METHODS.find(x => x.id === id);
  if (m) return m.label;
  return id.replace(/[_-]+/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

export function fiatDecimals(code: string): number {
  return FIATS.find(f => f.code === code)?.decimals ?? 2;
}

export function fmtEgoc(uegoc: number, digits = 2): string {
  return (uegoc / 1_000_000).toLocaleString(undefined, {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
}

export function fmtNumber(micro: number, asset: string, digits?: number): string {
  const d = digits ?? assetMeta(asset).digits;
  return (micro / 1_000_000).toLocaleString(undefined, { minimumFractionDigits: Math.min(d, 2), maximumFractionDigits: d });
}

export function fmtAmount(micro: number, asset: string, digits?: number): string {
  return `${fmtNumber(micro, asset, digits)} ${assetMeta(asset).symbol}`;
}

export function fmtBase(raw: string | null | undefined, decimals: number | null | undefined, symbol: string, minDigits = 0): string {
  if (raw == null || decimals == null) return '—';
  try {
    const v = BigInt(raw);
    const scale = BigInt(10) ** BigInt(decimals);
    const whole = v / scale;
    const keep = Math.min(decimals, Math.max(4, minDigits));
    const frac = (v % scale).toString().padStart(decimals, '0').slice(0, keep).replace(/0+$/, '').padEnd(Math.min(minDigits, decimals), '0');
    return `${whole.toLocaleString()}${frac ? '.' + frac : ''} ${symbol}`;
  } catch {
    return '—';
  }
}

export function fmtFiat(micro: number, code: string): string {
  const d = fiatDecimals(code);
  const v = micro / 1_000_000;
  return `${v.toLocaleString(undefined, { minimumFractionDigits: d, maximumFractionDigits: d })} ${code}`;
}

export function fmtUnitPrice(micro: number, code: string): string {
  const v = micro / 1_000_000;
  const digits = v >= 100 ? 2 : v >= 1 ? 4 : v >= 0.01 ? 5 : 6;
  return `${v.toLocaleString(undefined, { minimumFractionDigits: digits, maximumFractionDigits: digits })} ${code}`;
}

export function unitPriceMicro(price: Price, egocUsd: number): number | null {
  if ('fixed' in price) return price.fixed;
  if (!egocUsd) return null;
  return Math.round(egocUsd * 1_000_000 * (1 + price.margin_bps / 10_000));
}

export function marginLabel(bps: number): string {
  const pct = bps / 100;
  if (pct === 0) return 'Market price';
  return `Market ${pct > 0 ? '+' : ''}${pct.toFixed(2).replace(/\.?0+$/, '')}%`;
}

export function shortAddr(a: string): string {
  if (!a) return '';
  return a.length <= 16 ? a : `${a.slice(0, 10)}…${a.slice(-4)}`;
}

export function positivePct(p: ProfileSummary): number | null {
  const rated = p.positive + p.neutral + p.negative;
  if (rated === 0) return null;
  return Math.round((p.positive / rated) * 100);
}

export function reputationLine(p: ProfileSummary): string {
  if (p.completed === 0) return 'New trader';
  const pct = positivePct(p);
  const parts = [`${p.completed} trade${p.completed === 1 ? '' : 's'}`];
  if (pct !== null) parts.push(`${pct}% positive`);
  if (p.partners > 1) parts.push(`${p.partners} partners`);
  return parts.join(' · ');
}

export function fmtDuration(secs: number): string {
  const s = Math.max(0, Math.floor(secs));
  if (s >= 86_400) return `${Math.floor(s / 86_400)}d ${Math.floor((s % 86_400) / 3_600)}h`;
  if (s >= 3_600) return `${Math.floor(s / 3_600)}h ${Math.floor((s % 3_600) / 60)}m`;
  if (s >= 60) return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s`;
  return `${s}s`;
}

export function windowLabel(secs: number): string {
  const m = Math.round(secs / 60);
  if (m >= 60 && m % 60 === 0) return `${m / 60} h`;
  return `${m} min`;
}

export function toMicro(input: string): number {
  const n = parseFloat(input.replace(/,/g, ''));
  if (!isFinite(n) || n <= 0) return 0;
  return Math.round(n * 1_000_000);
}

export function errText(e: unknown): string {
  const s = typeof e === 'string' ? e : (e as { message?: string })?.message ?? JSON.stringify(e);
  return s.replace(/^[A-Za-z]+Error:\s*/, '').replace(/^"|"$/g, '');
}

export const STATUS_META: Record<TradeStatus, { label: string; tone: string }> = {
  awaiting_lock: { label: 'Waiting for escrow', tone: 'bg-yellow-500/15 text-yellow-400' },
  expired: { label: 'Expired', tone: 'bg-gray-600/30 text-gray-400' },
  locked: { label: 'Escrow funded', tone: 'bg-blue-500/15 text-blue-400' },
  payment_overdue: { label: 'Payment overdue', tone: 'bg-orange-500/15 text-orange-400' },
  paid: { label: 'Marked paid', tone: 'bg-cyan-500/15 text-cyan-400' },
  disputed: { label: 'In dispute', tone: 'bg-red-500/15 text-red-400' },
  cancelled: { label: 'Cancelled', tone: 'bg-gray-600/30 text-gray-400' },
  released: { label: 'Completed', tone: 'bg-green-500/15 text-green-400' },
  refunded: { label: 'Refunded', tone: 'bg-gray-600/30 text-gray-300' },
};

export function isOpenStatus(s: TradeStatus): boolean {
  return s === 'awaiting_lock' || s === 'locked' || s === 'payment_overdue' || s === 'paid' || s === 'disputed';
}
