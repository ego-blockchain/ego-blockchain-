import React, { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { useNavigate } from 'react-router-dom';
import { useWallet } from '../App';
import { useConfirm } from '../hooks/useConfirm';
import { requireConfirm } from '../lib/totp';

interface StakePosition {
  id:         string;
  amount:     number;
  staked_at:  number;
  lock_days:  number;
  unstake_at: number;
  is_locked:  boolean;
  apr:        number;
  accrued:    number;
  early_fee:  number;
}

interface StakingInfo {
  positions:  StakePosition[];
  staked_amount:      number;
  lock_period_days:   number;
  apr:                number;
  node_rate?:         boolean;
  budget_live?:       boolean;
  budget_per_day_uegoc?: number;
  point_rate_bps?:    number;
  max_rate_bps?:      number;
  activity_milli?:    number;
  lock_rates?:        [number, number][];
  pending_rewards:    number;
  unlock_date:        number | null;
  staked_at:          number | null;
  is_locked:          boolean;
  projected_interest: number;
  early_unstake_fee:  number;
}

interface Balance { uegoc: number; formatted: string; }
interface Peer { address: string; name: string; endpoint: string; last_seen: number; }

interface CombinedDrs {
  combined_score: number;
  staked_uegoc:   number;
  validator_rank: number | null;
  is_eligible:    boolean;
  poc_events_24h: number;
  post_sectors:   number;
}

interface Tokenomics {
  total_supply_egoc:  number;
  is_testnet:         boolean;
  circulating_egoc:   number;
  circulating_pct:    number;
  halving: {
    era:                    number;
    current_reward_egoc:    number;
    blocks_to_next_halving: number;
  };
  staking: {
    total_staked_egoc: number;
    active_stakers:    number;
  };
}

const BASE_APR = 12.5;
const LOCK_OPTIONS = [
  { days: 30,  bonusPct: 0,   bonus: '0%',   label: '30 days'  },
  { days: 90,  bonusPct: 2,   bonus: '+2%',  label: '90 days'  },
  { days: 180, bonusPct: 5,   bonus: '+5%',  label: '6 months' },
  { days: 365, bonusPct: 10,  bonus: '+10%', label: '1 year'   },
];

function fmtDate(ts: number | null): string {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleDateString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
  });
}

function fmtEgoc(uegoc: number): string {
  return (uegoc / 1_000_000).toLocaleString(undefined, {
    minimumFractionDigits: 2, maximumFractionDigits: 2,
  });
}

function daysUntil(ts: number | null): number {
  if (!ts) return 0;
  return Math.max(0, Math.ceil((ts - Date.now() / 1000) / 86400));
}

const MIN_STAKE_EGOC = 1000;

const StakingPage: React.FC = () => {
  const { wallet } = useWallet();
  const navigate = useNavigate();
  const { confirm, ConfirmDialog } = useConfirm();
  const [info, setInfo]           = useState<StakingInfo | null>(null);
  const [balance, setBalance]     = useState<Balance | null>(null);
  const [peers, setPeers]         = useState<Peer[]>([]);
  const [drs, setDrs]             = useState<CombinedDrs | null>(null);
  const [tokenomics, setTokenomics] = useState<Tokenomics | null>(null);
  const [stakeAmount, setStakeAmount] = useState('');
  const [lockDays, setLockDays]   = useState(30);
  const [mode, setMode]           = useState<'stake' | 'unstake'>('stake');
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult]       = useState<{ ok: boolean; msg: string } | null>(null);

  const load = useCallback(async () => {
    try {
      const [i, b, ps] = await Promise.all([
        invoke<StakingInfo>('get_staking_info'),
        invoke<Balance>('get_balance'),
        invoke<Peer[]>('get_network_peers'),
      ]);
      setInfo(i);
      setBalance(b);
      setPeers(ps);
    } catch {}
    invoke<CombinedDrs>('get_combined_drs').then(setDrs).catch(() => {});
    invoke<Tokenomics>('get_tokenomics').then(setTokenomics).catch(() => {});
  }, []);

  useEffect(() => { load(); }, [load, wallet?.address]);

  const selectedLock   = LOCK_OPTIONS.find(o => o.days === lockDays)!;
  const lockBonus      = selectedLock.bonus;
  const nodeRate       = !!info?.node_rate;
  const rateFor        = (days: number) => info?.lock_rates?.find(([d]) => d === days)?.[1]
    ?? (BASE_APR + (LOCK_OPTIONS.find(o => o.days === days)?.bonusPct ?? 0)) * (nodeRate ? 2 : 1);
  const effectiveApr   = +rateFor(lockDays).toFixed(2);
  const activity       = (info?.activity_milli ?? (nodeRate ? 2000 : 1000)) / 1000;
  const online         = activity >= 2;
  const storageBoost   = online ? +(activity - 2).toFixed(2) : 0;
  const lockFactor     = +((BASE_APR + selectedLock.bonusPct) / BASE_APR).toFixed(2);
  const baseRate       = (info?.point_rate_bps ?? BASE_APR * 100) / 100;
  const maxRate        = (info?.max_rate_bps ?? BASE_APR * 100) / 100;
  const shared         = baseRate < maxRate;
  const budgetPerDay   = (info?.budget_per_day_uegoc ?? 0) / 1_000_000;
  const projectedYield = stakeAmount
    ? ((parseFloat(stakeAmount) || 0) * (effectiveApr / 100) * (lockDays / 365)).toFixed(2)
    : '0.00';

  async function handleStake() {
    const amt = Math.round((parseFloat(stakeAmount) || 0) * 1_000_000);
    if (amt <= 0) return;
    if (!(await requireConfirm('send'))) return;
    setSubmitting(true);
    setResult(null);
    try {
      await invoke('stake_coins', { amountUegoc: amt, lockDays });
      await load();
      setResult({ ok: true, msg: `Staked ${stakeAmount} EGOC for ${lockDays} days.` });
      setStakeAmount('');
    } catch (e: any) {
      setResult({ ok: false, msg: String(e) });
    } finally {
      setSubmitting(false);
    }
  }

  async function handleUnstake(earlyUnstake: boolean = false, positionId?: string) {
    if (earlyUnstake) {
      const pos = positionId ? info?.positions.find(p => p.id === positionId) : undefined;
      const feeUegoc = pos ? pos.early_fee : (info?.early_unstake_fee ?? 0);
      const fee = (feeUegoc / 1_000_000).toFixed(4);
      if (!await confirm(`Early unstake will deduct ${fee} EGOC as a 10% fee.`, { detail: 'This fee goes to network nodes. Only this position is unstaked; your other positions are unaffected.', confirmLabel: 'Unstake Early' })) return;
    }
    if (!(await requireConfirm('send'))) return;
    setSubmitting(true);
    setResult(null);
    try {
      await invoke('unstake_coins', { early: earlyUnstake, positionId: positionId ?? null });
      await load();
      setResult({ ok: true, msg: earlyUnstake ? 'Early unstake complete (10% fee applied).' : 'Stake returned to your wallet.' });
    } catch (e: any) {
      setResult({ ok: false, msg: String(e) });
    } finally {
      setSubmitting(false);
    }
  }

  const staked      = info ? info.staked_amount / 1_000_000 : 0;
  const pendingRew  = info ? info.pending_rewards / 1_000_000 : 0;
  const lockLeft    = daysUntil(info?.unlock_date ?? null);
  const hasStake    = (info?.staked_amount ?? 0) > 0;
  const canUnstake  = hasStake && !info?.is_locked;
  const availBal    = balance ? balance.uegoc / 1_000_000 : 0;

  return (
    <div className="p-6 space-y-5 max-w-4xl mx-auto">
      {ConfirmDialog}

      <div className="flex items-center gap-2">
        <h1 className="text-xl font-bold">Staking</h1>
        <span className="text-yellow-400 text-[10px] font-bold bg-yellow-400/15 px-1.5 py-px rounded">TEST</span>
      </div>

      <div className="grid grid-cols-5 gap-3">
        {[
          { label: 'Staked',              val: `${fmtEgoc(info?.staked_amount ?? 0)} EGOC`,                                  color: 'text-blue-400'   },
          { label: 'APR',                 val: `${info?.apr ?? BASE_APR}%`,                                                        color: 'text-green-400'  },
          { label: 'Projected Interest',  val: hasStake ? `${((info?.projected_interest ?? 0) / 1_000_000).toFixed(4)} EGOC` : '—', color: 'text-cyan-400'   },
          { label: 'Pending Rewards',     val: `${pendingRew.toFixed(2)} EGOC`,                                               color: 'text-yellow-400' },
          { label: 'Lock Remaining',      val: hasStake ? `${lockLeft} days` : '—',                                          color: 'text-purple-400' },
        ].map(c => (
          <div key={c.label} className="bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <div className="text-xs text-gray-400 mb-1">{c.label}</div>
            <div className={`text-xl font-black ${c.color}`}>{c.val}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-5 gap-4">
        {}
        <div className="col-span-3 bg-gray-800 rounded-2xl p-5 border border-gray-700">
          {result ? (
            <div className="text-center py-8 space-y-4">
              <div className="text-5xl">{result.ok ? '✅' : '❌'}</div>
              <div className="text-lg font-bold">{result.ok ? 'Done!' : 'Error'}</div>
              <p className={`text-sm ${result.ok ? 'text-gray-300' : 'text-red-400'}`}>{result.msg}</p>
              <button
                onClick={() => setResult(null)}
                className="bg-blue-600 hover:bg-blue-500 px-6 py-3 rounded-xl font-semibold transition"
              >
                OK
              </button>
            </div>
          ) : (
            <>
              <div className="flex gap-2 mb-5">
                {(['stake', 'unstake'] as const).map(m => (
                  <button
                    key={m}
                    onClick={() => setMode(m)}
                    className={`flex-1 py-2.5 rounded-xl font-semibold text-sm capitalize transition ${
                      mode === m ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-400 hover:bg-gray-600'
                    }`}
                  >
                    {m === 'stake' ? '🔒 Stake' : '🔓 Unstake'}
                  </button>
                ))}
              </div>

              {mode === 'stake' ? (
                <div className="space-y-4">
                  <div>
                    <label className="text-xs text-gray-400 block mb-1.5">
                      Amount (EGOC)
                      {balance && (
                        <span className="ml-2 text-gray-500">
                          Available: {availBal.toLocaleString(undefined, { maximumFractionDigits: 2 })} EGOC
                        </span>
                      )}
                    </label>
                    <div className="flex gap-2">
                      <input
                        type="number"
                        min="0"
                        value={stakeAmount}
                        onChange={e => setStakeAmount(e.target.value)}
                        className="flex-1 bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none transition"
                        placeholder="0"
                      />
                      <button
                        onClick={() => balance && setStakeAmount((balance.uegoc / 1_000_000).toFixed(2))}
                        className="text-xs px-3 bg-gray-700 hover:bg-gray-600 rounded-xl transition"
                      >
                        Max
                      </button>
                    </div>
                  </div>

                  <div>
                    <label className="text-xs text-gray-400 block mb-2">Lock Period</label>
                    <div className="grid grid-cols-4 gap-2">
                      {LOCK_OPTIONS.map(opt => (
                        <button
                          key={opt.days}
                          onClick={() => setLockDays(opt.days)}
                          className={`py-2.5 rounded-xl text-xs font-medium transition ${
                            lockDays === opt.days
                              ? 'bg-blue-600 text-white'
                              : 'bg-gray-700 text-gray-400 hover:bg-gray-600'
                          }`}
                        >
                          <div>{opt.label}</div>
                          <div className="text-green-400 mt-0.5">{rateFor(opt.days).toFixed(1)}%</div>
                          <div className="text-[10px] text-gray-500">{opt.bonus === '0%' ? 'no lock bonus' : `${opt.bonus} lock bonus`}</div>
                        </button>
                      ))}
                    </div>
                    <div className="mt-2 text-xs text-red-400/80 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
                      ⚠️ Early unstaking before the lock expires incurs a <span className="font-semibold text-red-400">10% penalty</span> on your staked amount. The fee is distributed to network nodes.
                    </div>
                  </div>

                  {stakeAmount && (
                    <div className="bg-gray-900 rounded-xl p-4 space-y-2 text-sm">
                      <div className="font-semibold text-gray-200 mb-2">Projection</div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Your rate now</span>
                        <span className="text-green-400">{effectiveApr}% a year</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Base rate</span>
                        <span className="text-gray-200">{baseRate.toFixed(2)}%{shared ? ` (shared, ${maxRate}% at most)` : ''}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Lock</span>
                        <span className="text-green-400">×{lockFactor} ({lockBonus})</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Online node</span>
                        <span className={online ? 'text-green-400' : 'text-gray-500'}>{online ? '×2 while this computer stays online' : 'Keep this computer online as a node for ×2'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Shared storage</span>
                        <span className={storageBoost > 0 ? 'text-green-400' : 'text-gray-500'}>{storageBoost > 0 ? `+${storageBoost}× from the storage you share` : 'Share up to 1 TB for up to +1×'}</span>
                      </div>
                      <div className="text-xs text-gray-500">The rate is worked out at each check-in and can go down as more people stake.</div>
                      <div className="border-t border-gray-700 pt-2 flex justify-between font-bold">
                        <span>Projected yield</span>
                        <span className="text-green-400">{projectedYield} EGOC</span>
                      </div>
                      <div className="flex justify-between text-xs text-gray-500">
                        <span>Unlock date</span>
                        <span>{fmtDate(Math.floor(Date.now() / 1000) + lockDays * 86400)}</span>
                      </div>
                      <div className="flex justify-between text-xs text-gray-500 border-t border-gray-700 pt-2">
                        <span>Early unstake penalty</span>
                        <span className="text-red-400 font-semibold">
                          −{((parseFloat(stakeAmount) || 0) * 0.10).toFixed(2)} EGOC (10%)
                        </span>
                      </div>
                    </div>
                  )}

                  {hasStake && (
                    <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-3 text-xs text-blue-300">
                      You have {fmtEgoc(info!.staked_amount)} EGOC staked. Adding more merges into that
                      position. Interest on the new amount starts today, and your unlock date only moves
                      later, never earlier.
                    </div>
                  )}

                  <button
                    onClick={handleStake}
                    disabled={!stakeAmount || submitting}
                    className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-40 py-3 rounded-xl font-semibold transition"
                  >
                    {submitting ? 'Processing...' : hasStake ? 'Add to Stake' : 'Stake EGOC'}
                  </button>
                </div>
              ) : (

                <div className="space-y-4">
                  {hasStake ? (
                    <>
                      <div className="text-xs text-gray-400 mb-1">
                        {info!.positions.length} position{info!.positions.length === 1 ? '' : 's'} ·
                        {' '}{fmtEgoc(info!.staked_amount)} EGOC total
                      </div>

                      {info!.positions
                        .slice()
                        .sort((a, b) => a.unstake_at - b.unstake_at)
                        .map(pos => (
                        <div
                          key={pos.id}
                          className={`bg-gray-900 rounded-xl p-4 space-y-3 border ${
                            pos.is_locked ? 'border-yellow-500/25' : 'border-green-500/30'
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <div className="text-blue-400 font-bold text-lg">
                              {fmtEgoc(pos.amount)} EGOC
                            </div>
                            <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full ${
                              pos.is_locked
                                ? 'bg-yellow-500/15 text-yellow-400'
                                : 'bg-green-500/15 text-green-400'
                            }`}>
                              {pos.is_locked ? 'Locked' : 'Unlocked'}
                            </span>
                          </div>

                          <div className="grid grid-cols-2 gap-3 text-sm">
                            <div>
                              <div className="text-xs text-gray-400 mb-0.5">Lock Period</div>
                              <div className="text-white font-medium">{pos.lock_days} days</div>
                            </div>
                            <div>
                              <div className="text-xs text-gray-400 mb-0.5">APR</div>
                              <div className="text-white font-medium">{pos.apr.toFixed(2)}%</div>
                            </div>
                            <div>
                              <div className="text-xs text-gray-400 mb-0.5">Staked On</div>
                              <div className="text-white font-medium">{fmtDate(pos.staked_at)}</div>
                            </div>
                            <div>
                              <div className="text-xs text-gray-400 mb-0.5">Unlocks On</div>
                              <div className={`font-medium ${pos.is_locked ? 'text-yellow-400' : 'text-green-400'}`}>
                                {fmtDate(pos.unstake_at)}
                              </div>
                            </div>
                          </div>

                          <div className="flex items-center justify-between text-xs pt-1 border-t border-gray-800">
                            <span className="text-gray-400">Interest accrued</span>
                            <span className="text-cyan-400 font-mono">
                              {(pos.accrued / 1_000_000).toFixed(6)} EGOC
                            </span>
                          </div>

                          {pos.is_locked ? (
                            <button
                              onClick={() => handleUnstake(true, pos.id)}
                              disabled={submitting}
                              className="w-full bg-yellow-600 hover:bg-yellow-500 disabled:opacity-40 py-2 rounded-lg text-sm font-semibold transition"
                            >
                              {submitting
                                ? 'Processing...'
                                : `Unstake early (fee ${(pos.early_fee / 1_000_000).toFixed(4)} EGOC)`}
                            </button>
                          ) : (
                            <button
                              onClick={() => handleUnstake(false, pos.id)}
                              disabled={submitting}
                              className="w-full bg-green-600 hover:bg-green-500 disabled:opacity-40 py-2 rounded-lg text-sm font-semibold transition"
                            >
                              {submitting ? 'Processing...' : 'Unstake now (no fee)'}
                            </button>
                          )}
                        </div>
                      ))}
                    </>
                  ) : (
                    <div className="text-center py-8 text-gray-500">
                      <div className="text-4xl mb-3">💤</div>
                      <div className="text-sm">No active stake.</div>
                      <div className="text-xs mt-1">Switch to the Stake tab to lock EGOC.</div>
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>

        {}
        <div className="col-span-2 space-y-4">

          {}
          <div className="bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <h3 className="font-semibold mb-4">How staking pays</h3>
            <div className="space-y-3 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-400">Daily budget</span>
                <span className="font-mono text-green-400">{budgetPerDay.toLocaleString(undefined, { maximumFractionDigits: 0 })} EGOC</span>
              </div>
              <p className="text-xs text-gray-500 -mt-1">Halves every 4 years, so it lasts 120 years. Unspent budget stays in the pool.</p>
              <div className="flex justify-between">
                <span className="text-gray-400">Base rate now</span>
                <span className={`font-mono ${shared ? 'text-yellow-400' : 'text-green-400'}`}>{baseRate.toFixed(2)}%</span>
              </div>
              <p className="text-xs text-gray-500 -mt-1">
                {shared
                  ? `Staking is using the whole daily budget, so it is shared: every rate is lower while this many people stake.`
                  : `At most ${maxRate}%. Once everyone's staking would use more than the daily budget, every rate goes down as more people stake.`}
              </p>
              <div className="border-t border-gray-700 pt-3 space-y-1.5">
                <div className="text-xs text-gray-400">Your stake counts</div>
                <div className="flex justify-between text-xs"><span className="text-gray-400">Lock ({selectedLock.label})</span><span className="font-mono">×{lockFactor}</span></div>
                <div className="flex justify-between text-xs"><span className="text-gray-400">Online node</span><span className={`font-mono ${online ? 'text-green-400' : 'text-gray-500'}`}>{online ? '×2' : '×1'}</span></div>
                <div className="flex justify-between text-xs"><span className="text-gray-400">Shared storage</span><span className={`font-mono ${storageBoost > 0 ? 'text-green-400' : 'text-gray-500'}`}>+{storageBoost}×</span></div>
                <div className="flex justify-between text-sm font-semibold border-t border-gray-700 pt-1.5"><span>Your rate</span><span className="text-green-400">{effectiveApr}% a year</span></div>
              </div>
              {storageBoost < 1 && (
                <button onClick={() => navigate('/storage')} className="w-full mt-1 rounded-xl bg-emerald-500/15 border border-emerald-500/30 px-3 py-2 text-xs font-semibold text-emerald-300 hover:bg-emerald-500/25">
                  {online ? 'Share more storage to raise your rate up to 3×' : 'Run this computer as a node and share storage for up to 3×'}
                </button>
              )}
              <p className="text-xs text-gray-500">Stakers also pay 90% less in fees.</p>
            </div>
          </div>

          <div className="bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <h3 className="font-semibold mb-4 flex items-center gap-2">EGOC Tokenomics
              <span className="text-yellow-400 text-[9px] font-bold bg-yellow-400/15 px-1.5 py-px rounded">TEST</span>
            </h3>
            {tokenomics ? (
              <div className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-400">Total supply</span>
                  <span className="font-mono">{tokenomics.total_supply_egoc.toLocaleString()} EGOC</span>
                </div>
                {!tokenomics.is_testnet && (
                <div className="flex justify-between">
                  <span className="text-gray-400">Circulating</span>
                  <span className="font-mono text-green-400">
                    {tokenomics.circulating_egoc.toLocaleString(undefined, { maximumFractionDigits: 0 })} EGOC
                    <span className="text-gray-500 ml-1">({tokenomics.circulating_pct}%)</span>
                  </span>
                </div>
                )}
                <div className="flex justify-between">
                  <span className="text-gray-400">Block reward</span>
                  <span className="font-mono text-yellow-400">
                    {tokenomics.halving.current_reward_egoc} EGOC
                    <span className="text-gray-500 ml-1">(era {tokenomics.halving.era})</span>
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Next halving</span>
                  <span className="font-mono text-blue-400">
                    {tokenomics.halving.blocks_to_next_halving.toLocaleString()} blocks
                  </span>
                </div>
                <div className="border-t border-gray-700 pt-3 flex justify-between">
                  <span className="text-gray-400">Network staked</span>
                  <span className="font-mono text-orange-400">
                    {tokenomics.staking.total_staked_egoc.toLocaleString(undefined, { maximumFractionDigits: 0 })} EGOC
                    <span className="text-gray-500 ml-1">({tokenomics.staking.active_stakers} stakers)</span>
                  </span>
                </div>
              </div>
            ) : (
              <div className="text-center text-sm text-gray-500 py-4">
                <div className="animate-pulse">Loading tokenomics…</div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default StakingPage;
