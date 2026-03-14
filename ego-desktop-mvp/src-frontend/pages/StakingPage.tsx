import React, { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { useWallet } from '../App';
import { useConfirm } from '../hooks/useConfirm';

interface StakingInfo {
  staked_amount:      number;
  lock_period_days:   number;
  apr:                number;
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
    min_stake_egoc:    number;
  };
}

const APR = 12.5;
const LOCK_OPTIONS = [
  { days: 30,  bonus: '0%',   label: '30 days'  },
  { days: 90,  bonus: '+2%',  label: '90 days'  },
  { days: 180, bonus: '+5%',  label: '6 months' },
  { days: 365, bonus: '+10%', label: '1 year'   },
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

  const lockBonus = LOCK_OPTIONS.find(o => o.days === lockDays)!.bonus;
  const projectedYield = stakeAmount
    ? ((parseFloat(stakeAmount) || 0) * (APR / 100) * (lockDays / 365)).toFixed(2)
    : '0.00';

  async function handleStake() {
    const amt = Math.round((parseFloat(stakeAmount) || 0) * 1_000_000);
    if (amt <= 0) return;
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

  async function handleUnstake(earlyUnstake: boolean = false) {
    if (earlyUnstake) {
      const fee = info ? (info.early_unstake_fee / 1_000_000).toFixed(4) : '0';
      if (!await confirm(`Early unstake will deduct ${fee} EGOC as a 10% fee.`, { detail: 'This fee goes to network nodes. Are you sure you want to proceed?', confirmLabel: 'Unstake Early' })) return;
    }
    setSubmitting(true);
    setResult(null);
    try {
      await invoke('unstake_coins', { early: earlyUnstake });
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
      {/* Summary cards */}
      <div className="grid grid-cols-5 gap-3">
        {[
          { label: 'Staked',              val: `${fmtEgoc(info?.staked_amount ?? 0)} EGOC`,                                  color: 'text-blue-400'   },
          { label: 'APR',                 val: `${info?.apr ?? APR}%`,                                                        color: 'text-green-400'  },
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
        {/* Form */}
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
                          <div className="text-green-400 mt-0.5">{opt.bonus}</div>
                        </button>
                      ))}
                    </div>
                  </div>

                  {stakeAmount && (
                    <div className="bg-gray-900 rounded-xl p-4 space-y-2 text-sm">
                      <div className="font-semibold text-gray-200 mb-2">Projection</div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Staking APR</span>
                        <span className="text-green-400">{APR}%</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Lock bonus</span>
                        <span className="text-green-400">{lockBonus}</span>
                      </div>
                      <div className="border-t border-gray-700 pt-2 flex justify-between font-bold">
                        <span>Projected yield</span>
                        <span className="text-green-400">{projectedYield} EGOC</span>
                      </div>
                      <div className="flex justify-between text-xs text-gray-500">
                        <span>Unlock date</span>
                        <span>{fmtDate(Math.floor(Date.now() / 1000) + lockDays * 86400)}</span>
                      </div>
                    </div>
                  )}

                  {hasStake && (
                    <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-3 text-xs text-yellow-300">
                      ⚠️ You already have {fmtEgoc(info!.staked_amount)} EGOC staked. Unstake first before staking again.
                    </div>
                  )}

                  <button
                    onClick={handleStake}
                    disabled={!stakeAmount || submitting || hasStake}
                    className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-40 py-3 rounded-xl font-semibold transition"
                  >
                    {submitting ? '⏳ Processing...' : '🔒 Stake EGOC'}
                  </button>
                </div>
              ) : (
                /* ── Unstake panel ── */
                <div className="space-y-4">
                  {hasStake ? (
                    <>
                      {/* Current stake details */}
                      <div className="bg-gray-900 rounded-xl p-4 space-y-3">
                        <div className="text-sm font-semibold text-gray-200 mb-1">Current Stake</div>
                        <div className="grid grid-cols-2 gap-3 text-sm">
                          <div>
                            <div className="text-xs text-gray-400 mb-0.5">Amount Staked</div>
                            <div className="text-blue-400 font-bold">{fmtEgoc(info!.staked_amount)} EGOC</div>
                          </div>
                          <div>
                            <div className="text-xs text-gray-400 mb-0.5">Lock Period</div>
                            <div className="text-white font-medium">{info!.lock_period_days} days</div>
                          </div>
                          <div>
                            <div className="text-xs text-gray-400 mb-0.5">Staked On</div>
                            <div className="text-white font-medium">{fmtDate(info!.staked_at)}</div>
                          </div>
                          <div>
                            <div className="text-xs text-gray-400 mb-0.5">Unlocks On</div>
                            <div className={`font-medium ${info!.is_locked ? 'text-yellow-400' : 'text-green-400'}`}>
                              {fmtDate(info!.unlock_date)}
                            </div>
                          </div>
                        </div>
                        {info!.is_locked && (
                          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3 text-xs text-yellow-300 mt-1">
                            🔒 Lock period ends on {fmtDate(info!.unlock_date)}. Early unstake fee: {((info!.early_unstake_fee) / 1_000_000).toFixed(4)} EGOC (10%)
                          </div>
                        )}
                        {canUnstake && (
                          <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3 text-xs text-green-300 mt-1">
                            ✅ Lock period has ended. Ready to unstake — no fee.
                          </div>
                        )}
                      </div>

                      {info!.is_locked ? (
                        <div className="space-y-2">
                          <button
                            onClick={() => handleUnstake(true)}
                            disabled={submitting}
                            className="w-full bg-yellow-600 hover:bg-yellow-500 disabled:opacity-40 py-3 rounded-xl font-semibold transition"
                          >
                            {submitting ? '⏳ Processing...' : `⚡ Unstake Early (10% fee)`}
                          </button>
                          <div className="text-center text-xs text-gray-500 py-1">
                            — or — wait until {fmtDate(info!.unlock_date)} for no fee
                          </div>
                        </div>
                      ) : (
                        <button
                          onClick={() => handleUnstake(false)}
                          disabled={!canUnstake || submitting}
                          className="w-full bg-green-600 hover:bg-green-500 disabled:opacity-40 py-3 rounded-xl font-semibold transition"
                        >
                          {submitting ? '⏳ Processing...' : '🔓 Unstake Now (no fee)'}
                        </button>
                      )}
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

        {/* Right-column cards */}
        <div className="col-span-2 space-y-4">

          {/* Mining eligibility */}
          <div className="bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <h3 className="font-semibold mb-4">Mining Eligibility</h3>
            <div className="space-y-3">
              {/* DRS score */}
              <div>
                <div className="flex justify-between text-xs text-gray-400 mb-1">
                  <span>Combined DRS</span>
                  <span className={drs && drs.combined_score >= 0.5 ? 'text-green-400' : 'text-red-400'}>
                    {drs ? drs.combined_score.toFixed(3) : '—'} {drs && drs.combined_score >= 0.5 ? '✓' : '< 0.5 required'}
                  </span>
                </div>
                <div className="h-1.5 bg-gray-700 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${drs && drs.combined_score >= 0.5 ? 'bg-green-500' : 'bg-red-500'}`}
                    style={{ width: `${Math.min(100, ((drs?.combined_score ?? 0) / 5) * 100)}%` }}
                  />
                </div>
              </div>
              {/* Stake requirement */}
              <div>
                <div className="flex justify-between text-xs text-gray-400 mb-1">
                  <span>Stake (min {MIN_STAKE_EGOC} EGOC)</span>
                  <span className={hasStake && (info?.staked_amount ?? 0) >= MIN_STAKE_EGOC * 1_000_000 ? 'text-green-400' : 'text-yellow-400'}>
                    {fmtEgoc(info?.staked_amount ?? 0)} EGOC
                    {hasStake && (info?.staked_amount ?? 0) >= MIN_STAKE_EGOC * 1_000_000 ? ' ✓' : ''}
                  </span>
                </div>
                <div className="h-1.5 bg-gray-700 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${(info?.staked_amount ?? 0) >= MIN_STAKE_EGOC * 1_000_000 ? 'bg-green-500' : 'bg-yellow-500'}`}
                    style={{ width: `${Math.min(100, ((info?.staked_amount ?? 0) / (MIN_STAKE_EGOC * 1_000_000)) * 100)}%` }}
                  />
                </div>
              </div>
              {/* Result pill */}
              <div className={`mt-1 rounded-xl p-3 text-center text-sm font-semibold ${
                drs?.is_eligible
                  ? 'bg-green-500/15 border border-green-500/30 text-green-400'
                  : 'bg-gray-700/50 border border-gray-600/30 text-gray-400'
              }`}>
                {drs?.is_eligible ? '✅ Eligible to mine blocks' : '⏳ Not yet eligible to mine'}
              </div>
              {drs?.validator_rank != null && (
                <div className="text-center text-xs text-purple-400">
                  Validator rank #{drs.validator_rank}
                </div>
              )}
            </div>
          </div>

          {/* Tokenomics snapshot */}
          <div className="bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <h3 className="font-semibold mb-4">EGOC Tokenomics</h3>
            {tokenomics ? (
              <div className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-400">Total supply</span>
                  <span className="font-mono">{tokenomics.total_supply_egoc.toLocaleString()} EGOC</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Circulating</span>
                  <span className="font-mono text-green-400">
                    {tokenomics.circulating_egoc.toLocaleString(undefined, { maximumFractionDigits: 0 })} EGOC
                    <span className="text-gray-500 ml-1">({tokenomics.circulating_pct}%)</span>
                  </span>
                </div>
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
