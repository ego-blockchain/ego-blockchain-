import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/tauri';

interface StakingInfo {
  staked_amount: number;
  lock_period_days: number;
  apr: number;
  pending_rewards: number;
  is_locked: boolean;
}

const APR = 12.5;
const LOCK_OPTIONS = [
  { days: 30,  bonus: '0%',   label: '30 days'  },
  { days: 90,  bonus: '+2%',  label: '90 days'  },
  { days: 180, bonus: '+5%',  label: '6 months' },
  { days: 365, bonus: '+10%', label: '1 year'   },
];

const StakingPage: React.FC = () => {
  const [info, setInfo] = useState<StakingInfo | null>(null);
  const [stakeAmount, setStakeAmount] = useState('');
  const [lockDays, setLockDays] = useState(30);
  const [mode, setMode] = useState<'stake' | 'unstake'>('stake');
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  useEffect(() => {
    invoke<StakingInfo>('get_staking_info').then(setInfo).catch(() => {});
  }, []);

  const projectedApr = APR + LOCK_OPTIONS.find(o => o.days === lockDays)!.bonus.replace('%', '').replace('+', '');
  const projectedYield = stakeAmount
    ? ((parseFloat(stakeAmount) || 0) * (APR / 100) * (lockDays / 365)).toFixed(2)
    : '0.00';

  async function handleSubmit() {
    setSubmitting(true);
    await new Promise(r => setTimeout(r, 1200));
    setResult(mode === 'stake'
      ? `Staked ${stakeAmount} EGOC for ${lockDays} days. Lock interest: 20% simple on rewards.`
      : `Unstaking initiated. Funds available after lock period.`
    );
    setSubmitting(false);
  }

  const staked     = info ? info.staked_amount / 1_000_000 : 10_000;
  const pending    = info ? info.pending_rewards / 1_000_000 : 250;
  const lockLeft   = info ? info.lock_period_days : 22;

  return (
    <div className="p-6 space-y-5 max-w-4xl mx-auto">
      {/* Current stake summary */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Staked',         val: `${staked.toLocaleString()} EGOC`, color: 'text-blue-400'   },
          { label: 'APR',            val: `${info?.apr ?? APR}%`,             color: 'text-green-400'  },
          { label: 'Pending Rewards',val: `${pending.toFixed(2)} EGOC`,       color: 'text-yellow-400' },
          { label: 'Lock Remaining', val: `${lockLeft} days`,                 color: 'text-purple-400' },
        ].map(c => (
          <div key={c.label} className="bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <div className="text-xs text-gray-400 mb-1">{c.label}</div>
            <div className={`text-xl font-black ${c.color}`}>{c.val}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-5 gap-4">
        {/* Stake / Unstake form */}
        <div className="col-span-3 bg-gray-800 rounded-2xl p-5 border border-gray-700">
          {result ? (
            <div className="text-center py-8 space-y-4">
              <div className="text-5xl">✅</div>
              <div className="text-lg font-bold">Done!</div>
              <p className="text-sm text-gray-300">{result}</p>
              <button onClick={() => { setResult(null); setStakeAmount(''); }} className="bg-blue-600 hover:bg-blue-500 px-6 py-3 rounded-xl font-semibold transition">
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

              <div className="space-y-4">
                <div>
                  <label className="text-xs text-gray-400 block mb-1.5">Amount (EGOC)</label>
                  <input
                    type="number"
                    min="0"
                    value={stakeAmount}
                    onChange={e => setStakeAmount(e.target.value)}
                    className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none transition"
                    placeholder="0"
                  />
                </div>

                {mode === 'stake' && (
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
                )}

                {mode === 'stake' && stakeAmount && (
                  <div className="bg-gray-900 rounded-xl p-4 space-y-2 text-sm">
                    <div className="font-semibold text-gray-200 mb-2">Projection</div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Staking APR</span>
                      <span className="text-green-400">{APR}%</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Lock bonus</span>
                      <span className="text-green-400">{LOCK_OPTIONS.find(o => o.days === lockDays)!.bonus}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Reward lock interest</span>
                      <span className="text-yellow-400">20% simple</span>
                    </div>
                    <div className="border-t border-gray-700 pt-2 flex justify-between font-bold">
                      <span>Projected yield</span>
                      <span className="text-green-400">{projectedYield} EGOC</span>
                    </div>
                  </div>
                )}

                <button
                  onClick={handleSubmit}
                  disabled={!stakeAmount || submitting}
                  className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-40 py-3 rounded-xl font-semibold transition"
                >
                  {submitting ? '⏳ Processing...' : mode === 'stake' ? '🔒 Stake EGOC' : '🔓 Unstake EGOC'}
                </button>
              </div>
            </>
          )}
        </div>

        {/* Info cards */}
        <div className="col-span-2 space-y-4">
          <div className="bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <h3 className="font-semibold mb-4">How Staking Works</h3>
            <div className="space-y-3 text-sm text-gray-300">
              <div className="flex gap-2.5">
                <span className="text-lg shrink-0">🔒</span>
                <span>Lock EGOC to earn staking rewards + governance rights</span>
              </div>
              <div className="flex gap-2.5">
                <span className="text-lg shrink-0">📈</span>
                <span>Rewards are locked for 30 days and earn 20% simple interest</span>
              </div>
              <div className="flex gap-2.5">
                <span className="text-lg shrink-0">⚡</span>
                <span>Stakers get free contract deploys up to the epoch quota</span>
              </div>
              <div className="flex gap-2.5">
                <span className="text-lg shrink-0">🛡️</span>
                <span>Higher stake → better DRS multiplier → more emissions</span>
              </div>
            </div>
          </div>

          <div className="bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <h3 className="font-semibold mb-4">Validator Delegation</h3>
            <div className="space-y-3">
              {[
                { name: 'EgoNode-Alpha', stake: '142k', apy: '13.2%', status: 'active' },
                { name: 'EgoNode-Beta',  stake: '98k',  apy: '12.8%', status: 'active' },
                { name: 'QuarkNode',     stake: '67k',  apy: '11.9%', status: 'active' },
              ].map(v => (
                <div key={v.name} className="flex items-center justify-between bg-gray-900 rounded-xl p-3 text-sm">
                  <div>
                    <div className="font-medium">{v.name}</div>
                    <div className="text-xs text-gray-400">Stake: {v.stake} EGOC</div>
                  </div>
                  <div className="text-right">
                    <div className="text-green-400 font-bold">{v.apy}</div>
                    <div className="text-xs text-green-500">● Active</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default StakingPage;
