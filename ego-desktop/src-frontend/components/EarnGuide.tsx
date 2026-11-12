import React, { useEffect, useMemo, useState } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { useNavigate } from 'react-router-dom';

export const EARN_GUIDE_SEEN_KEY = 'ego-earn-guide-seen-v1';

interface EarnPlan { name: string; gb: number; monthly_usd: number; host_monthly_usd: number }

interface Guide {
  node_pool_per_day_egoc: number;
  online_nodes: number;
  registered_nodes: number;
  checkin_every_hours: number;
  streak_needed: number;
  uptime_points_cap: number;
  storage_points_per_gb: number;
  storage_points_cap: number;
  coverage_points_per_witness: number;
  coverage_witness_cap: number;
  coverage_valid_days: number;
  host_share_pct: number;
  hosts_per_plan: number;
  plans: EarnPlan[];
  staking_apr_pct: number;
  staking_lock_bonus_pct: [number, number][];
  node_staking_multiplier: number;
  compute_core_hour_egoc: number;
  compute_gpu_hour_egoc: number;
  my_rank: number | null;
  places_taken: number;
  my_multiplier: number;
  early_places: number;
  storage_points_total: number;
  stake_live: boolean;
  stake_budget_per_day_egoc: number;
  stake_rate_plain_pct: number;
  stake_rate_best_pct: number;
}

const mult = (rank: number) => {
  if (rank < 100) return 10;
  if (rank < 1000) return 7 - 5.5 * (rank - 100) / 900;
  if (rank < 10000) return 1.5 - 0.5 * (rank - 1000) / 9000;
  return 1;
};

const spread = (pool: number, nodes: number) => {
  let total = 0;
  for (let r = 0; r < nodes; r++) total += mult(r);
  return { first: pool * mult(0) / total, last: pool * mult(nodes - 1) / total };
};

const SIZES = [50, 200, 500, 1024, 2048, 5120, 10240];

const size = (gb: number) => (gb >= 1024 ? `${+(gb / 1024).toFixed(1)} TB` : `${gb} GB`);
const num = (n: number, d = 0) => n.toLocaleString(undefined, { maximumFractionDigits: d, minimumFractionDigits: d });
const usd = (n: number) => `$${n < 10 ? n.toFixed(2) : num(n, 0)}`;

const Section: React.FC<{ icon: string; title: string; children: React.ReactNode }> = ({ icon, title, children }) => (
  <div className="rounded-xl border border-gray-700 bg-gray-900/60 p-4">
    <div className="flex items-center gap-2 mb-2">
      <span className="text-lg">{icon}</span>
      <h3 className="font-semibold text-white">{title}</h3>
    </div>
    <div className="text-sm text-gray-300 space-y-2 leading-relaxed">{children}</div>
  </div>
);

const EarnGuide: React.FC<{ open: boolean; onClose: () => void }> = ({ open, onClose }) => {
  const navigate = useNavigate();
  const [g, setG] = useState<Guide | null>(null);
  const [failed, setFailed] = useState(false);
  const [sizeIdx, setSizeIdx] = useState(3);

  useEffect(() => {
    if (!open) return;
    setFailed(false);
    invoke<Guide>('get_earn_guide').then(setG).catch(() => setFailed(true));
  }, [open]);

  const gb = SIZES[sizeIdx];

  const storage = useMemo(() => {
    if (!g) return null;
    const points = Math.min(gb * g.storage_points_per_gb, g.storage_points_cap);
    const fullAt = g.storage_points_cap / g.storage_points_per_gb;
    const halfPool = g.node_pool_per_day_egoc / 2;
    const poolShare = halfPool * points / (g.storage_points_total + points);
    const drawBoost = (g.uptime_points_cap + points) / g.uptime_points_cap;
    const stakeBoost = points / g.storage_points_cap;
    const fits = g.plans.filter(p => p.gb <= gb);
    const perGb = fits.map(p => p.host_monthly_usd / p.gb);
    const low = perGb.length ? gb * Math.min(...perGb) : 0;
    const high = perGb.length ? gb * Math.max(...perGb) : 0;
    return { points, fullAt, low, high, halfPool, poolShare, drawBoost, stakeBoost };
  }, [g, gb]);

  const tiers = useMemo(() => (g ? [100, 1000, 10000].map(n => ({ n, ...spread(g.node_pool_per_day_egoc, n) })) : []), [g]);

  if (!open) return null;

  const go = (path: string) => { onClose(); navigate(path); };
  const pool = g?.node_pool_per_day_egoc ?? 0;
  const online = g?.online_nodes ?? 0;
  const yearLock = g?.staking_lock_bonus_pct.find(([d]) => d === 365)?.[1] ?? 0;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm" onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="w-full max-w-2xl max-h-[88vh] overflow-y-auto rounded-2xl border border-gray-700 bg-gray-800 shadow-2xl">
        <div className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-gray-700 bg-gray-800 px-6 py-5">
          <div>
            <h2 className="text-xl font-bold text-white">How your computer earns EGOC</h2>
            <p className="mt-1 text-sm text-gray-400">The network pays nodes for what they give it. These are the rules it runs today, on the test network.</p>
          </div>
          <button onClick={onClose} className="shrink-0 rounded-lg px-2 py-1 text-gray-400 hover:bg-gray-700 hover:text-white" aria-label="Close">✕</button>
        </div>

        {failed && !g && (
          <div className="px-6 py-10 text-center text-sm text-gray-400">The numbers could not be loaded right now. Open the Earn page for your live rewards.</div>
        )}
        {!failed && !g && (
          <div className="px-6 py-10 text-center text-sm text-gray-400">Loading the network's numbers…</div>
        )}

        {g && storage && (
          <div className="space-y-3 px-6 py-5">
            <div className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-4">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-lg">🚀</span>
                <h3 className="font-semibold text-emerald-300">The first 100 nodes earn 10× per point</h3>
              </div>
              <div className="text-sm text-gray-200 space-y-2 leading-relaxed">
                <p><b className="text-white">{num(pool)} EGOC a day</b> is shared by every node that stays online, halving every 4 years so it lasts 120 years. Nodes 1 to 100 earn 10× per point for as long as they stay online. Nodes 101 to 1,000 earn 7× down to 1.5×, and it reaches 1× by node 10,000.</p>
                <p className="text-emerald-200">
                  {g.my_rank !== null
                    ? <>You are node <b>#{num(g.my_rank + 1)}</b>, earning <b>{+g.my_multiplier.toFixed(2)}×</b> per point.</>
                    : <>{g.places_taken < g.early_places ? <><b>{num(g.early_places - g.places_taken)}</b> of the first {g.early_places} places are still open.</> : <>All of the first {g.early_places} places are taken.</>} Your place is set at your first check-in.</>}
                </p>
                <div className="grid grid-cols-3 gap-2 text-center">
                  {tiers.map(t => (
                    <div key={t.n} className="rounded-lg bg-gray-900/60 px-2 py-2">
                      <div className="text-xs text-gray-400">With {num(t.n)} nodes</div>
                      <div className="font-semibold text-white">≈ {num(t.first, t.first < 10 ? 1 : 0)} EGOC</div>
                      <div className="text-[11px] text-gray-500">a day for a first-100 node</div>
                      {t.n > 100 && <div className="text-[11px] text-gray-500">≈ {num(t.last, t.last < 10 ? 1 : 0)} for node #{num(t.n)}</div>}
                    </div>
                  ))}
                </div>
                <p className="text-gray-300">
                  {online > 0 ? <>Right now <b className="text-white">{num(online)}</b> {online === 1 ? 'node is' : 'nodes are'} online and earning{online < 100 ? ', so you can still be one of the first 100.' : '.'}</> : 'Nodes that are online now share the whole pool.'}
                  {' '}Your node checks in every {g.checkin_every_hours} hours and starts earning after {g.streak_needed} check-in{g.streak_needed === 1 ? '' : 's'} in a row. Half the pool goes by uptime and coverage, half by the storage you offer. One computer can run at most 2 nodes.
                </p>
              </div>
            </div>

            <Section icon="🗄️" title="Storage: the more you share, the stronger your node">
              <div>
                <div className="flex items-center justify-between text-xs text-gray-400 mb-1">
                  <span>How much do you want to rent?</span>
                  <span className="font-semibold text-white text-sm">{size(gb)}</span>
                </div>
                <input type="range" min={0} max={SIZES.length - 1} step={1} value={sizeIdx} onChange={e => setSizeIdx(+e.target.value)} className="w-full accent-emerald-500" />
                <div className="flex justify-between text-[11px] text-gray-500">{SIZES.map(s => <span key={s}>{size(s)}</span>)}</div>
              </div>
              <p>Storage is where most DRS points come from: {g.storage_points_per_gb} per GB, up to {num(g.storage_points_cap)} at {size(storage.fullAt)}. Uptime gives at most {g.uptime_points_cap} and coverage at most {g.coverage_points_per_witness * g.coverage_witness_cap}. {size(gb)} gives you <b className="text-white">{num(storage.points)} points</b>.</p>
              <div className="grid grid-cols-3 gap-2">
                <div className="rounded-lg bg-gray-900/60 px-3 py-2">
                  <div className="text-xs text-gray-400">Chance to be picked to make blocks</div>
                  <div className="font-semibold text-emerald-300">≈ {num(storage.drawBoost, storage.drawBoost < 10 ? 1 : 0)}× a node with no storage</div>
                  <div className="text-[11px] text-gray-500">Block makers get the block reward and 60% of fees</div>
                </div>
                <div className="rounded-lg bg-gray-900/60 px-3 py-2">
                  <div className="text-xs text-gray-400">Share of the {num(storage.halfPool)} EGOC a day that goes to storage</div>
                  <div className="font-semibold text-emerald-300">≈ {num(storage.poolShare, storage.poolShare < 10 ? 1 : 0)} EGOC a day</div>
                  <div className="text-[11px] text-gray-500">At today's {num(g.storage_points_total)} storage points on the network</div>
                </div>
                <div className="rounded-lg bg-gray-900/60 px-3 py-2">
                  <div className="text-xs text-gray-400">Staking rate while you stake</div>
                  <div className="font-semibold text-emerald-300">{+(g.node_staking_multiplier + storage.stakeBoost).toFixed(2)}× the normal rate</div>
                  <div className="text-[11px] text-gray-500">{g.node_staking_multiplier}× for an online node, +{+storage.stakeBoost.toFixed(2)}× for this storage</div>
                </div>
              </div>
              <p><b className="text-white">Paid plans on top:</b> when people buy storage, the {g.hosts_per_plan} computers that keep each plan get {g.host_share_pct}% of its price. If your {size(gb)} fills with paid plans, that is about <b className="text-emerald-300">{storage.low === storage.high ? usd(storage.low) : `${usd(storage.low)} to ${usd(storage.high)}`} a month</b>, paid in EGOC.</p>
              <div className="overflow-hidden rounded-lg border border-gray-700">
                <table className="w-full text-xs">
                  <thead className="bg-gray-900/60 text-gray-400">
                    <tr><th className="px-3 py-1.5 text-left font-medium">Plan</th><th className="px-3 py-1.5 text-right font-medium">People pay</th><th className="px-3 py-1.5 text-right font-medium">Each host gets</th></tr>
                  </thead>
                  <tbody>
                    {g.plans.map(p => (
                      <tr key={p.name} className={`border-t border-gray-700 ${p.gb <= gb ? 'text-gray-200' : 'text-gray-500'}`}>
                        <td className="px-3 py-1.5">{p.name} · {size(p.gb)}</td>
                        <td className="px-3 py-1.5 text-right">{usd(p.monthly_usd)}/mo</td>
                        <td className="px-3 py-1.5 text-right">{usd(p.host_monthly_usd)}/mo</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="text-xs text-gray-500">Files are encrypted before they reach you, so you can never read what you keep.</p>
            </Section>

            <Section icon="📡" title="Coverage: prove the signal where you are">
              <p>Show that there is real wireless coverage at your location. Each nearby node that confirms it adds {g.coverage_points_per_witness} points, up to {g.coverage_witness_cap} confirmations ({g.coverage_points_per_witness * g.coverage_witness_cap} points). A proof counts for {g.coverage_valid_days} days, and the points add to your uptime share of the pool.</p>
            </Section>

            <Section icon="🖥️" title="Compute: rent out idle CPU and GPU">
              <p>Other people run jobs on your machine, each in its own sandbox. You set the price: yours is {num(g.compute_core_hour_egoc, 2)} EGOC per core hour and {num(g.compute_gpu_hour_egoc, 2)} EGOC per GPU hour. Renters pay through escrow, so you are paid for the time they use.</p>
              <p className="text-gray-400">Example: 4 cores rented for a full day pay {num(4 * 24 * g.compute_core_hour_egoc, 1)} EGOC.</p>
            </Section>

            <Section icon="🔒" title="Staking: lock EGOC, earn a yearly rate">
              <p>Staking pays up to <b className="text-white">{num(g.staking_apr_pct, 1)}% a year</b>. Lock longer for more: {g.staking_lock_bonus_pct.map(([d, b]) => `+${num(b, 0)}% for ${d === 365 ? 'a year' : `${d} days`}`).join(', ')}.</p>
              <p>Keep your node online while you stake and your stake counts <b className="text-emerald-300">{g.node_staking_multiplier}×</b>. Share storage too and it rises to <b className="text-emerald-300">{g.node_staking_multiplier + 1}×</b> at {size(g.storage_points_cap / g.storage_points_per_gb)}, counted from each check-in: up to {num((g.staking_apr_pct + yearLock) * (g.node_staking_multiplier + 1), 0)}% a year.</p>
              <p>Staking has a fixed budget of {num(g.stake_budget_per_day_egoc)} EGOC a day, halving every 4 years, so it lasts 120 years. Once everyone's staking would use more than that, every rate goes down as more people stake. {g.stake_live ? <>Right now: <b className="text-white">{num(g.stake_rate_plain_pct, 1)}%</b> for a plain stake, up to <b className="text-emerald-300">{num(g.stake_rate_best_pct, 1)}%</b> for an online node with {size(g.storage_points_cap / g.storage_points_per_gb)} on a one-year lock.</> : null} Stakers also pay 90% less in fees.</p>
            </Section>

            <p className="px-1 text-xs text-gray-500">What you get depends on how many nodes are online, how much people buy and the EGOC price. These are test network coins.</p>
          </div>
        )}

        <div className="sticky bottom-0 flex flex-wrap items-center justify-end gap-2 border-t border-gray-700 bg-gray-800 px-6 py-4">
          <button onClick={() => go('/storage')} className="rounded-lg border border-gray-600 px-4 py-2 text-sm text-gray-200 hover:bg-gray-700">Set up storage</button>
          <button onClick={() => go('/earnings')} className="rounded-lg border border-gray-600 px-4 py-2 text-sm text-gray-200 hover:bg-gray-700">Open Earn</button>
          <button onClick={onClose} className="rounded-lg bg-emerald-500 px-5 py-2 text-sm font-semibold text-black hover:bg-emerald-400">Got it</button>
        </div>
      </div>
    </div>
  );
};

export default EarnGuide;
