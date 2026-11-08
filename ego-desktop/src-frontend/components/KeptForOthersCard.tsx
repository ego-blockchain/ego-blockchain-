import React, { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/tauri';

interface HostedFile {
  cid: string;
  owner: string;
  bytes: number;
  role: string;
  copies: number;
  holding: boolean;
  recorded: boolean;
  plan_active: boolean;
  last_proof: number;
}

interface HostedStorage {
  files: HostedFile[];
  file_count: number;
  hosted_bytes: number;
  paying_files: number;
  earned_24h_uegoc: number;
  earned_30d_uegoc: number;
  earned_total_uegoc: number;
  registered: boolean;
  paused_reason: string | null;
  plan_pay: boolean;
  plans_kept: number;
  reserved_bytes: number;
  offered_bytes: number;
  last_claim: number;
}

const SHOWN = 8;

function egoc(uegoc: number) {
  const v = uegoc / 1_000_000;
  return v.toLocaleString('en-US', { minimumFractionDigits: v > 0 && v < 0.01 ? 6 : 4, maximumFractionDigits: v > 0 && v < 0.01 ? 6 : 4 });
}

function size(bytes: number) {
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(2)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
  return `${Math.max(1, Math.round(bytes / 1e3))} KB`;
}

function ago(ts: number) {
  const s = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (s < 3600) return `${Math.max(1, Math.floor(s / 60))} min ago`;
  if (s < 86_400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86_400)} d ago`;
}

function short(addr: string) {
  return addr.length > 18 ? `${addr.slice(0, 10)}…${addr.slice(-6)}` : addr;
}

function status(f: HostedFile, planPay: boolean): { text: string; tone: string } {
  if (!f.holding) return { text: 'Receiving the data', tone: 'text-gray-400' };
  if (planPay) {
    if (f.last_proof > 0) return { text: `Held, proved ${ago(f.last_proof)}`, tone: 'text-green-400' };
    return { text: 'Held, first proof within the hour', tone: 'text-green-400' };
  }
  if (!f.recorded) return { text: "Not paying yet: its owner hasn't recorded it on the chain", tone: 'text-yellow-400' };
  if (!f.plan_active) return { text: 'Not paying: its owner has no paid plan right now', tone: 'text-yellow-400' };
  if (f.last_proof > 0) return { text: `Paying, last proved ${ago(f.last_proof)}`, tone: 'text-green-400' };
  return { text: 'Paying, first proof within the hour', tone: 'text-green-400' };
}

const KeptForOthersCard: React.FC<{ allocatedGb: number; onSetUp: () => void }> = ({ allocatedGb, onSetUp }) => {
  const [data, setData] = useState<HostedStorage | null>(null);

  useEffect(() => {
    const load = () => invoke<HostedStorage>('get_hosted_storage').then(setData).catch(() => {});
    load();
    const t = setInterval(load, 30_000);
    return () => clearInterval(t);
  }, []);

  if (!data) return null;

  return (
    <div className="bg-gray-800 rounded-2xl border border-gray-700 p-5 space-y-4">
      <div>
        <div className="font-semibold">Storage you keep for other people</div>
        <div className="text-xs text-gray-400 mt-1">
          {data.plan_pay
            ? "Each storage plan is kept by 3 computers. Each of them is paid its share of the plan every month, whether the space is used or not, while it stays online and keeps the owner's files."
            : "Every file is kept by 3 computers, one main copy and two backups. Each of them is paid on the chain for the days it proves it still holds the file, while the owner's storage plan runs."}
        </div>
      </div>

      <div className="grid grid-cols-3 gap-3">
        {[
          ['Last 24 hours', data.earned_24h_uegoc],
          ['Last 30 days', data.earned_30d_uegoc],
          ['All time', data.earned_total_uegoc],
        ].map(([label, v]) => (
          <div key={label as string} className="bg-gray-900/60 rounded-xl p-3">
            <div className="text-xs text-gray-400">{label}</div>
            <div className="text-lg font-semibold text-green-400">{egoc(v as number)} <span className="text-xs text-gray-400">EGOC</span></div>
          </div>
        ))}
      </div>

      {data.plan_pay && (
        <div className="text-sm text-gray-300">
          Space kept for{' '}
          <span className={data.plans_kept > 0 ? 'text-green-400' : 'text-gray-400'}>
            {data.plans_kept === 1 ? '1 storage plan' : `${data.plans_kept} storage plans`}
          </span>
          : {size(data.reserved_bytes)} reserved of {size(data.offered_bytes)} offered
          {data.last_claim > 0 && <span className="text-gray-500"> · checked in {ago(data.last_claim)}</span>}
        </div>
      )}

      <div className="text-sm text-gray-300">
        {data.file_count === 1 ? '1 file' : `${data.file_count} files`} kept here, {size(data.hosted_bytes)} held
        {!data.plan_pay && (
          <>
            ,{' '}
            <span className={data.paying_files > 0 ? 'text-green-400' : 'text-gray-400'}>{data.paying_files} paying</span>
          </>
        )}
      </div>

      {!data.registered && (
        <div className="text-xs text-yellow-400">
          This computer isn't registered on the network yet, so it can't prove files and be paid. It registers itself automatically.
        </div>
      )}
      {data.paused_reason && (
        <div className="text-xs text-yellow-400">Proofs are paused: {data.paused_reason}. Turn off any VPN or proxy to be paid.</div>
      )}
      {data.file_count === 0 && allocatedGb <= 0 && (
        <div className="flex items-center justify-between gap-3 text-xs text-gray-400">
          <span>Set aside storage space so other people's files can be kept here.</span>
          <button onClick={onSetUp} className="shrink-0 text-blue-400 hover:text-blue-300">Set up storage</button>
        </div>
      )}

      {data.files.length > 0 && (
        <div className="divide-y divide-gray-700/60">
          {data.files.slice(0, SHOWN).map(f => {
            const st = status(f, data.plan_pay);
            return (
              <div key={f.cid} className="py-2 flex items-center justify-between gap-3 text-sm">
                <div className="min-w-0">
                  <div className="text-gray-200">
                    {size(f.bytes)} · {f.role === 'master' ? 'Main copy' : 'Backup copy'}
                    {f.role === 'master' && <span className="text-gray-500"> · {Math.min(f.copies, 3)} of 3 copies</span>}
                  </div>
                  <div className="text-xs text-gray-500 truncate">Owner {short(f.owner)}</div>
                </div>
                <div className={`text-xs text-right ${st.tone}`}>{st.text}</div>
              </div>
            );
          })}
          {data.file_count > SHOWN && (
            <div className="pt-2 text-xs text-gray-500">and {data.file_count - SHOWN} more</div>
          )}
        </div>
      )}
    </div>
  );
};

export default KeptForOthersCard;
