import React, { useState, useEffect, useRef } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { open as dialogOpen } from '@tauri-apps/api/dialog';
import { readDir } from '@tauri-apps/api/fs';

interface SiteFile {
  path: string;
  cid: string;
  mime_type: string;
  size: number;
}

interface HostedSite {
  name: string;
  root_cid: string;
  owner: string;
  deployed_at: number;
  updated_at: number;
  file_count: number;
  total_size: number;
  local_url: string;
  files: SiteFile[];
  custom_domain?: string;
}

interface FinalizeFileEntry {
  path: string;
  cid: string;
  mime_type: string;
  size: number;
}

interface FlatFile {
  absolutePath: string;
  relativePath: string;
  name: string;
}

interface HostingPlanOption {
  tier: string;
  label: string;
  usd_per_month: number;
  max_sites: number;
  max_storage_gb: number;
  egoc_per_month: number;
  uegoc_per_month: number;
}

interface ActiveHostingPlan {
  owner: string;
  tier: string;
  months: number;
  started_at: number;
  expires_at: number;
  paid_uegoc: number;
  tx_hash: string;
}

interface HostingAccess {
  has_access: boolean;
  in_trial: boolean;
  trial_days_left: number;
  has_plan: boolean;
  plan_tier: string | null;
  plan_expires_at: number | null;
}

const NS1 = 'ns1.egoblockchain.com';
const NS2 = 'ns2.egoblockchain.com';

function slugFromDomain(domain: string): string {
  return domain
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .replace(/[^a-z0-9]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

function fmtBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(2)} MB`;
  return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function timeAgo(ts: number): string {
  const diff = Math.floor(Date.now() / 1000 - ts);
  if (diff < 60) return 'just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function mimeForFile(name: string): string {
  const ext = name.split('.').pop()?.toLowerCase() ?? '';
  const map: Record<string, string> = {
    html: 'text/html', htm: 'text/html',
    css: 'text/css', js: 'application/javascript', mjs: 'application/javascript',
    json: 'application/json',
    png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg',
    gif: 'image/gif', svg: 'image/svg+xml', ico: 'image/x-icon', webp: 'image/webp',
    woff: 'font/woff', woff2: 'font/woff2', ttf: 'font/ttf',
    txt: 'text/plain', xml: 'application/xml', pdf: 'application/pdf',
    wasm: 'application/wasm', mp4: 'video/mp4', webm: 'video/webm',
    mp3: 'audio/mpeg', wav: 'audio/wav',
  };
  return map[ext] ?? 'application/octet-stream';
}


const IGNORED_DIRS = new Set([
  'venv', '.venv', 'env', '.env',
  'node_modules', '__pycache__', '.git', '.svn',
  'dist', 'build', '.next', '.nuxt', '.cache',
  'target', '.idea', '.vscode',
]);

function flattenDir(entries: any[], _folderPath: string, base: string): FlatFile[] {
  const normBase = base.replace(/\\/g, '/').replace(/\/+$/, '');
  const result: FlatFile[] = [];
  for (const entry of entries) {
    if (entry.children !== undefined) {
      const dirName = (entry.name ?? '').toLowerCase();
      if (IGNORED_DIRS.has(dirName)) continue;
      result.push(...flattenDir(entry.children, _folderPath, base));
    } else if (entry.path) {
      const normPath = entry.path.replace(/\\/g, '/');
      const rel = normPath.startsWith(normBase)
        ? normPath.slice(normBase.length)
        : '/' + normPath.split('/').pop();
      result.push({
        absolutePath: entry.path,
        relativePath: rel.startsWith('/') ? rel : '/' + rel,
        name: entry.name ?? normPath.split('/').pop() ?? '',
      });
    }
  }
  return result;
}

const MAX_SITE_SIZE = 2 * 1024 * 1024 * 1024;

function NsCard({ domain }: { domain: string }) {
  const [copied, setCopied] = useState('');

  function copy(val: string, key: string) {
    navigator.clipboard.writeText(val).catch(() => {});
    setCopied(key);
    setTimeout(() => setCopied(''), 2000);
  }

  return (
    <div className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-4 space-y-4 text-sm">
      <div className="font-semibold text-blue-300">
        One step — change your nameservers
      </div>
      <div className="text-xs text-gray-400 leading-relaxed">
        Log in to wherever you bought <span className="text-white font-mono">{domain}</span> (GoDaddy, Namecheap, etc.),
        find <strong className="text-white">Nameservers</strong> or <strong className="text-white">NS records</strong>, and replace them with:
      </div>
      <div className="space-y-1.5">
        {[NS1, NS2].map((ns, i) => (
          <div key={ns} className="bg-gray-900 rounded-lg flex items-center overflow-hidden font-mono text-xs">
            <span className="px-3 py-2.5 text-yellow-400 w-10 text-center border-r border-gray-700">{i + 1}</span>
            <span className="px-3 py-2.5 text-green-300 flex-1">{ns}</span>
            <button
              onClick={() => copy(ns, ns)}
              className="px-3 py-2.5 text-gray-400 hover:text-white hover:bg-gray-700 transition-colors border-l border-gray-700"
            >
              {copied === ns ? '✓' : 'Copy'}
            </button>
          </div>
        ))}
      </div>
      <div className="text-xs text-gray-500 leading-relaxed">
        That's it. Ego's network resolves your domain — files are stored and served
        by Ego nodes across the network, not from any single server.
        DNS changes take a few minutes to 48h to propagate.
      </div>
      <div className="text-xs text-gray-600">
        Once done, <span className="text-white font-mono">https://{domain}</span> goes live.
      </div>
    </div>
  );
}

function RemoveModal({ site, onConfirm, onCancel }: {
  site: HostedSite;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const label = site.custom_domain ?? site.name;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" onClick={onCancel}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <div
        className="relative w-full max-w-sm bg-gray-800 border border-gray-700 rounded-2xl shadow-2xl p-6 space-y-5"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-start gap-4">
          <div className="w-10 h-10 rounded-xl bg-red-500/15 border border-red-500/30 flex items-center justify-center shrink-0">
            <svg className="w-5 h-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
            </svg>
          </div>
          <div>
            <div className="font-semibold text-white">Remove site</div>
            <div className="text-sm text-gray-400 mt-1">
              This will permanently remove <span className="text-white font-mono">{label}</span> and all its files from the network.
            </div>
          </div>
        </div>

        <div className="bg-gray-900 rounded-xl px-4 py-3 text-xs text-gray-500 space-y-1">
          <div className="flex justify-between">
            <span>Files</span>
            <span className="text-gray-300">{site.file_count}</span>
          </div>
          <div className="flex justify-between">
            <span>Size</span>
            <span className="text-gray-300">{fmtBytes(site.total_size)}</span>
          </div>
          {site.custom_domain && (
            <div className="flex justify-between">
              <span>Domain</span>
              <span className="text-gray-300 font-mono">{site.custom_domain}</span>
            </div>
          )}
        </div>

        <div className="flex gap-3">
          <button
            onClick={onCancel}
            className="flex-1 py-2.5 bg-gray-700 hover:bg-gray-600 rounded-xl text-sm font-medium transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="flex-1 py-2.5 bg-red-600 hover:bg-red-500 rounded-xl text-sm font-semibold transition-colors"
          >
            Remove
          </button>
        </div>
      </div>
    </div>
  );
}

const HostingPage: React.FC = () => {
  const [sites, setSites]         = useState<HostedSite[]>([]);
  const [loading, setLoading]     = useState(true);
  const [deploying, setDeploying] = useState(false);
  const [deployProgress, setDeployProgress] = useState('');
  const [error, setError]         = useState('');
  const [domainInput, setDomainInput] = useState('');
  const [selectedFolder, setSelectedFolder] = useState<string | null>(null);
  const [folderName, setFolderName]         = useState('');
  const [folderFileCount, setFolderFileCount] = useState(0);
  const [expandedSite, setExpandedSite] = useState<string | null>(null);
  const [justDeployed, setJustDeployed] = useState<{ domain: string; name: string } | null>(null);
  const [copiedUrl, setCopiedUrl] = useState('');
  const [removingSite, setRemovingSite] = useState<HostedSite | null>(null);
  const [dnsStatuses, setDnsStatuses] = useState<Record<string, 'pending' | 'live' | 'checking'>>({});
  const [plans, setPlans]             = useState<HostingPlanOption[]>([]);
  const [myPlan, setMyPlan]           = useState<ActiveHostingPlan | null>(null);
  const [planMonths, setPlanMonths]   = useState(1);
  const [purchasing, setPurchasing]   = useState('');
  const [planError, setPlanError]     = useState('');
  const [confirmCancel, setConfirmCancel] = useState(false);
  const [access, setAccess]           = useState<HostingAccess | null>(null);
  const [previewSite, setPreviewSite] = useState<HostedSite | null>(null);
  const [previewInput, setPreviewInput] = useState('');

  const load = () => {
    invoke<HostedSite[]>('get_hosted_sites')
      .then(setSites).catch(() => {}).finally(() => setLoading(false));
  };

  const checkDnsStatuses = useRef<(sitesArr: HostedSite[]) => void>();
  checkDnsStatuses.current = (sitesArr: HostedSite[]) => {
    sitesArr.forEach(site => {
      if (!site.custom_domain) return;
      const d = site.custom_domain;
      setDnsStatuses(prev => ({ ...prev, [d]: prev[d] ?? 'checking' }));
      invoke<string>('check_domain_status', { domain: d })
        .then(status => setDnsStatuses(prev => ({ ...prev, [d]: status as 'pending' | 'live' })))
        .catch(() => setDnsStatuses(prev => ({ ...prev, [d]: 'pending' })));
    });
  };

  useEffect(() => {
    load();
    invoke<HostingPlanOption[]>('get_hosting_plans').then(setPlans).catch(() => {});
    invoke<ActiveHostingPlan | null>('get_my_hosting_plan').then(setMyPlan).catch(() => {});
    invoke<HostingAccess>('get_hosting_access').then(setAccess).catch(() => {});
  }, []);

  useEffect(() => {
    if (sites.length > 0) checkDnsStatuses.current!(sites);
    const interval = setInterval(() => {
      if (sites.length > 0) checkDnsStatuses.current!(sites);
    }, 60_000);
    return () => clearInterval(interval);
  }, [sites]);

  async function pickFolder() {
    try {
      const result = await dialogOpen({ directory: true, multiple: false, title: 'Select website folder' });
      if (!result || Array.isArray(result)) return;
      const folder = result as string;
      setSelectedFolder(folder);
      setFolderName(folder.replace(/\\/g, '/').split('/').pop() || folder);
      setError('');
      const entries = await readDir(folder, { recursive: true });
      const files = flattenDir(entries, folder, folder);
      setFolderFileCount(files.length);
    } catch (e: any) {
      setError(String(e));
    }
  }

  const domain = domainInput.trim().toLowerCase()
    .replace(/^https?:\/\//, '').replace(/\/$/, '');
  const isValidDomain = domain.length >= 3 && domain.includes('.');
  const slug = isValidDomain ? slugFromDomain(domain) : '';
  const accessOk  = !access || access.has_access;
  const canDeploy = !deploying && isValidDomain && selectedFolder !== null && accessOk;

  async function deploy() {
    if (!canDeploy || !selectedFolder) return;
    setDeploying(true);
    setError('');

    try {
      setDeployProgress('Preparing…');
      await invoke('deploy_site_begin', { name: slug });

      const entries = await readDir(selectedFolder, { recursive: true });
      const files   = flattenDir(entries, selectedFolder, selectedFolder);

      if (files.length === 0) { throw new Error('No files found in selected folder.'); }
      console.log('[deploy] files:', files.map(f => f.relativePath));

      const finalized: FinalizeFileEntry[] = [];
      let totalSize = 0;

      for (let i = 0; i < files.length; i++) {
        const file  = files[i];
        const label = file.name.length > 30 ? '…' + file.name.slice(-27) : file.name;
        setDeployProgress(`Uploading ${i + 1} / ${files.length} — ${label}`);

        const result = await invoke<{ cid: string; size: number }>('deploy_site_file', {
          name: slug,
          file: { path: file.relativePath, source_path: file.absolutePath, mime_type: mimeForFile(file.name) },
        });
        totalSize += result.size;

        if (totalSize > MAX_SITE_SIZE) { throw new Error('Total site size exceeds 2 GB.'); }

        finalized.push({ path: file.relativePath, cid: result.cid, mime_type: mimeForFile(file.name), size: result.size });
      }

      setDeployProgress('Publishing to network…');
      await invoke<HostedSite>('finalize_deploy', { name: slug, files: finalized });
      await invoke('set_custom_domain', { name: slug, domain });

      setJustDeployed({ domain, name: slug });
      setDomainInput('');
      setSelectedFolder(null);
      setFolderName('');
      setFolderFileCount(0);
      load();
    } catch (e: any) {
      setError(String(e));
    } finally {
      setDeploying(false);
      setDeployProgress('');
    }
  }

  async function undeploy(site: HostedSite) {
    setRemovingSite(site);
  }

  async function confirmUndeploy() {
    if (!removingSite) return;
    const site = removingSite;
    setRemovingSite(null);
    try {
      await invoke('undeploy_site', { name: site.name });
      if (justDeployed?.name === site.name) setJustDeployed(null);
      load();
    } catch (e: any) {
      setError(String(e));
    }
  }

  async function cancelPlan() {
    try {
      await invoke('cancel_hosting_plan');
      setMyPlan(null);
      setConfirmCancel(false);
    } catch (e: any) {
      setPlanError(String(e));
    }
  }

  async function buyPlan(tier: string) {
    setPurchasing(tier);
    setPlanError('');
    try {
      const plan = await invoke<ActiveHostingPlan>('purchase_hosting_plan', { tier, months: planMonths });
      setMyPlan(plan);
      invoke<HostingPlanOption[]>('get_hosting_plans').then(setPlans).catch(() => {});
      invoke<HostingAccess>('get_hosting_access').then(setAccess).catch(() => {});
    } catch (e: any) {
      setPlanError(String(e));
    } finally {
      setPurchasing('');
    }
  }

  function copyUrl(url: string) {
    navigator.clipboard.writeText(url).catch(() => {});
    setCopiedUrl(url);
    setTimeout(() => setCopiedUrl(''), 2000);
  }

  return (
    <div className="p-6 space-y-5 max-w-2xl mx-auto">

      {removingSite && (
        <RemoveModal
          site={removingSite}
          onConfirm={confirmUndeploy}
          onCancel={() => setRemovingSite(null)}
        />
      )}

      <div>
        <h2 className="text-xl font-bold">Web Hosting</h2>
        <p className="text-sm text-gray-400 mt-1">
          Deploy any website to the Ego network. Bring your own domain — files are AES-256 encrypted before leaving your device. No node on the network can read your content.
        </p>
      </div>

      {access && !access.has_plan && access.in_trial && access.trial_days_left <= 3 && access.trial_days_left > 0 && (
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-2xl px-5 py-3 flex items-center justify-between text-sm">
          <div className="text-yellow-300">
            <span className="font-semibold">{access.trial_days_left} day{access.trial_days_left !== 1 ? 's' : ''} left</span>
            <span className="text-yellow-400/70 ml-2">in your free trial — subscribe to keep hosting.</span>
          </div>
          <span className="text-xs text-yellow-500">Free trial</span>
        </div>
      )}

      {access && !access.has_access && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-2xl px-5 py-4 space-y-2">
          <div className="text-sm font-semibold text-red-300">Free trial expired</div>
          <div className="text-xs text-gray-400">
            Your 7-day free trial has ended. Subscribe to a plan below to deploy new sites and keep your domains active.
          </div>
          <div className="text-xs text-gray-500 mt-1">
            Existing nameserver settings (<span className="font-mono text-gray-400">ns1/ns2.egoblockchain.com</span>) will stop resolving until you subscribe.
          </div>
        </div>
      )}

      {access && access.in_trial && access.trial_days_left > 3 && !access.has_plan && (
        <div className="bg-blue-500/8 border border-blue-500/20 rounded-2xl px-5 py-3 flex items-center justify-between text-xs text-blue-300">
          <span><span className="font-semibold">{access.trial_days_left} days</span> remaining in your free trial</span>
          <span className="text-blue-500">Free trial</span>
        </div>
      )}

      {plans.length > 0 && (
        <div className="bg-gray-800 rounded-2xl border border-gray-700 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="font-semibold text-sm">Hosting Plans</div>
              <div className="text-xs text-gray-400 mt-0.5">Paid in EGOC · up to 4× cheaper than reseller hosting</div>
            </div>
            <div className="flex items-center gap-2 text-xs text-gray-400">
              <span>Duration:</span>
              {[1, 3, 6, 12].map(m => (
                <button
                  key={m}
                  onClick={() => setPlanMonths(m)}
                  className={`px-2.5 py-1 rounded-lg transition-colors ${planMonths === m ? 'bg-blue-600 text-white' : 'bg-gray-700 hover:bg-gray-600'}`}
                >
                  {m}mo
                </button>
              ))}
            </div>
          </div>

          {myPlan && (
            <div className="bg-green-500/10 border border-green-500/25 rounded-xl px-4 py-3 text-xs text-green-300 flex items-center justify-between">
              <div>
                <span className="font-semibold capitalize">{myPlan.tier}</span> plan active
                <span className="text-gray-400 ml-2">· expires {new Date(myPlan.expires_at * 1000).toLocaleDateString()}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                {confirmCancel ? (
                  <div className="flex items-center gap-2">
                    <span className="text-gray-400">Cancel subscription?</span>
                    <button onClick={cancelPlan} className="text-red-400 hover:text-red-300 font-semibold">Yes</button>
                    <button onClick={() => setConfirmCancel(false)} className="text-gray-400 hover:text-white">No</button>
                  </div>
                ) : (
                  <button
                    onClick={() => setConfirmCancel(true)}
                    className="text-gray-500 hover:text-red-400 transition-colors"
                  >
                    Unsubscribe
                  </button>
                )}
              </div>
            </div>
          )}

          <div className="grid grid-cols-3 gap-3">
            {plans.map(plan => {
              const marketRate: Record<string, number> = { starter: 19.95, pro: 24.95, business: 54.95 };
              const isActive   = myPlan?.tier === plan.tier;
              const isCurrent  = !!myPlan && myPlan.tier !== plan.tier;
              const totalEgoc  = (plan.egoc_per_month * planMonths).toFixed(4);
              const totalUsd   = (plan.usd_per_month * planMonths).toFixed(2);
              const market     = ((marketRate[plan.tier] ?? 25) * planMonths).toFixed(2);
              const btnLabel   = purchasing === plan.tier
                ? 'Processing…'
                : isActive
                  ? `Renew · +${planMonths}mo`
                  : isCurrent
                    ? `Switch · ${planMonths}mo`
                    : `Subscribe · ${planMonths}mo`;
              return (
                <div
                  key={plan.tier}
                  className={`rounded-xl border p-4 space-y-3 relative ${
                    isActive
                      ? 'border-green-500/40 bg-green-500/5'
                      : plan.tier === 'pro'
                        ? 'border-blue-500/50 bg-blue-500/5'
                        : 'border-gray-700 bg-gray-900/50'
                  }`}
                >
                  {isActive && (
                    <div className="absolute -top-2.5 left-1/2 -translate-x-1/2 bg-green-600 text-white text-[10px] font-bold px-2 py-0.5 rounded-full">
                      CURRENT
                    </div>
                  )}
                  {!isActive && plan.tier === 'pro' && (
                    <div className="absolute -top-2.5 left-1/2 -translate-x-1/2 bg-blue-600 text-white text-[10px] font-bold px-2 py-0.5 rounded-full">
                      POPULAR
                    </div>
                  )}
                  <div>
                    <div className="font-semibold text-sm">{plan.label}</div>
                    <div className="text-xs text-gray-500 mt-0.5">
                      {plan.max_sites === 0 ? 'Unlimited' : plan.max_sites} sites · {plan.max_storage_gb >= 1000 ? `${plan.max_storage_gb / 1000} TB` : `${plan.max_storage_gb} GB`}
                    </div>
                  </div>
                  <div>
                    <div className="text-lg font-bold">
                      {totalEgoc}
                      <span className="text-xs font-normal text-gray-400 ml-1">EGOC</span>
                    </div>
                    <div className="text-xs text-gray-500">
                      ≈ ${totalUsd} · resellers pay ${market}
                    </div>
                  </div>
                  <button
                    onClick={() => buyPlan(plan.tier)}
                    disabled={!!purchasing}
                    className={`w-full py-2 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50 ${
                      isActive
                        ? 'bg-green-600/30 hover:bg-green-600/50 text-green-300'
                        : plan.tier === 'pro'
                          ? 'bg-blue-600 hover:bg-blue-500'
                          : 'bg-gray-700 hover:bg-gray-600'
                    }`}
                  >
                    {btnLabel}
                  </button>
                </div>
              );
            })}
          </div>

          {planError && (
            <div className="text-xs text-red-400 bg-red-500/10 rounded-xl px-3 py-2">{planError}</div>
          )}
        </div>
      )}

      {justDeployed && (
        <div className="bg-green-500/10 border border-green-500/30 rounded-2xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="font-semibold text-green-300">Published to the Ego network</div>
            <button onClick={() => setJustDeployed(null)} className="text-gray-500 hover:text-white text-xl leading-none">×</button>
          </div>
          <NsCard domain={justDeployed.domain} />
        </div>
      )}

      <div className="bg-gray-800 rounded-2xl border border-gray-700 p-5 space-y-4">

        <div>
          <label className="text-xs font-medium text-gray-400 block mb-1.5">Your domain</label>
          <input
            value={domainInput}
            onChange={e => setDomainInput(e.target.value.replace(/\s/g, ''))}
            placeholder="mysite.com"
            disabled={deploying}
            className="w-full bg-gray-900 border border-gray-600 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none font-mono transition-colors disabled:opacity-50"
          />
          {isValidDomain && (
            <div className="mt-1.5 text-xs text-gray-500">
              After publishing, you'll just change your nameservers to Ego's — one step, no technical setup.
            </div>
          )}
        </div>

        <div>
          <label className="text-xs font-medium text-gray-400 block mb-1.5">Website folder</label>

          {deploying ? (
            <div className="border-2 border-dashed border-blue-500/40 rounded-xl py-8 text-center space-y-3">
              <div className="text-2xl animate-pulse">🚀</div>
              <div className="text-sm text-blue-400 font-medium">{deployProgress}</div>
              <div className="w-48 mx-auto bg-gray-700 rounded-full h-1">
                <div className="bg-blue-500 h-1 rounded-full animate-pulse w-full" />
              </div>
            </div>
          ) : selectedFolder ? (
            <div className="border-2 border-dashed border-green-500/40 rounded-xl py-5 px-4 text-center space-y-2">
              <div className="text-green-400 font-semibold text-sm">{folderName}</div>
              <div className="text-xs text-gray-500">
                {folderFileCount > 0 ? `${folderFileCount} file${folderFileCount !== 1 ? 's' : ''}` : 'Reading…'}
              </div>
              <button
                className="text-xs text-gray-500 underline"
                onClick={() => { setSelectedFolder(null); setFolderName(''); setFolderFileCount(0); }}
              >
                Change folder
              </button>
            </div>
          ) : (
            <button
              onClick={pickFolder}
              className="w-full border-2 border-dashed border-gray-600 hover:border-blue-500/50 rounded-xl py-10 text-center transition-colors"
            >
              <div className="text-4xl mb-3">📂</div>
              <div className="text-sm text-gray-300 font-medium">Click to select your website folder</div>
              <div className="text-xs text-gray-500 mt-1">HTML, CSS, JS, images — up to 2 GB</div>
            </button>
          )}
        </div>

        {error && (
          <div className="text-sm text-red-400 bg-red-500/10 rounded-xl px-4 py-2.5">{error}</div>
        )}

        <button
          onClick={deploy}
          disabled={!canDeploy}
          className="w-full py-3.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed rounded-xl font-semibold text-sm transition-colors"
        >
          {deploying
            ? deployProgress || 'Deploying…'
            : !accessOk
              ? 'Subscribe to a plan to deploy'
              : !isValidDomain
                ? 'Enter your domain to continue'
                : selectedFolder === null
                  ? 'Select your website folder'
                  : `Publish ${domain}`}
        </button>
      </div>

      {(loading || sites.length > 0) && (
        <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
          <div className="px-5 py-4 border-b border-gray-700 flex items-center justify-between">
            <h3 className="font-semibold text-sm">Published Sites</h3>
            <span className="text-xs text-gray-500">{sites.length} site{sites.length !== 1 ? 's' : ''}</span>
          </div>

          {loading ? (
            <div className="px-5 py-8 text-center text-gray-500 text-sm animate-pulse">Loading…</div>
          ) : (
            <div className="divide-y divide-gray-700/50">
              {sites.map(site => {
                const displayDomain = site.custom_domain ?? site.name;
                const publicUrl = site.custom_domain ? `https://${site.custom_domain}` : site.local_url;

                return (
                  <div key={site.name}>
                    <div className="flex items-center gap-3 px-5 py-4">
                      <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-sm font-bold shrink-0">
                        {displayDomain.charAt(0).toUpperCase()}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <div className="text-sm font-semibold font-mono truncate">{displayDomain}</div>
                          {site.custom_domain && (() => {
                            const status = dnsStatuses[site.custom_domain];
                            if (status === 'live') return (
                              <span className="shrink-0 flex items-center gap-1 text-xs font-medium text-green-400 bg-green-400/10 border border-green-400/25 rounded-full px-2 py-0.5">
                                <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
                                Live
                              </span>
                            );
                            return (
                              <span className="shrink-0 flex items-center gap-1 text-xs font-medium text-yellow-400 bg-yellow-400/10 border border-yellow-400/25 rounded-full px-2 py-0.5">
                                <span className="w-1.5 h-1.5 rounded-full bg-yellow-400" />
                                Pending
                              </span>
                            );
                          })()}
                        </div>
                        <div className="text-xs text-gray-500 mt-0.5">
                          {site.file_count} files · {fmtBytes(site.total_size)} · {timeAgo(site.updated_at)}
                        </div>
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <button
                          onClick={() => copyUrl(publicUrl)}
                          className="text-xs px-2.5 py-1.5 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors"
                        >
                          {copiedUrl === publicUrl ? '✓' : 'Copy URL'}
                        </button>
                        <button
                          onClick={() => { setPreviewSite(site); setPreviewInput(site.custom_domain ?? site.name); }}
                          className="text-xs px-2.5 py-1.5 bg-blue-600/20 hover:bg-blue-600/40 text-blue-300 rounded-lg transition-colors"
                        >
                          Preview
                        </button>
                        <button
                          onClick={() => setExpandedSite(expandedSite === site.name ? null : site.name)}
                          className="text-xs px-2 py-1.5 text-gray-500 hover:text-white rounded-lg transition-colors"
                        >
                          {expandedSite === site.name ? '▲' : '▼'}
                        </button>
                        <button
                          onClick={() => undeploy(site)}
                          className="text-xs px-2.5 py-1.5 text-red-400 hover:bg-red-500/20 rounded-lg transition-colors"
                        >
                          Remove
                        </button>
                      </div>
                    </div>

                    {expandedSite === site.name && (
                      <div className="px-5 pb-4 space-y-3">
                        {site.custom_domain && <NsCard domain={site.custom_domain} />}
                        <div className="bg-gray-900 rounded-xl overflow-hidden">
                          <div className="max-h-36 overflow-y-auto divide-y divide-gray-700/30">
                            {site.files.map(f => (
                              <div key={f.path} className="flex justify-between px-3 py-1.5 text-xs">
                                <span className="font-mono text-gray-300">{f.path}</span>
                                <span className="text-gray-500 shrink-0 ml-3">{fmtBytes(f.size)}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
      {/* ── In-app site preview modal ── */}
      {previewSite && (
        <div className="fixed inset-0 z-50 flex flex-col bg-black/80 backdrop-blur-md">
          {/* Browser chrome */}
          <div className="flex items-center gap-3 px-4 py-3 bg-gray-900 border-b border-gray-700 shrink-0">
            {/* Traffic lights */}
            <div className="flex items-center gap-1.5 shrink-0">
              <button onClick={() => setPreviewSite(null)}
                className="w-3 h-3 rounded-full bg-red-500 hover:bg-red-400 transition-colors" />
              <div className="w-3 h-3 rounded-full bg-yellow-500/60" />
              <div className="w-3 h-3 rounded-full bg-green-500/60" />
            </div>

            {/* Back / Forward / Reload */}
            <div className="flex items-center gap-1 shrink-0 text-gray-500">
              <button className="w-7 h-7 flex items-center justify-center hover:bg-gray-800 rounded-md text-sm" title="Back">‹</button>
              <button className="w-7 h-7 flex items-center justify-center hover:bg-gray-800 rounded-md text-sm" title="Forward">›</button>
              <button
                onClick={() => {
                  const frame = document.getElementById('ego-preview-frame') as HTMLIFrameElement | null;
                  if (frame) frame.src = frame.src;
                }}
                className="w-7 h-7 flex items-center justify-center hover:bg-gray-800 rounded-md text-sm" title="Reload">↻</button>
            </div>

            {/* Address bar */}
            <div className="flex-1 flex items-center bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 gap-2 min-w-0">
              <span className="text-green-400 text-xs shrink-0">🔒</span>
              <input
                value={previewInput}
                onChange={e => setPreviewInput(e.target.value)}
                onKeyDown={e => {
                  if (e.key === 'Enter') {
                    const frame = document.getElementById('ego-preview-frame') as HTMLIFrameElement | null;
                    if (frame) frame.src = previewSite.local_url;
                  }
                }}
                className="flex-1 bg-transparent text-sm text-gray-200 font-mono outline-none min-w-0"
              />
            </div>

            {/* Open in real browser */}
            <button
              onClick={() => invoke('open_in_browser', { url: previewSite.local_url })}
              className="text-xs px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded-lg shrink-0 transition-colors"
              title="Open in system browser"
            >
              ↗ Open
            </button>
          </div>

          {/* Viewport tabs for responsive preview */}
          <div className="flex items-center gap-1 px-4 py-2 bg-gray-900/80 border-b border-gray-800 shrink-0">
            {[
              { label: '🖥 Desktop', w: '100%' },
              { label: '📱 Mobile', w: '390px' },
              { label: '📟 Tablet', w: '768px' },
            ].map(vp => (
              <button
                key={vp.label}
                onClick={() => {
                  const wrap = document.getElementById('ego-preview-wrap');
                  if (wrap) wrap.style.width = vp.w;
                }}
                className="text-[11px] px-3 py-1 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-400 hover:text-white transition-colors"
              >
                {vp.label}
              </button>
            ))}
            <span className="ml-auto text-[11px] text-gray-600 font-mono">{previewSite.custom_domain ?? previewSite.name}</span>
          </div>

          {/* iframe area */}
          <div className="flex-1 overflow-auto bg-gray-950 flex justify-center py-4">
            <div
              id="ego-preview-wrap"
              className="h-full transition-all duration-300 bg-white rounded-t-lg overflow-hidden shadow-2xl"
              style={{ width: '100%' }}
            >
              {previewSite.local_url ? (
                <iframe
                  id="ego-preview-frame"
                  src={previewSite.local_url}
                  title="Site preview"
                  className="w-full h-full border-0"
                  sandbox="allow-scripts allow-same-origin allow-forms"
                />
              ) : (
                <div className="flex items-center justify-center h-full text-gray-400 text-sm">
                  <div className="text-center space-y-2">
                    <div className="text-4xl">🌐</div>
                    <p>No local preview URL available.</p>
                    <p className="text-xs text-gray-600">The site may still be deploying.</p>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default HostingPage;
