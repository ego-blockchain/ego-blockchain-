import React, { useState, useEffect, useRef } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { open as shellOpen } from '@tauri-apps/api/shell';

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

async function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve((reader.result as string).split(',')[1]);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
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

const HostingPage: React.FC = () => {
  const [sites, setSites]         = useState<HostedSite[]>([]);
  const [loading, setLoading]     = useState(true);
  const [deploying, setDeploying] = useState(false);
  const [deployProgress, setDeployProgress] = useState('');
  const [error, setError]         = useState('');
  const [domainInput, setDomainInput] = useState('');
  const [pendingFiles, setPendingFiles] = useState<File[]>([]);
  const [pendingSize, setPendingSize]   = useState(0);
  const [expandedSite, setExpandedSite] = useState<string | null>(null);
  const [justDeployed, setJustDeployed] = useState<{ domain: string; name: string } | null>(null);
  const [copiedUrl, setCopiedUrl] = useState('');
  const dirInputRef  = useRef<HTMLInputElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const load = () => {
    invoke<HostedSite[]>('get_hosted_sites')
      .then(setSites).catch(() => {}).finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
    if (dirInputRef.current) {
      dirInputRef.current.setAttribute('webkitdirectory', '');
      dirInputRef.current.setAttribute('directory', '');
      dirInputRef.current.setAttribute('multiple', '');
    }
  }, []);

  function stageFiles(fileList: FileList) {
    const files = Array.from(fileList);
    if (!files.length) return;
    const totalSize = files.reduce((s, f) => s + f.size, 0);
    if (totalSize > MAX_SITE_SIZE) { setError('Total site size exceeds 2 GB.'); return; }
    setPendingFiles(files);
    setPendingSize(totalSize);
    setError('');
  }

  function handleFileInput(e: React.ChangeEvent<HTMLInputElement>) {
    if (e.target.files?.length) stageFiles(e.target.files);
    e.target.value = '';
  }

  const domain = domainInput.trim().toLowerCase()
    .replace(/^https?:\/\//, '').replace(/\/$/, '');
  const isValidDomain = domain.length >= 3 && domain.includes('.');
  const slug = isValidDomain ? slugFromDomain(domain) : '';
  const canDeploy = !deploying && isValidDomain && pendingFiles.length > 0;

  async function deploy() {
    if (!canDeploy) return;
    setDeploying(true);
    setError('');

    try {
      setDeployProgress('Preparing…');
      await invoke('deploy_site_begin', { name: slug });

      const entries: FinalizeFileEntry[] = [];

      for (let i = 0; i < pendingFiles.length; i++) {
        const file = pendingFiles[i];
        const label = file.name.length > 30 ? '…' + file.name.slice(-27) : file.name;
        setDeployProgress(`Uploading ${i + 1} / ${pendingFiles.length} — ${label}`);

        const content_base64 = await fileToBase64(file);
        const rel  = (file as any).webkitRelativePath || file.name;
        const path = rel.includes('/') ? '/' + rel.split('/').slice(1).join('/') : '/' + rel;

        const result = await invoke<{ cid: string; size: number }>('deploy_site_file', {
          name: slug,
          file: { path, content_base64, mime_type: mimeForFile(file.name) },
        });
        entries.push({ path, cid: result.cid, mime_type: mimeForFile(file.name), size: result.size });
      }

      setDeployProgress('Publishing to network…');
      await invoke<HostedSite>('finalize_deploy', { name: slug, files: entries });
      await invoke('set_custom_domain', { name: slug, domain });

      setJustDeployed({ domain, name: slug });
      setDomainInput('');
      setPendingFiles([]);
      setPendingSize(0);
      load();
    } catch (e: any) {
      setError(String(e));
    } finally {
      setDeploying(false);
      setDeployProgress('');
    }
  }

  async function undeploy(site: HostedSite) {
    if (!confirm(`Remove "${site.custom_domain ?? site.name}"? This cannot be undone.`)) return;
    try {
      await invoke('undeploy_site', { name: site.name });
      if (justDeployed?.name === site.name) setJustDeployed(null);
      load();
    } catch (e: any) {
      setError(String(e));
    }
  }

  function copyUrl(url: string) {
    navigator.clipboard.writeText(url).catch(() => {});
    setCopiedUrl(url);
    setTimeout(() => setCopiedUrl(''), 2000);
  }

  return (
    <div className="p-6 space-y-5 max-w-2xl mx-auto">

      <div>
        <h2 className="text-xl font-bold">Web Hosting</h2>
        <p className="text-sm text-gray-400 mt-1">
          Deploy any website to the Ego network. Bring your own domain — files are stored across Ego nodes, not any single server.
        </p>
      </div>

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
          <div
            className={`border-2 border-dashed rounded-xl transition-colors ${
              deploying ? 'border-blue-500/40 cursor-default' : 'border-gray-600 hover:border-blue-500/50 cursor-pointer'
            }`}
            onClick={() => !deploying && dirInputRef.current?.click()}
            onDragOver={e => e.preventDefault()}
            onDrop={e => { e.preventDefault(); if (!deploying && e.dataTransfer.files.length) stageFiles(e.dataTransfer.files); }}
          >
            <input ref={dirInputRef} type="file" className="hidden" onChange={handleFileInput} />
            <input ref={fileInputRef} type="file" className="hidden" multiple onChange={handleFileInput} />

            {deploying ? (
              <div className="py-8 text-center space-y-3">
                <div className="text-2xl animate-pulse">🚀</div>
                <div className="text-sm text-blue-400 font-medium">{deployProgress}</div>
                <div className="w-48 mx-auto bg-gray-700 rounded-full h-1">
                  <div className="bg-blue-500 h-1 rounded-full animate-pulse w-full" />
                </div>
              </div>
            ) : pendingFiles.length > 0 ? (
              <div className="py-5 px-4 text-center">
                <div className="text-green-400 font-semibold text-sm mb-1">
                  {pendingFiles.length} file{pendingFiles.length !== 1 ? 's' : ''} · {fmtBytes(pendingSize)}
                </div>
                <div className="text-xs text-gray-500 space-y-0.5 max-h-20 overflow-hidden">
                  {pendingFiles.slice(0, 5).map((f, i) => {
                    const rel  = (f as any).webkitRelativePath || f.name;
                    const path = rel.includes('/') ? rel.split('/').slice(1).join('/') : rel;
                    return <div key={i} className="font-mono truncate">{path}</div>;
                  })}
                  {pendingFiles.length > 5 && <div className="text-gray-600">+{pendingFiles.length - 5} more files</div>}
                </div>
                <button
                  className="mt-2 text-xs text-gray-500 underline"
                  onClick={e => { e.stopPropagation(); setPendingFiles([]); setPendingSize(0); }}
                >
                  Change folder
                </button>
              </div>
            ) : (
              <div className="py-10 text-center">
                <div className="text-4xl mb-3">📂</div>
                <div className="text-sm text-gray-300 font-medium">Drop your website folder here</div>
                <div className="text-xs text-gray-500 mt-1">HTML, CSS, JS, images — up to 2 GB</div>
                <button
                  className="mt-3 text-xs text-blue-400 underline"
                  onClick={e => { e.stopPropagation(); fileInputRef.current?.click(); }}
                >
                  or select individual files
                </button>
              </div>
            )}
          </div>
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
            : !isValidDomain
              ? 'Enter your domain to continue'
              : pendingFiles.length === 0
                ? 'Add your website folder'
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
                        <div className="text-sm font-semibold font-mono truncate">{displayDomain}</div>
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
                          onClick={() => shellOpen(site.local_url)}
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
                        {site.custom_domain && (
                          <NsCard domain={site.custom_domain} />
                        )}
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
    </div>
  );
};

export default HostingPage;
