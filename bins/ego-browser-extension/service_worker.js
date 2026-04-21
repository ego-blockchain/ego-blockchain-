const DEFAULT_NODES = ["http://localhost:47395"];

async function getNodes() {
  return new Promise(resolve => {
    chrome.storage.sync.get({ nodes: DEFAULT_NODES }, r => {
      resolve((r.nodes && r.nodes.length > 0) ? r.nodes : DEFAULT_NODES);
    });
  });
}

async function tryResolve(nodeUrl, siteName) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3000);
  try {
    const resp = await fetch(`${nodeUrl}/resolve/${siteName}`, { signal: controller.signal });
    clearTimeout(timer);
    if (resp.ok) return nodeUrl;
  } catch (_) {
    clearTimeout(timer);
  }
  return null;
}

function parseSiteName(host) {
  if (host.endsWith(".ego")) return host.slice(0, -4).replace(/^www\./, "");
  if (host.endsWith(".eo"))  return host.slice(0, -3).replace(/^www\./, "");
  return null;
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  try {
    const url = new URL(details.url);
    const host = url.hostname;
    const siteName = parseSiteName(host);
    if (!siteName) return;

    const nodes = await getNodes();

    for (const node of nodes) {
      const found = await tryResolve(node, siteName);
      if (found) {
        const path = url.pathname === "/" ? "" : url.pathname;
        const redirect = `${found}/site/${siteName}${path}${url.search}`;
        chrome.tabs.update(details.tabId, { url: redirect });
        await cacheWorkingNode(node);
        return;
      }
    }

    chrome.tabs.update(details.tabId, {
      url: `chrome-extension://${chrome.runtime.id}/not-found.html?site=${encodeURIComponent(siteName)}`,
    });
  } catch (_) {}
}, { url: [{ hostSuffix: ".ego" }, { hostSuffix: ".eo" }] });

async function cacheWorkingNode(nodeUrl) {
  const { nodeCache = {} } = await chrome.storage.local.get("nodeCache");
  nodeCache[nodeUrl] = Date.now();
  await chrome.storage.local.set({ nodeCache });
}

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  if (msg.type === "check_node") {
    tryResolve(msg.url, "_health_check").then(ok => {
      reply({ online: ok !== null });
    });
    return true;
  }
  if (msg.type === "fetch_nodes_from") {
    fetch(`${msg.url}/nodes`, { signal: AbortSignal.timeout ? AbortSignal.timeout(3000) : undefined })
      .then(r => r.json())
      .then(data => {
        const urls = data.nodes || [];
        chrome.storage.sync.get({ nodes: DEFAULT_NODES }, ({ nodes }) => {
          const merged = [...new Set([...nodes, ...urls])];
          chrome.storage.sync.set({ nodes: merged });
          reply({ added: urls.length });
        });
      })
      .catch(() => reply({ added: 0 }));
    return true;
  }
});
