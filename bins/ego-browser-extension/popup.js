const DEFAULT_NODES = ["http://localhost:47395"];

let nodes = [];

async function loadNodes() {
  return new Promise(resolve => {
    chrome.storage.sync.get({ nodes: DEFAULT_NODES }, r => {
      nodes = r.nodes && r.nodes.length > 0 ? r.nodes : DEFAULT_NODES;
      resolve(nodes);
    });
  });
}

async function saveNodes() {
  await chrome.storage.sync.set({ nodes });
}

function renderNodes() {
  const list = document.getElementById("nodeList");
  list.innerHTML = "";
  nodes.forEach((url, i) => {
    const item = document.createElement("div");
    item.className = "node-item";

    const dot = document.createElement("div");
    dot.className = "dot";
    dot.id = `dot-${i}`;

    const label = document.createElement("div");
    label.className = "node-url";
    label.textContent = url;
    label.title = url;

    const syncBtn = document.createElement("button");
    syncBtn.className = "btn-sm btn-sync";
    syncBtn.textContent = "Sync peers";
    syncBtn.onclick = () => syncPeers(url, i);

    const removeBtn = document.createElement("button");
    removeBtn.className = "btn-sm btn-remove";
    removeBtn.textContent = "×";
    removeBtn.onclick = () => removeNode(i);

    item.appendChild(dot);
    item.appendChild(label);
    if (url !== "http://localhost:47395") item.appendChild(removeBtn);
    item.appendChild(syncBtn);
    list.appendChild(item);

    checkNode(url, i);
  });
}

function checkNode(url, index) {
  chrome.runtime.sendMessage({ type: "check_node", url }, (resp) => {
    const dot = document.getElementById(`dot-${index}`);
    if (dot) {
      dot.className = "dot " + ((resp && resp.online) ? "online" : "offline");
    }
  });
}

function syncPeers(nodeUrl, index) {
  chrome.runtime.sendMessage({ type: "fetch_nodes_from", url: nodeUrl }, (resp) => {
    if (resp && resp.added > 0) {
      loadNodes().then(renderNodes);
    }
  });
}

function removeNode(index) {
  if (nodes[index] === "http://localhost:47395") return;
  nodes.splice(index, 1);
  saveNodes().then(renderNodes);
}

document.addEventListener("DOMContentLoaded", async () => {
  await loadNodes();
  renderNodes();

  document.getElementById("goBtn").addEventListener("click", openSite);
  document.getElementById("siteInput").addEventListener("keydown", e => {
    if (e.key === "Enter") openSite();
  });

  document.getElementById("addBtn").addEventListener("click", addNode);
  document.getElementById("nodeInput").addEventListener("keydown", e => {
    if (e.key === "Enter") addNode();
  });
});

function openSite() {
  let raw = document.getElementById("siteInput").value.trim().toLowerCase();
  if (!raw) return;
  raw = raw.replace(/^https?:\/\//, "").replace(/\.ego$/, "").replace(/\.eo$/, "").replace(/^www\./, "");
  if (!raw) return;
  chrome.runtime.sendMessage({ type: "check_node", url: nodes[0] }, resp => {
    const node = (resp && resp.online) ? nodes[0] : nodes[1] || nodes[0];
    chrome.tabs.create({ url: `${node}/site/${raw}` });
  });
}

async function addNode() {
  let url = document.getElementById("nodeInput").value.trim();
  if (!url) return;
  if (!url.startsWith("http")) url = "http://" + url;
  url = url.replace(/\/$/, "");
  if (!nodes.includes(url)) {
    nodes.push(url);
    await saveNodes();
    document.getElementById("nodeInput").value = "";
    renderNodes();
  }
}
