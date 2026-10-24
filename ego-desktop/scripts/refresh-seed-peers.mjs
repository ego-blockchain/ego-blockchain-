import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.join(here, "..", "src-tauri", "seed_peers.txt");
const relay = "/dns4/egorelay.egoblockchain.com/tcp/4001/p2p/12D3KooWFFjZdk4nhpsXKxa44eUsggQ9rAzELeVv34Eav8qA5t9y/p2p-circuit/p2p/";
const maxSeeds = 48;
const maxAgeSecs = 7 * 86400;

const appData = process.env.APPDATA || path.join(os.homedir(), ".config");
const cachePath = process.argv[2] || path.join(appData, "EgoDesktop", "peers.json");

const targets = new Map();
const add = (endpoint, seen) => {
  if (typeof endpoint !== "string" || !endpoint.startsWith(relay)) return;
  const id = endpoint.slice(relay.length).split("/")[0];
  if (!/^12D3KooW[1-9A-HJ-NP-Za-km-z]{44}$/.test(id)) return;
  const prev = targets.get(id);
  if (!prev || prev.seen < seen) targets.set(id, { endpoint: relay + id, seen });
};

const now = Math.floor(Date.now() / 1000);
try {
  const res = await fetch("https://rpc.egoblockchain.com/nodes");
  const body = await res.json();
  for (const ep of body.nodes || []) add(ep, now);
} catch (e) {
  console.warn(`node list unavailable: ${e.message}`);
}
try {
  for (const p of JSON.parse(fs.readFileSync(cachePath, "utf8"))) {
    if (now - (p.last_seen || 0) <= maxAgeSecs) add(p.endpoint, p.last_seen || 0);
  }
} catch (e) {
  console.warn(`peer cache unavailable at ${cachePath}: ${e.message}`);
}

const lines = [...targets.values()]
  .sort((a, b) => b.seen - a.seen)
  .slice(0, maxSeeds)
  .map((t) => t.endpoint);
if (lines.length === 0) {
  console.error("no seed peers found, seed_peers.txt left unchanged");
  process.exit(1);
}
fs.writeFileSync(out, lines.join("\n") + "\n");
console.log(`wrote ${lines.length} seed peers to ${out}`);
