import React, { useState, useEffect, useRef, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import Pagination from '../components/Pagination';
import { useWallet } from '../App';
import { decodeLandDots, decodeBorders, DOT_LAT_TOP, DOT_LAT_BOTTOM } from '../components/landDots';

interface Location {
  latitude: number;
  longitude: number;
  accuracy?: number;
  altitude?: number;
  city?: string;
  region?: string;
  country?: string;
}

interface CoverageStatus {
  location?: Location;
  coverage_synced_count: number;
  last_coverage_event?: number;
  is_online: boolean;
  network_quality: string;
  vpn_detected: boolean;
  vpn_reason: string;
  machine_id: string;
}

interface PeerInfo {
  address:   string;
  name:      string;
  endpoint:  string;
  last_seen: number;
  city?:    string;
  country?: string;
  lat?:     number | null;
  lon?:     number | null;
}

interface PocEvent {
  id: number;
  timestamp: number;
  quality: string;
  peers: number;
  reward_uegoc: number;
  h3_cell?: string;
}

interface P2pStatus {
  public_endpoint: string;
}

function extractPeerId(endpoint: string): string {
  const safeEndpoint = endpoint || ''; // Ensure endpoint is a string, even if it's null/undefined
  const m = safeEndpoint.match(/\/p2p\/([A-Za-z0-9]+)$/);
  return m ? m[1] : safeEndpoint;
}

function shortPeerId(id: string): string {
  if (id.length <= 16) return id;
  return id.slice(0, 8) + '…' + id.slice(-6);
}

function timeAgo(ts: number) {
  const diff = Math.floor(Date.now() / 1000 - ts);
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

function qualityBadge(q: string) {
  if (q === 'Excellent') return 'text-green-400 bg-green-500/15';
  if (q === 'Good')      return 'text-blue-400 bg-blue-500/15';
  if (q === 'Fair')      return 'text-yellow-400 bg-yellow-500/15';
  return 'text-red-400 bg-red-500/15';
}

function fmtCoord(lat: number, lon: number): string {
  const latDir = lat >= 0 ? 'N' : 'S';
  const lonDir = lon >= 0 ? 'E' : 'W';
  return `${Math.abs(lat).toFixed(4)}°${latDir}, ${Math.abs(lon).toFixed(4)}°${lonDir}`;
}

function deriveH3Cell(lat: number, lon: number): string {
  const a = Math.abs(Math.round(lat * 1000));
  const b = Math.abs(Math.round(lon * 1000));
  const n = (a * 180000 + b) >>> 0;
  return `892${n.toString(16).padStart(9, '0').slice(-9)}ff`;
}

function locationLabel(loc: Location): string {
  const parts = [loc.city, loc.region, loc.country].filter(Boolean);
  return parts.length > 0 ? parts.join(', ') : 'Unknown';
}

const COUNTRY_COORDS: Record<string, [number, number]> = {
  'United States': [37.1, -95.7], 'Canada': [56.1, -106.3], 'Mexico': [23.6, -102.6],
  'Brazil': [-14.2, -51.9], 'Argentina': [-38.4, -63.6], 'Colombia': [4.6, -74.3],
  'Chile': [-35.7, -71.5], 'Peru': [-9.2, -75.0], 'Venezuela': [6.4, -66.6],
  'United Kingdom': [55.4, -3.4], 'Germany': [51.2, 10.5], 'France': [46.2, 2.2],
  'Spain': [40.5, -3.7], 'Italy': [41.9, 12.6], 'Netherlands': [52.1, 5.3],
  'Sweden': [60.1, 18.6], 'Norway': [60.5, 8.5], 'Denmark': [56.3, 9.5],
  'Finland': [61.9, 25.7], 'Switzerland': [46.8, 8.2], 'Austria': [47.5, 14.6],
  'Belgium': [50.5, 4.5], 'Poland': [51.9, 19.1], 'Portugal': [39.4, -8.2],
  'Czech Republic': [49.8, 15.5], 'Hungary': [47.2, 19.5], 'Romania': [45.9, 25.0],
  'Greece': [39.1, 21.8], 'Ukraine': [48.4, 31.2], 'Ireland': [53.4, -8.2],
  'Iceland': [65.0, -19.0], 'Russia': [61.5, 105.3], 'Turkey': [39.0, 35.2],
  'China': [35.9, 104.2], 'Japan': [36.2, 138.3], 'South Korea': [35.9, 127.8],
  'India': [20.6, 79.0], 'Pakistan': [30.4, 69.4], 'Bangladesh': [23.7, 90.4],
  'Vietnam': [14.1, 108.3], 'Thailand': [15.9, 101.0], 'Indonesia': [-0.8, 113.9],
  'Malaysia': [4.2, 109.0], 'Philippines': [12.9, 121.8], 'Singapore': [1.4, 103.8],
  'Taiwan': [23.7, 121.0], 'Hong Kong': [22.4, 114.1], 'Myanmar': [19.2, 96.0],
  'Cambodia': [12.6, 105.0], 'Australia': [-25.3, 133.8], 'New Zealand': [-40.9, 174.9],
  'South Africa': [-30.6, 22.9], 'Nigeria': [9.1, 8.7], 'Kenya': [-0.0, 37.9],
  'Egypt': [26.8, 30.8], 'Ethiopia': [9.1, 40.5], 'Ghana': [7.9, -1.0],
  'UAE': [23.4, 53.8], 'Saudi Arabia': [23.9, 45.1], 'Israel': [31.1, 34.9],
  'Iran': [32.4, 53.7], 'Iraq': [33.2, 43.7], 'Kazakhstan': [48.0, 66.9],
  'Luxembourg': [49.8, 6.1], 'Slovakia': [48.7, 19.7], 'Bulgaria': [42.7, 25.5],
  'Croatia': [45.1, 15.2], 'Serbia': [44.0, 21.0], 'Lithuania': [55.2, 23.9],
  'Latvia': [56.9, 24.6], 'Estonia': [58.6, 25.0], 'Slovenia': [46.2, 15.0],
};

const CITY_COORDS: Record<string, [number, number]> = {
  'New York': [40.7, -74.0], 'Los Angeles': [34.1, -118.2], 'Chicago': [41.9, -87.6],
  'Houston': [29.8, -95.4], 'London': [51.5, -0.1], 'Paris': [48.9, 2.3],
  'Berlin': [52.5, 13.4], 'Amsterdam': [52.4, 4.9], 'Frankfurt': [50.1, 8.7],
  'Tokyo': [35.7, 139.7], 'Beijing': [39.9, 116.4], 'Shanghai': [31.2, 121.5],
  'Seoul': [37.6, 127.0], 'Singapore': [1.3, 103.8], 'Mumbai': [19.1, 72.9],
  'Sydney': [-33.9, 151.2], 'Melbourne': [-37.8, 145.0], 'Toronto': [43.7, -79.4],
  'Vancouver': [49.3, -123.1], 'Montreal': [45.5, -73.6], 'São Paulo': [-23.5, -46.6],
  'Buenos Aires': [-34.6, -58.4], 'Dubai': [25.2, 55.3], 'Moscow': [55.8, 37.6],
  'Stockholm': [59.3, 18.1], 'Zurich': [47.4, 8.5], 'Vienna': [48.2, 16.4],
  'Warsaw': [52.2, 21.0], 'Madrid': [40.4, -3.7], 'Rome': [41.9, 12.5],
  'Istanbul': [41.0, 29.0], 'Taipei': [25.0, 121.5], 'Hong Kong': [22.3, 114.2],
  'Bangkok': [13.8, 100.5], 'Jakarta': [-6.2, 106.8], 'Kuala Lumpur': [3.1, 101.7],
};

interface MapNode {
  id: string;
  lat: number;
  lon: number;
  label: string;
  isMe: boolean;
}

function resolveCoords(city?: string, country?: string): [number, number] | null {
  if (city) {
    for (const [k, v] of Object.entries(CITY_COORDS)) {
      if (city.toLowerCase().includes(k.toLowerCase())) return v;
    }
  }
  if (country) {
    for (const [k, v] of Object.entries(COUNTRY_COORDS)) {
      if (country.toLowerCase().includes(k.toLowerCase())) return v;
    }
  }
  return null;
}

const LAND_DOTS = decodeLandDots();
const BORDER_LINES = decodeBorders();

interface Cluster {
  x: number;
  y: number;
  count: number;
  hasMe: boolean;
  label: string;
  id: string;
  r: number;
}

interface TooltipState { x: number; y: number; cluster: Cluster }

const WorldNetworkMap: React.FC<{ myNode: MapNode | null; peers: MapNode[] }> = ({ myNode, peers }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const vsRef     = useRef({ scale: 1, ox: 0, oy: 0, drag: false, lx: 0, ly: 0, moved: false });
  const frameRef  = useRef(0);
  const baseRef   = useRef<{ canvas: HTMLCanvasElement; key: string } | null>(null);
  const [tooltip, setTooltip] = useState<TooltipState | null>(null);
  const nodesRef  = useRef<MapNode[]>([]);
  const clustersRef = useRef<Cluster[]>([]);

  const allNodes = myNode ? [myNode, ...peers] : peers;
  nodesRef.current = allNodes;

  const project = useCallback((lon: number, lat: number, w: number, h: number): [number,number] => {
    const vs = vsRef.current;
    return [
      ((lon + 180) / 360) * w * vs.scale + vs.ox,
      ((DOT_LAT_TOP - lat) / (DOT_LAT_TOP - DOT_LAT_BOTTOM)) * h * vs.scale + vs.oy,
    ];
  }, []);

  const zoomAt = useCallback((cx: number, cy: number, factor: number) => {
    const v  = vsRef.current;
    const ns = Math.max(0.5, Math.min(2000, v.scale * factor));
    const sf = ns / v.scale;
    v.ox = cx - sf * (cx - v.ox);
    v.oy = cy - sf * (cy - v.oy);
    v.scale = ns;
  }, []);

  const zoomCenter = useCallback((factor: number) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    zoomAt(rect.width / 2, rect.height / 2, factor);
  }, [zoomAt]);

  const resetView = useCallback(() => {
    const v = vsRef.current;
    v.scale = 1; v.ox = 0; v.oy = 0;
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let dpr = window.devicePixelRatio || 1;
    const resize = () => {
      dpr = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();
      canvas.width  = rect.width  * dpr;
      canvas.height = rect.height * dpr;
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);

    const renderBase = (w: number, h: number): HTMLCanvasElement => {
      const vs  = vsRef.current;
      const key = `${vs.scale.toFixed(4)}|${vs.ox.toFixed(1)}|${vs.oy.toFixed(1)}|${w}|${h}|${dpr}`;
      if (baseRef.current?.key === key) return baseRef.current.canvas;

      let off = baseRef.current?.canvas;
      if (!off) off = document.createElement('canvas');
      off.width  = w * dpr;
      off.height = h * dpr;
      const bctx = off.getContext('2d')!;
      bctx.save();
      bctx.scale(dpr, dpr);

      const grad = bctx.createRadialGradient(w / 2, h / 2, 40, w / 2, h / 2, Math.max(w, h) * 0.75);
      grad.addColorStop(0, '#0b1224');
      grad.addColorStop(1, '#04060d');
      bctx.fillStyle = grad;
      bctx.fillRect(0, 0, w, h);

      bctx.strokeStyle = 'rgba(120,150,255,0.035)';
      bctx.lineWidth = 0.5;
      for (let lon = -180; lon <= 180; lon += 30) {
        const [x] = project(lon, 0, w, h);
        bctx.beginPath(); bctx.moveTo(x, 0); bctx.lineTo(x, h); bctx.stroke();
      }
      for (let lat = -45; lat <= 75; lat += 30) {
        const [, y] = project(0, lat, w, h);
        bctx.beginPath(); bctx.moveTo(0, y); bctx.lineTo(w, y); bctx.stroke();
      }

      const r = Math.min(3.2, Math.max(0.9, 1.15 * Math.sqrt(vs.scale)));
      bctx.fillStyle = '#2c3a63';
      bctx.beginPath();
      for (let i = 0; i < LAND_DOTS.length; i += 2) {
        const [x, y] = project(LAND_DOTS[i], LAND_DOTS[i + 1], w, h);
        if (x < -4 || x > w + 4 || y < -4 || y > h + 4) continue;
        bctx.moveTo(x + r, y);
        bctx.arc(x, y, r, 0, Math.PI * 2);
      }
      bctx.fill();

      bctx.strokeStyle = `rgba(130,160,235,${Math.min(0.34, 0.16 + vs.scale * 0.05)})`;
      bctx.lineWidth = Math.min(1.1, 0.55 + vs.scale * 0.08);
      bctx.beginPath();
      for (const line of BORDER_LINES) {
        let started = false;
        for (let i = 0; i < line.length; i += 2) {
          const [x, y] = project(line[i], line[i + 1], w, h);
          if (!started) { bctx.moveTo(x, y); started = true; }
          else bctx.lineTo(x, y);
        }
      }
      bctx.stroke();

      if (vs.scale >= 1.8) {
        const showLabels = vs.scale >= 2.6;
        bctx.font = '9px sans-serif';
        for (const [name, [lat, lon]] of Object.entries(CITY_COORDS)) {
          const [x, y] = project(lon, lat, w, h);
          if (x < -10 || x > w + 10 || y < -10 || y > h + 10) continue;
          bctx.fillStyle = 'rgba(150,170,220,0.8)';
          bctx.beginPath();
          bctx.arc(x, y, 1.6, 0, Math.PI * 2);
          bctx.fill();
          if (showLabels) {
            bctx.fillStyle = 'rgba(160,180,225,0.6)';
            bctx.fillText(name, x + 5, y + 3);
          }
        }
      }

      bctx.restore();
      baseRef.current = { canvas: off, key };
      return off;
    };

    const drawNodeMarker = (
      c: CanvasRenderingContext2D, x: number, y: number, t: number,
      color: [number, number, number], phase: number, big: boolean,
    ) => {
      const [cr, cg, cb] = color;
      const rgba = (a: number) => `rgba(${cr},${cg},${cb},${a})`;

      const glowR = big ? 26 : 18;
      const glow  = c.createRadialGradient(x, y, 1, x, y, glowR);
      glow.addColorStop(0, rgba(0.30));
      glow.addColorStop(1, rgba(0));
      c.fillStyle = glow;
      c.beginPath(); c.arc(x, y, glowR, 0, Math.PI * 2); c.fill();

      const rings = big ? 2 : 1;
      for (let k = 0; k < rings; k++) {
        const u = ((t * 0.55 + phase + k * 0.5) % 1);
        const ringR  = 5 + u * (big ? 22 : 15);
        c.strokeStyle = rgba(0.55 * (1 - u));
        c.lineWidth   = 1.4;
        c.beginPath(); c.arc(x, y, ringR, 0, Math.PI * 2); c.stroke();
      }

      c.fillStyle = rgba(1);
      c.beginPath(); c.arc(x, y, big ? 5 : 4, 0, Math.PI * 2); c.fill();
      c.fillStyle = '#ffffff';
      c.beginPath(); c.arc(x, y, big ? 2 : 1.6, 0, Math.PI * 2); c.fill();
      c.strokeStyle = rgba(0.9);
      c.lineWidth = 1;
      c.beginPath(); c.arc(x, y, big ? 7.5 : 6, 0, Math.PI * 2); c.stroke();
    };

    const draw = (ts: number) => {
      const t    = ts / 1000;
      const rect = canvas.getBoundingClientRect();
      const w    = rect.width;
      const h    = rect.height;
      const vs   = vsRef.current;

      ctx.save();
      ctx.scale(dpr, dpr);
      ctx.clearRect(0, 0, w, h);
      ctx.drawImage(renderBase(w, h), 0, 0, w, h);

      const nodes = nodesRef.current;

      const CELL = 34;
      const cellMap = new Map<string, { sx: number; sy: number; count: number; hasMe: boolean; label: string; id: string }>();
      for (const node of nodes) {
        const [px, py] = project(node.lon, node.lat, w, h);
        if (px < -60 || px > w + 60 || py < -60 || py > h + 60) continue;
        const key = `${Math.round(px / CELL)},${Math.round(py / CELL)}`;
        const c = cellMap.get(key);
        if (c) {
          c.sx += px; c.sy += py; c.count++;
          c.hasMe = c.hasMe || node.isMe;
        } else {
          cellMap.set(key, { sx: px, sy: py, count: 1, hasMe: node.isMe, label: node.label, id: node.id });
        }
      }
      const clusters: Cluster[] = [];
      for (const c of cellMap.values()) {
        clusters.push({
          x: c.sx / c.count,
          y: c.sy / c.count,
          count: c.count,
          hasMe: c.hasMe,
          label: c.label,
          id: c.id,
          r: c.count === 1 ? 13 : Math.min(26, 12 + Math.log2(c.count) * 3),
        });
      }
      clustersRef.current = clusters;

      const meCluster = clusters.find(c => c.hasMe);

      if (meCluster) {
        const { x: mx, y: my } = meCluster;
        let ai = 0;
        for (const c of clusters) {
          if (c.hasMe || ai >= 60) continue;
          const dx = c.x - mx, dy = c.y - my;
          if (Math.hypot(dx, dy) < 10) continue;
          const cpx = (mx + c.x) / 2 - dy * 0.18;
          const cpy = (my + c.y) / 2 + dx * 0.18;

          const lg = ctx.createLinearGradient(mx, my, c.x, c.y);
          lg.addColorStop(0, 'rgba(56,189,248,0.45)');
          lg.addColorStop(1, 'rgba(248,113,113,0.35)');
          ctx.strokeStyle = lg;
          ctx.lineWidth = 1.1;
          ctx.beginPath();
          ctx.moveTo(mx, my);
          ctx.quadraticCurveTo(cpx, cpy, c.x, c.y);
          ctx.stroke();

          const u  = (t * 0.30 + ai * 0.37) % 1;
          const iu = 1 - u;
          const qx = iu * iu * mx + 2 * iu * u * cpx + u * u * c.x;
          const qy = iu * iu * my + 2 * iu * u * cpy + u * u * c.y;
          const pg = ctx.createRadialGradient(qx, qy, 0, qx, qy, 5);
          pg.addColorStop(0, 'rgba(255,255,255,0.95)');
          pg.addColorStop(1, 'rgba(125,211,252,0)');
          ctx.fillStyle = pg;
          ctx.beginPath(); ctx.arc(qx, qy, 5, 0, Math.PI * 2); ctx.fill();
          ai++;
        }
      }

      let pi = 0;
      for (const c of clusters) {
        if (c.hasMe) continue;
        if (c.count === 1) {
          drawNodeMarker(ctx, c.x, c.y, t, [248, 113, 113], pi * 0.23, false);
          if (vs.scale >= 1.8 && c.label && c.label !== '—') {
            ctx.font = '10px sans-serif';
            ctx.fillStyle = 'rgba(252,165,165,0.85)';
            ctx.fillText(c.label, c.x + 10, c.y + 3);
          }
        } else {
          const glow = ctx.createRadialGradient(c.x, c.y, 2, c.x, c.y, c.r + 10);
          glow.addColorStop(0, 'rgba(248,113,113,0.35)');
          glow.addColorStop(1, 'rgba(248,113,113,0)');
          ctx.fillStyle = glow;
          ctx.beginPath(); ctx.arc(c.x, c.y, c.r + 10, 0, Math.PI * 2); ctx.fill();

          ctx.fillStyle = 'rgba(127,29,29,0.85)';
          ctx.beginPath(); ctx.arc(c.x, c.y, c.r, 0, Math.PI * 2); ctx.fill();
          ctx.strokeStyle = 'rgba(248,113,113,0.9)';
          ctx.lineWidth = 1.6;
          ctx.beginPath(); ctx.arc(c.x, c.y, c.r, 0, Math.PI * 2); ctx.stroke();

          const u = ((t * 0.5 + pi * 0.31) % 1);
          ctx.strokeStyle = `rgba(248,113,113,${0.5 * (1 - u)})`;
          ctx.lineWidth = 1.2;
          ctx.beginPath(); ctx.arc(c.x, c.y, c.r + u * 14, 0, Math.PI * 2); ctx.stroke();

          ctx.fillStyle = '#fecaca';
          ctx.font = `bold ${c.count > 999 ? 10 : 11}px sans-serif`;
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillText(c.count > 9999 ? `${Math.round(c.count / 1000)}k` : String(c.count), c.x, c.y + 0.5);
          ctx.textAlign = 'start';
          ctx.textBaseline = 'alphabetic';
        }
        pi++;
      }

      if (meCluster) {
        const { x: mx, y: my } = meCluster;
        drawNodeMarker(ctx, mx, my, t, [56, 189, 248], 0, true);

        const label = meCluster.count > 1 ? `YOU +${meCluster.count - 1}` : 'YOU';
        ctx.font = 'bold 10px sans-serif';
        const tw = ctx.measureText(label).width;
        const bx = mx + 11, by = my - 19;
        ctx.fillStyle = 'rgba(8,18,34,0.85)';
        ctx.strokeStyle = 'rgba(56,189,248,0.5)';
        ctx.lineWidth = 1;
        ctx.beginPath();
        (ctx as any).roundRect ? (ctx as any).roundRect(bx, by, tw + 12, 16, 5) : ctx.rect(bx, by, tw + 12, 16);
        ctx.fill(); ctx.stroke();
        ctx.fillStyle = '#7dd3fc';
        ctx.fillText(label, bx + 6, by + 11.5);
      }

      ctx.restore();
      frameRef.current = requestAnimationFrame(draw);
    };

    frameRef.current = requestAnimationFrame(draw);

    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const rect = canvas.getBoundingClientRect();
      zoomAt(e.clientX - rect.left, e.clientY - rect.top, e.deltaY > 0 ? 0.82 : 1.22);
    };
    canvas.addEventListener('wheel', onWheel, { passive: false });

    return () => { cancelAnimationFrame(frameRef.current); ro.disconnect(); canvas.removeEventListener('wheel', onWheel); };
  }, [project, zoomAt]);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    vsRef.current.drag = true; vsRef.current.moved = false;
    vsRef.current.lx = e.clientX; vsRef.current.ly = e.clientY;
    setTooltip(null);
  }, []);

  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const vs = vsRef.current;
    if (vs.drag) {
      if (Math.abs(e.clientX - vs.lx) + Math.abs(e.clientY - vs.ly) > 2) vs.moved = true;
      vs.ox += e.clientX - vs.lx; vs.oy += e.clientY - vs.ly;
      vs.lx  = e.clientX;          vs.ly  = e.clientY;
      setTooltip(null); return;
    }
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    let found: Cluster | null = null;
    for (const c of clustersRef.current) {
      if (Math.hypot(c.x - mx, c.y - my) < Math.max(13, c.r + 2)) { found = c; break; }
    }
    setTooltip(found ? { x: mx, y: my, cluster: found } : null);
  }, []);

  const handleMouseUp = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const vs = vsRef.current;
    const wasDrag = vs.drag && vs.moved;
    vs.drag = false;
    if (wasDrag) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    for (const c of clustersRef.current) {
      if (c.count > 1 && Math.hypot(c.x - mx, c.y - my) < c.r + 2) {
        zoomAt(c.x, c.y, 2.6);
        setTooltip(null);
        return;
      }
    }
  }, [zoomAt]);

  const handleMouseLeave = useCallback(() => { vsRef.current.drag = false; setTooltip(null); }, []);

  return (
    <div className="relative w-full" style={{ height: 420 }}>
      <canvas
        ref={canvasRef}
        className="w-full h-full rounded-xl cursor-grab active:cursor-grabbing select-none"
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseLeave}
        style={{ display: 'block', width: '100%', height: '100%' }}
      />
      <div className="absolute top-3 right-3 flex flex-col gap-1.5">
        {[
          { label: '+', title: 'Zoom in',  fn: () => zoomCenter(1.45) },
          { label: '−', title: 'Zoom out', fn: () => zoomCenter(0.69) },
          { label: '⌖', title: 'Reset view', fn: resetView },
        ].map(b => (
          <button
            key={b.label}
            title={b.title}
            onClick={b.fn}
            className="w-7 h-7 rounded-lg bg-gray-900/80 border border-gray-600/50 text-gray-300 text-sm font-bold
                       hover:bg-gray-700/80 hover:text-white hover:border-gray-500 transition-colors backdrop-blur-sm
                       flex items-center justify-center leading-none"
          >
            {b.label}
          </button>
        ))}
      </div>
      <div className="absolute bottom-2 right-2 flex gap-3 text-xs text-gray-400 bg-black/50 backdrop-blur-sm rounded-lg px-3 py-1.5 border border-gray-700/40">
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-sky-400 inline-block"/>You</span>
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-red-400 inline-block"/>Peers</span>
        <span className="text-gray-600 hidden sm:inline">Scroll=zoom · Drag=pan</span>
      </div>
      {tooltip && (
        <div
          className="absolute pointer-events-none bg-gray-900/95 border border-gray-600 rounded-lg px-3 py-2 text-xs shadow-xl backdrop-blur-sm"
          style={{ left: Math.min(tooltip.x + 14, 320), top: tooltip.y - 14, zIndex: 20 }}
        >
          <div className={`font-bold mb-1 ${tooltip.cluster.hasMe ? 'text-sky-300' : 'text-red-300'}`}>
            {tooltip.cluster.count > 1
              ? `◉ ${tooltip.cluster.count} nodes${tooltip.cluster.hasMe ? ' (incl. you)' : ''}`
              : tooltip.cluster.hasMe ? '◉ Your Node' : '● Peer Node'}
          </div>
          <div className="text-gray-200">{tooltip.cluster.label}</div>
          {tooltip.cluster.count > 1 ? (
            <div className="text-gray-500 mt-0.5 text-[10px]">Click to zoom in</div>
          ) : !tooltip.cluster.hasMe && (
            <div className="text-gray-500 font-mono mt-0.5 text-[10px]">{shortPeerId(tooltip.cluster.id)}</div>
          )}
        </div>
      )}
    </div>
  );
};

const CoveragePage: React.FC = () => {
  const { wallet } = useWallet();
  const [coverage,   setCoverage]   = useState<CoverageStatus | null>(null);
  const [events,     setEvents]     = useState<PocEvent[]>([]);
  const [peers,      setPeers]      = useState<PeerInfo[]>([]);
  const eventLogRef = useRef<HTMLDivElement>(null);
  const [p2pStatus,  setP2pStatus]  = useState<P2pStatus | null>(null);
  const [loading,    setLoading]    = useState(true);

  const withTimeout = <T,>(promise: Promise<T>, fallback: T, ms = 15_000): Promise<T> =>
    Promise.race([promise, new Promise<T>(resolve => setTimeout(() => resolve(fallback), ms))]);

  function fallbackCoverage(): CoverageStatus {
    const walletReady = Boolean(wallet?.address);
    return {
      coverage_synced_count: 0,
      is_online: walletReady,
      machine_id: '',
      network_quality: walletReady ? 'Fair' : 'Offline',
      vpn_detected: false,
      vpn_reason: '',
    };
  }

  function refreshCoverage() {
    withTimeout(invoke<CoverageStatus>('get_coverage_status'), fallbackCoverage())
      .then(setCoverage)
      .catch(() => setCoverage(fallbackCoverage()));
    withTimeout(invoke<PocEvent[]>('get_poc_events'), [])
      .then(setEvents)
      .catch(() => setEvents([]));
  }

  useEffect(() => {
    let active = true;

    async function loadInitial() {
      try {
        const [nextCoverage, nextEvents, nextPeers, nextP2p] = await Promise.all([
          withTimeout(invoke<CoverageStatus>('get_coverage_status'), fallbackCoverage()),
          withTimeout(invoke<PocEvent[]>('get_poc_events'), []),
          withTimeout(invoke<PeerInfo[]>('get_network_peers'), []),
          withTimeout(invoke<P2pStatus>('get_p2p_status'), { public_endpoint: '' }),
        ]);
        if (!active) return;
        setCoverage(nextCoverage);
        setEvents(nextEvents);
        setPeers(nextPeers);
        setP2pStatus(nextP2p.public_endpoint ? nextP2p : null);
      } finally {
        if (active) setLoading(false);
      }
    }

    void loadInitial();

    const unlistenCoverage = listen('ego://coverage-updated', refreshCoverage);
    const unlistenVpn      = listen('ego://vpn-status-changed', refreshCoverage);
    const tPeers = setInterval(() => {
      withTimeout(invoke<PeerInfo[]>('get_network_peers'), [])
        .then(setPeers)
        .catch(() => setPeers([]));
    }, 10_000);

    return () => {
      active = false;
      clearInterval(tPeers);
      unlistenCoverage.then(fn => fn());
      unlistenVpn.then(fn => fn());
    };
  }, [wallet?.address]);

  useEffect(() => {
    const el = eventLogRef.current;
    if (el) setTimeout(() => { el.scrollTop = el.scrollHeight; }, 0);
  }, [events]);

  const coverageState = coverage ?? fallbackCoverage();
  const quality   = coverageState.network_quality;
  const synced    = coverageState.coverage_synced_count ?? 0;
  const online    = coverageState.is_online;
  const vpn       = coverageState.vpn_detected ?? false;
  const vpnReason = coverageState.vpn_reason ?? '';
  const machineId = coverageState.machine_id ?? '';
  const loc       = coverageState.location;
  const h3Cell    = loc ? deriveH3Cell(loc.latitude, loc.longitude) : null;
  const coordStr  = loc ? fmtCoord(loc.latitude, loc.longitude) : null;
  const cityStr   = loc ? locationLabel(loc) : null;

  const myPeerId = p2pStatus?.public_endpoint
    ? extractPeerId(p2pStatus.public_endpoint)
    : '';

  const nowTs      = Math.floor(Date.now() / 1000);
  const todayStart = Math.floor(new Date().setHours(0, 0, 0, 0) / 1000);
  const events24h  = events.filter(e => e.timestamp >= nowTs - 86400);
  const todayRewardsUegoc = events
    .filter(e => e.timestamp >= todayStart)
    .reduce((sum, e) => sum + e.reward_uegoc, 0);
  const todayRewardsStr = online || todayRewardsUegoc > 0
    ? `${(todayRewardsUegoc / 1_000_000).toFixed(4)} EGOC`
    : '—';

  const mapNodes: MapNode[] = [];
  if (loc) {
    mapNodes.push({
      id: myPeerId || 'me',
      lat: loc.latitude,
      lon: loc.longitude,
      label: cityStr || 'My Node',
      isMe: true,
    });
  }

  const locCounts = new Map<string, number>();
  if (loc) locCounts.set(`${loc.latitude.toFixed(2)},${loc.longitude.toFixed(2)}`, 1);
  const seenPeers = new Set<string>();
  let peersNoLocation = 0;
  for (const peer of peers) {
    if (peer.address === wallet?.address) continue;
    const peerId = extractPeerId(peer.endpoint) || peer.address;
    if (seenPeers.has(peerId)) continue;
    seenPeers.add(peerId);

    const coords: [number, number] | null =
      (typeof peer.lat === 'number' && typeof peer.lon === 'number')
        ? [peer.lat, peer.lon]
        : resolveCoords(peer.city, peer.country);
    if (!coords) { peersNoLocation++; continue; }

    const key = `${coords[0].toFixed(2)},${coords[1].toFixed(2)}`;
    const n = locCounts.get(key) ?? 0;
    locCounts.set(key, n + 1);
    const angle  = n * 2.39996;
    const radius = 0.0045 * Math.sqrt(n);
    mapNodes.push({
      id: peerId,
      lat: coords[0] + Math.sin(angle) * radius,
      lon: coords[1] + Math.cos(angle) * radius,
      label: [peer.city, peer.country].filter(Boolean).join(', ') || peer.name || '—',
      isMe: false,
    });
  }

  const peersOnMap = mapNodes.filter(n => !n.isMe).length;

  return (
    <div className="p-6 space-y-5 max-w-4xl mx-auto">

      {vpn && (
        <div className="rounded-2xl p-4 border border-red-500/50 bg-red-500/10 flex items-start gap-3">
          <div className="text-2xl shrink-0">🚫</div>
          <div className="flex-1 min-w-0">
            <div className="font-bold text-red-400 text-sm">VPN / Proxy Detected — Coverage Paused</div>
            <div className="text-xs text-red-300/80 mt-0.5 leading-relaxed">
              Proof-of-Coverage rewards require a real residential or business IP address.
              VPNs, proxies, and datacenter IPs are not eligible and have been blocked to prevent location spoofing.
            </div>
            {vpnReason && (
              <div className="mt-2 text-xs font-mono text-red-400/70 bg-red-900/20 rounded-lg px-3 py-1.5 break-all">
                Reason: {vpnReason}
              </div>
            )}
            <div className="mt-2 text-xs text-red-300/60">
              Disable your VPN to resume earning. Your connection is re-checked every 5 minutes automatically.
            </div>
          </div>
        </div>
      )}

      <div className={`rounded-2xl p-5 border flex items-center justify-between ${
        online ? 'bg-green-500/10 border-green-500/30' : 'bg-red-500/10 border-red-500/30'
      }`}>
        <div className="flex items-center gap-4">
          <div className={`w-14 h-14 rounded-2xl flex items-center justify-center text-3xl ${
            online ? 'bg-green-500/20' : 'bg-red-500/20'
          }`}>📡</div>
          <div>
            <div className="text-lg font-bold">{online ? 'Coverage Active' : 'Coverage Offline'}</div>
            <div className="text-sm text-gray-400">
              PoC beacon · Quality: <span className={qualityBadge(quality).split(' ')[0]}>{quality}</span>
            </div>
            {!online && coverage?.vpn_detected && coverage.vpn_reason && (
              <div className="text-xs text-red-400 mt-1">VPN/proxy detected: {coverage.vpn_reason}</div>
            )}
            {!online && !coverage?.vpn_detected && (
              <div className="text-xs text-yellow-400 mt-1">Waiting for wallet or network…</div>
            )}
          </div>
        </div>
        <div className="text-right">
          <div className="text-3xl font-black text-green-400">{synced}</div>
          <div className="text-xs text-gray-400">witnesses synced</div>
          <div className="text-xs text-green-500 mt-0.5">
            {((11111 + synced * 1500) / 1_000_000).toFixed(4)} EGOC/event
          </div>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Today PoC Rewards', val: todayRewardsStr,                                     color: 'text-green-400'  },
          { label: 'Events (24h)',       val: `${events24h.length}`,                               color: 'text-blue-400'   },
          { label: 'Active Nodes',       val: `${peersOnMap + (loc ? 1 : 0)}`,                     color: 'text-purple-400' },
          { label: 'H3 Cell',            val: h3Cell ? h3Cell.slice(0, 8) + '…' : '—',            color: 'text-orange-400' },
        ].map(c => (
          <div key={c.label} className="bg-gray-800 rounded-2xl p-4 border border-gray-700">
            <div className="text-xs text-gray-400 mb-1">{c.label}</div>
            <div className={`text-xl font-bold ${c.color}`}>{c.val}</div>
          </div>
        ))}
      </div>

      {/* Live Network Map */}
      <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-700 flex items-center justify-between">
          <div>
            <h3 className="font-semibold">Live Network Map</h3>
            <p className="text-xs text-gray-500 mt-0.5">
              {peersOnMap} node{peersOnMap !== 1 ? 's' : ''} mapped
              {peersNoLocation > 0 && ` · ${peersNoLocation} without location`}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {online && (
              <span className="flex items-center gap-1.5 text-xs text-green-400">
                <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse inline-block"/>
                Live
              </span>
            )}
          </div>
        </div>
        <div className="p-3">
          <WorldNetworkMap myNode={mapNodes.find(n => n.isMe) ?? null} peers={mapNodes.filter(n => !n.isMe)} />
        </div>
      </div>

      <div className="grid grid-cols-5 gap-4">
        <div className="col-span-3 bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden self-start">
          <div className="px-5 py-4 border-b border-gray-700">
            <h3 className="font-semibold">PoC Event Log</h3>
          </div>
          <div ref={eventLogRef} className="divide-y divide-gray-700/50 max-h-[570px] overflow-y-auto">
            {events.length === 0 ? (
              <div className="px-5 py-8 text-center text-gray-500 text-sm">
                {online ? 'First event will appear in ~4 minutes…' : 'No events — coverage is offline'}
              </div>
            ) : events.map(ev => (
              <div key={ev.id} className="flex items-center justify-between px-5 py-3">
                <div className="flex items-center gap-3">
                  <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${qualityBadge(ev.quality)}`}>
                    {ev.quality}
                  </span>
                  <div>
                    <div className="text-xs text-gray-300">
                      {ev.peers > 0 ? `${ev.peers} peer${ev.peers > 1 ? 's' : ''} witnessed` : 'Self-attested (solo node)'}
                    </div>
                    <div className="text-xs text-gray-500">
                      base 0.011 + {ev.peers} × 0.0015 EGOC
                    </div>
                    {ev.h3_cell && <div className="text-xs text-gray-500 font-mono">H3: {ev.h3_cell}</div>}
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-sm font-semibold text-green-400">
                    +{(ev.reward_uegoc / 1_000_000).toFixed(4)} EGOC
                  </div>
                  <div className="text-xs text-gray-500">{timeAgo(ev.timestamp)}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="col-span-2 space-y-4">
          <div className="bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <h3 className="font-semibold mb-4">Location</h3>
            <div className="bg-gray-900 rounded-xl p-4 mb-3 flex items-center justify-center min-h-[7rem]">
              {loading ? (
                <div className="text-gray-500 text-sm animate-pulse">Detecting location…</div>
              ) : loc ? (
                <div className="text-center">
                  <div className="text-3xl mb-2">📍</div>
                  <div className="text-sm font-mono text-gray-300">{coordStr}</div>
                  <div className="text-xs text-gray-400 mt-1">{cityStr}</div>
                </div>
              ) : (
                <div className="text-center text-gray-500">
                  <div className="text-3xl mb-1">🌐</div>
                  <div className="text-xs">Location unavailable</div>
                  <div className="text-xs text-gray-600 mt-1">Check internet connection</div>
                </div>
              )}
            </div>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-400">Coordinates</span>
                <span className="font-mono text-xs">{coordStr ?? '—'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">City</span>
                <span>{loc?.city ?? '—'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Country</span>
                <span>{loc?.country ?? '—'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">H3 Cell</span>
                <span className="font-mono text-xs">{h3Cell ?? '—'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Source</span>
                <span className="text-gray-500 text-xs">IP geolocation</span>
              </div>
              <div className="flex justify-between items-center pt-1 border-t border-gray-700/50 mt-1">
                <span className="text-gray-400">VPN / Proxy</span>
                <span className={`text-xs font-semibold ${vpn ? 'text-red-400' : 'text-green-400'}`}>
                  {vpn ? '⚠ Detected' : '✓ None'}
                </span>
              </div>
              {machineId && (
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Machine ID</span>
                  <span className="font-mono text-xs text-gray-500 truncate max-w-[120px]" title={machineId}>
                    {machineId.slice(0, 16)}{machineId.length > 16 ? '…' : ''}
                  </span>
                </div>
              )}
            </div>
          </div>

          <div className="bg-gray-800 rounded-2xl p-5 border border-gray-700">
            <h3 className="font-semibold mb-4">Beacon Settings</h3>
            <div className="space-y-3 text-sm">
              {[
                { label: 'Beacon rate',  val: '1 Hz',  note: 'Batched off-peak' },
                { label: 'Interface',    val: 'Wi-Fi', note: 'Cellular-safe on'  },
                { label: 'Auto-disable', val: 'On',    note: 'On cellular cap'   },
              ].map(s => (
                <div key={s.label} className="flex justify-between items-start">
                  <div>
                    <div className="text-gray-300">{s.label}</div>
                    <div className="text-xs text-gray-500">{s.note}</div>
                  </div>
                  <span className="text-blue-400 font-medium">{s.val}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CoveragePage;
