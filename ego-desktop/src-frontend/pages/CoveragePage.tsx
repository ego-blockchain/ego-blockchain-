import React, { useState, useEffect, useRef, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import Pagination from '../components/Pagination';
import { useWallet } from '../App';

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
  const m = endpoint.match(/\/p2p\/([A-Za-z0-9]+)$/);
  return m ? m[1] : endpoint;
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

// Land polygons — continent + island shapes [lon, lat]
const LAND: [number, number][][] = [
  [[-167,62],[-158,56],[-152,60],[-148,60],[-140,60],[-136,56],[-132,54],[-128,50],[-126,50],[-124,46],[-124,40],[-122,36],[-118,34],[-116,32],[-110,30],[-106,28],[-100,26],[-97,26],[-93,28],[-90,28],[-88,30],[-84,30],[-82,30],[-80,26],[-82,24],[-88,20],[-88,16],[-84,14],[-82,10],[-78,8],[-76,8],[-72,10],[-68,12],[-62,12],[-64,16],[-66,18],[-68,18],[-70,20],[-74,22],[-76,24],[-78,26],[-80,26],[-82,30],[-80,32],[-78,34],[-76,36],[-72,42],[-70,44],[-68,47],[-64,44],[-62,46],[-60,47],[-58,48],[-56,50],[-54,52],[-56,56],[-58,60],[-60,62],[-64,64],[-72,64],[-78,66],[-80,70],[-85,72],[-94,74],[-100,72],[-110,70],[-120,72],[-130,70],[-140,70],[-148,68],[-158,66],[-165,66],[-167,68]],
  [[-78,10],[-75,12],[-70,12],[-62,12],[-60,10],[-56,8],[-52,5],[-50,4],[-44,2],[-40,0],[-36,-4],[-35,-6],[-35,-10],[-36,-12],[-38,-16],[-40,-20],[-42,-22],[-44,-24],[-46,-24],[-48,-28],[-50,-30],[-52,-34],[-54,-36],[-56,-38],[-58,-42],[-62,-46],[-64,-52],[-65,-55],[-67,-55],[-68,-55],[-68,-52],[-70,-50],[-72,-48],[-74,-44],[-75,-40],[-76,-36],[-78,-28],[-80,-22],[-80,-18],[-80,-10],[-80,-4],[-80,0],[-78,2],[-78,6],[-78,10]],
  [[-10,36],[-8,36],[-2,36],[2,38],[4,40],[2,44],[0,46],[-2,48],[-2,50],[0,52],[2,52],[4,52],[6,52],[8,54],[10,54],[12,56],[14,56],[16,56],[18,56],[20,54],[22,54],[24,52],[26,50],[28,48],[30,46],[28,44],[26,42],[24,40],[22,40],[22,38],[24,38],[26,38],[28,40],[30,40],[32,42],[36,44],[38,42],[36,40],[36,38],[34,36],[30,36],[26,36],[22,38],[18,40],[16,40],[14,42],[12,44],[10,44],[8,44],[6,44],[4,44],[2,44],[0,44],[-2,44],[-4,44],[-6,44],[-8,44],[-10,42],[-10,40],[-10,38],[-10,36]],
  [[4,58],[6,58],[8,56],[10,56],[12,56],[14,56],[16,58],[18,60],[20,60],[22,62],[24,64],[26,66],[28,68],[26,70],[22,70],[18,70],[16,70],[14,68],[12,66],[10,64],[8,62],[6,60],[4,58]],
  [[28,47],[28,52],[30,58],[30,64],[28,70],[34,70],[40,70],[50,68],[60,70],[70,72],[80,72],[90,74],[100,76],[110,78],[120,78],[130,76],[140,76],[150,78],[160,76],[170,74],[180,72],[180,66],[176,62],[170,58],[164,56],[158,52],[152,48],[148,46],[142,44],[134,44],[126,46],[120,48],[110,50],[100,50],[90,48],[80,50],[70,52],[60,52],[52,50],[46,50],[42,50],[38,48],[34,46],[28,47]],
  [[28,42],[28,38],[30,36],[32,32],[34,24],[36,18],[38,14],[44,12],[50,14],[54,14],[60,14],[70,10],[78,8],[80,6],[90,4],[100,2],[104,4],[106,8],[108,10],[110,14],[114,18],[118,22],[122,28],[126,32],[128,36],[130,40],[130,44],[132,44],[130,47],[120,50],[110,52],[100,54],[60,54],[54,52],[50,50],[46,50],[42,50],[40,48],[36,46],[32,44],[28,42]],
  [[68,22],[72,22],[76,20],[78,16],[80,12],[80,8],[78,8],[74,8],[70,10],[66,16],[66,20],[68,22]],
  [[98,22],[102,22],[108,16],[110,12],[108,8],[106,8],[104,4],[100,2],[98,4],[96,8],[92,16],[90,20],[90,22],[98,22]],
  [[-6,36],[-2,36],[2,36],[6,36],[10,36],[14,36],[18,34],[22,34],[26,34],[30,32],[34,30],[36,26],[38,22],[40,18],[42,16],[44,14],[46,12],[48,12],[50,12],[52,14],[50,12],[48,10],[46,10],[44,10],[42,8],[44,4],[44,0],[42,-4],[40,-8],[40,-12],[38,-16],[36,-20],[34,-24],[32,-28],[30,-32],[28,-34],[24,-36],[20,-36],[16,-32],[14,-26],[12,-20],[10,-14],[10,-8],[8,-4],[6,0],[4,4],[2,6],[0,6],[-2,6],[-4,6],[-6,4],[-8,4],[-12,4],[-14,8],[-16,10],[-16,12],[-16,14],[-16,16],[-16,18],[-14,20],[-14,22],[-14,24],[-12,26],[-8,28],[-6,30],[-4,32],[-4,34],[-6,36]],
  [[114,-22],[116,-20],[118,-18],[120,-18],[122,-18],[124,-16],[126,-14],[128,-14],[130,-12],[132,-12],[134,-12],[136,-12],[138,-14],[140,-16],[142,-16],[144,-16],[146,-18],[148,-20],[150,-22],[152,-24],[152,-26],[152,-28],[152,-32],[150,-36],[148,-38],[146,-40],[144,-40],[142,-38],[140,-38],[138,-36],[136,-34],[132,-32],[128,-34],[126,-34],[122,-34],[118,-34],[116,-32],[114,-30],[114,-26],[114,-22]],
  [[-56,82],[-44,82],[-30,82],[-18,82],[-18,78],[-20,76],[-22,74],[-24,72],[-24,70],[-28,68],[-34,68],[-40,68],[-46,68],[-52,68],[-54,72],[-56,76],[-56,80],[-56,82]],
  [[-6,50],[-4,50],[-2,52],[0,52],[2,52],[2,54],[0,56],[-2,58],[-4,58],[-6,58],[-6,56],[-4,54],[-4,52],[-6,50]],
  [[-10,52],[-6,52],[-6,54],[-8,54],[-10,54],[-10,52]],
  [[130,32],[132,34],[134,36],[136,36],[138,38],[140,40],[142,40],[142,38],[140,36],[138,34],[136,34],[134,32],[132,30],[130,32]],
  [[108,2],[110,4],[112,4],[114,6],[116,6],[118,4],[118,2],[116,2],[116,0],[114,0],[112,0],[110,0],[108,0],[108,2]],
  [[96,6],[98,4],[100,2],[102,2],[104,2],[106,2],[106,0],[104,0],[102,-2],[100,-4],[98,-4],[96,-2],[96,0],[96,4],[96,6]],
  [[130,-2],[132,-2],[134,-4],[136,-4],[138,-4],[140,-4],[142,-4],[144,-6],[146,-6],[148,-6],[148,-8],[146,-8],[144,-8],[142,-6],[140,-6],[138,-6],[136,-6],[134,-4],[132,-4],[130,-4],[130,-2]],
  [[44,-12],[46,-14],[48,-16],[50,-18],[50,-20],[50,-22],[50,-24],[48,-26],[46,-26],[44,-24],[44,-22],[44,-20],[44,-18],[44,-16],[44,-12]],
  [[-24,64],[-20,64],[-16,64],[-14,66],[-14,68],[-18,68],[-22,68],[-24,66],[-24,64]],
  [[172,-36],[174,-38],[176,-40],[178,-40],[176,-42],[174,-42],[172,-40],[172,-38],[172,-36]],
];

interface TooltipState { x: number; y: number; node: MapNode }

const WorldNetworkMap: React.FC<{ myNode: MapNode | null; peers: MapNode[] }> = ({ myNode, peers }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const vsRef     = useRef({ scale: 1, ox: 0, oy: 0, drag: false, lx: 0, ly: 0 });
  const frameRef  = useRef(0);
  const [tooltip, setTooltip] = useState<TooltipState | null>(null);
  const nodesRef  = useRef<MapNode[]>([]);

  const allNodes = myNode ? [myNode, ...peers] : peers;
  nodesRef.current = allNodes;

  const project = useCallback((lon: number, lat: number, w: number, h: number): [number,number] => {
    const vs = vsRef.current;
    return [
      ((lon + 180) / 360) * w * vs.scale + vs.ox,
      ((90 - lat)  / 180) * h * vs.scale + vs.oy,
    ];
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

    const draw = (ts: number) => {
      const t  = ts / 1000;
      const rect = canvas.getBoundingClientRect();
      const w  = rect.width;
      const h  = rect.height;
      const vs = vsRef.current;

      ctx.save();
      ctx.scale(dpr, dpr);
      ctx.clearRect(0, 0, w, h);

      // Ocean
      ctx.fillStyle = '#050810';
      ctx.fillRect(0, 0, w, h);

      // Graticule
      ctx.strokeStyle = 'rgba(255,255,255,0.04)';
      ctx.lineWidth = 0.4;
      for (let lon = -180; lon <= 180; lon += 30) {
        const [x, y0] = project(lon, 85, w, h);
        const [, y1]  = project(lon, -85, w, h);
        ctx.beginPath(); ctx.moveTo(x, y0); ctx.lineTo(x, y1); ctx.stroke();
      }
      for (let lat = -60; lat <= 90; lat += 30) {
        const [x0, y] = project(-180, lat, w, h);
        const [x1]    = project(180,  lat, w, h);
        ctx.beginPath(); ctx.moveTo(x0, y); ctx.lineTo(x1, y); ctx.stroke();
      }

      // Land polygons
      ctx.setLineDash([]);
      for (const poly of LAND) {
        if (poly.length < 3) continue;
        ctx.beginPath();
        const [sx, sy] = project(poly[0][0], poly[0][1], w, h);
        ctx.moveTo(sx, sy);
        for (let i = 1; i < poly.length; i++) {
          ctx.lineTo(...project(poly[i][0], poly[i][1], w, h));
        }
        ctx.closePath();
        ctx.fillStyle   = '#1e2540';
        ctx.strokeStyle = '#2e3560';
        ctx.lineWidth   = vs.scale > 2 ? 0.8 : 0.5;
        ctx.fill();
        ctx.stroke();
      }

      const nodes = nodesRef.current;
      const me    = nodes.find(n => n.isMe);
      const dashOff = (t * 25) % 18;

      // Mesh connections — all node pairs
      const MAX_LINES = 80;
      let lineCount = 0;
      for (let i = 0; i < nodes.length && lineCount < MAX_LINES; i++) {
        for (let j = i + 1; j < nodes.length && lineCount < MAX_LINES; j++) {
          const a = nodes[i], b = nodes[j];
          const [ax, ay] = project(a.lon, a.lat, w, h);
          const [bx, by] = project(b.lon, b.lat, w, h);
          const isMyLine = a.isMe || b.isMe;
          ctx.save();
          ctx.strokeStyle = isMyLine
            ? 'rgba(100,180,255,0.55)'
            : 'rgba(140,200,140,0.25)';
          ctx.lineWidth   = isMyLine ? 1.0 : 0.6;
          ctx.setLineDash([4, 6]);
          ctx.lineDashOffset = isMyLine ? -dashOff : -(dashOff * 0.6);
          ctx.beginPath();
          ctx.moveTo(ax, ay);
          ctx.lineTo(bx, by);
          ctx.stroke();
          ctx.restore();
          lineCount++;
        }
      }

      // Peer nodes
      for (const node of nodes.filter(n => !n.isMe)) {
        const [px, py] = project(node.lon, node.lat, w, h);
        ctx.beginPath();
        ctx.arc(px, py, 4, 0, Math.PI * 2);
        ctx.fillStyle   = '#81c784';
        ctx.fill();
        ctx.strokeStyle = 'rgba(150,230,150,0.6)';
        ctx.lineWidth   = 1;
        ctx.stroke();
        // Outer ring at higher zoom
        if (vs.scale > 1.5) {
          ctx.beginPath();
          ctx.arc(px, py, 7, 0, Math.PI * 2);
          ctx.strokeStyle = 'rgba(129,199,132,0.25)';
          ctx.lineWidth   = 1;
          ctx.stroke();
        }
      }

      // My node — pulsing glow
      if (me) {
        const [mx, my_y] = project(me.lon, me.lat, w, h);
        const pulse  = 0.5 + 0.5 * Math.sin(t * 2.5);
        const outerR = 10 + pulse * 8;
        const grad   = ctx.createRadialGradient(mx, my_y, 2, mx, my_y, outerR);
        grad.addColorStop(0, 'rgba(79,195,247,0.85)');
        grad.addColorStop(1, 'rgba(79,195,247,0)');
        ctx.beginPath(); ctx.arc(mx, my_y, outerR, 0, Math.PI * 2);
        ctx.fillStyle = grad; ctx.fill();
        // Second ring
        const ring2R = 6 + pulse * 4;
        ctx.beginPath(); ctx.arc(mx, my_y, ring2R, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(79,195,247,0.4)'; ctx.lineWidth = 1; ctx.stroke();
        // Core dot
        ctx.beginPath(); ctx.arc(mx, my_y, 5, 0, Math.PI * 2);
        ctx.fillStyle = '#ffffff'; ctx.fill();
        ctx.strokeStyle = '#4fc3f7'; ctx.lineWidth = 2; ctx.stroke();
        // Label
        if (vs.scale > 1.0) {
          ctx.fillStyle = 'rgba(79,195,247,0.9)';
          ctx.font = `bold ${Math.max(8, 9 * vs.scale)}px sans-serif`;
          ctx.fillText('YOU', mx + 8, my_y - 6);
        }
      }

      ctx.restore();
      frameRef.current = requestAnimationFrame(draw);
    };

    frameRef.current = requestAnimationFrame(draw);

    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const v    = vsRef.current;
      const rect = canvas.getBoundingClientRect();
      const cx = e.clientX - rect.left;
      const cy = e.clientY - rect.top;
      const d  = e.deltaY > 0 ? 0.82 : 1.22;
      const ns = Math.max(0.4, Math.min(12, v.scale * d));
      const sf = ns / v.scale;
      v.ox = cx - sf * (cx - v.ox);
      v.oy = cy - sf * (cy - v.oy);
      v.scale = ns;
    };
    canvas.addEventListener('wheel', onWheel, { passive: false });

    return () => { cancelAnimationFrame(frameRef.current); ro.disconnect(); canvas.removeEventListener('wheel', onWheel); };
  }, [project]);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    vsRef.current.drag = true; vsRef.current.lx = e.clientX; vsRef.current.ly = e.clientY;
    setTooltip(null);
  }, []);

  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const vs = vsRef.current;
    if (vs.drag) {
      vs.ox += e.clientX - vs.lx; vs.oy += e.clientY - vs.ly;
      vs.lx  = e.clientX;          vs.ly  = e.clientY;
      setTooltip(null); return;
    }
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    let found: MapNode | null = null;
    for (const node of nodesRef.current) {
      const [px, py] = project(node.lon, node.lat, rect.width, rect.height);
      if (Math.hypot(px - mx, py - my) < 12) { found = node; break; }
    }
    setTooltip(found ? { x: mx, y: my, node: found } : null);
  }, [project]);

  const handleMouseUp    = useCallback(() => { vsRef.current.drag = false; }, []);
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
      <div className="absolute bottom-2 right-2 flex gap-3 text-xs text-gray-400 bg-black/50 backdrop-blur-sm rounded-lg px-3 py-1.5 border border-gray-700/40">
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-white inline-block"/>You</span>
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-green-400 inline-block"/>Peers</span>
        <span className="text-gray-600 hidden sm:inline">Scroll=zoom · Drag=pan</span>
      </div>
      {tooltip && (
        <div
          className="absolute pointer-events-none bg-gray-900/95 border border-gray-600 rounded-lg px-3 py-2 text-xs shadow-xl backdrop-blur-sm"
          style={{ left: Math.min(tooltip.x + 14, 320), top: tooltip.y - 14, zIndex: 20 }}
        >
          <div className={`font-bold mb-1 ${tooltip.node.isMe ? 'text-blue-300' : 'text-green-300'}`}>
            {tooltip.node.isMe ? '◉ Your Node' : '● Peer Node'}
          </div>
          <div className="text-gray-200">{tooltip.node.label}</div>
          {!tooltip.node.isMe && (
            <div className="text-gray-500 font-mono mt-0.5 text-[10px]">{shortPeerId(tooltip.node.id)}</div>
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

  const seenLocs = new Set<string>();
  for (const peer of peers) {
    const coords = resolveCoords(peer.city, peer.country);
    if (!coords) continue;
    const jitter: [number, number] = [
      coords[0] + (Math.sin(peer.address.charCodeAt(0) * 7919) * 2),
      coords[1] + (Math.cos(peer.address.charCodeAt(1) * 6271) * 2),
    ];
    const key = `${jitter[0].toFixed(1)},${jitter[1].toFixed(1)}`;
    if (seenLocs.has(key)) continue;
    seenLocs.add(key);
    mapNodes.push({
      id: extractPeerId(peer.endpoint) || peer.address,
      lat: jitter[0],
      lon: jitter[1],
      label: [peer.city, peer.country].filter(Boolean).join(', ') || peer.name || '—',
      isMe: false,
    });
  }

  const peersOnMap     = mapNodes.filter(n => !n.isMe).length;
  const peersNoLocation = peers.filter(p => !resolveCoords(p.city, p.country)).length;

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
