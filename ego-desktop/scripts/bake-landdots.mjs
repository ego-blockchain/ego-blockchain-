import { readFile, writeFile } from 'fs/promises';
import { feature, mesh } from 'topojson-client';
import { geoContains } from 'd3-geo';

const topo = JSON.parse(await readFile(new URL('../node_modules/world-atlas/land-110m.json', import.meta.url), 'utf8'));
const land = feature(topo, topo.objects.land);
const ctopo = JSON.parse(await readFile(new URL('../node_modules/world-atlas/countries-110m.json', import.meta.url), 'utf8'));
const borders = mesh(ctopo, ctopo.objects.countries, (a, b) => a !== b);

const COLS = 288;
const ROWS = 110;
const LAT_TOP = 78;
const LAT_BOTTOM = -58;

const bytes = new Uint8Array(Math.ceil((COLS * ROWS) / 8));
for (let r = 0; r < ROWS; r++) {
  const lat = LAT_TOP - (r + 0.5) * ((LAT_TOP - LAT_BOTTOM) / ROWS);
  for (let c = 0; c < COLS; c++) {
    const lon = -180 + (c + 0.5) * (360 / COLS);
    if (geoContains(land, [lon, lat])) {
      const i = r * COLS + c;
      bytes[i >> 3] |= 1 << (i & 7);
    }
  }
}

const lines = borders.coordinates.filter(line =>
  line.some(([, lat]) => lat >= LAT_BOTTOM - 2 && lat <= LAT_TOP + 2)
);
const totalPts = lines.reduce((n, l) => n + l.length, 0);
const bbuf = Buffer.alloc(2 + lines.length * 2 + totalPts * 4);
let o = bbuf.writeUInt16LE(lines.length, 0);
for (const line of lines) {
  o = bbuf.writeUInt16LE(line.length, o);
  for (const [lon, lat] of line) {
    o = bbuf.writeInt16LE(Math.round(lon * 90), o);
    o = bbuf.writeInt16LE(Math.round(lat * 90), o);
  }
}
const bordersB64 = bbuf.toString('base64');

const b64 = Buffer.from(bytes).toString('base64');
const out = `export const DOT_COLS = ${COLS};
export const DOT_ROWS = ${ROWS};
export const DOT_LAT_TOP = ${LAT_TOP};
export const DOT_LAT_BOTTOM = ${LAT_BOTTOM};

const PACKED = '${b64}';

export function decodeLandDots(): Float32Array {
  const bin = atob(PACKED);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const pts: number[] = [];
  for (let r = 0; r < DOT_ROWS; r++) {
    const lat = DOT_LAT_TOP - (r + 0.5) * ((DOT_LAT_TOP - DOT_LAT_BOTTOM) / DOT_ROWS);
    for (let c = 0; c < DOT_COLS; c++) {
      const i = r * DOT_COLS + c;
      if (bytes[i >> 3] & (1 << (i & 7))) {
        const lon = -180 + (c + 0.5) * (360 / DOT_COLS);
        pts.push(lon, lat);
      }
    }
  }
  return new Float32Array(pts);
}

const BORDERS_PACKED = '${bordersB64}';

export function decodeBorders(): Float32Array[] {
  const bin = atob(BORDERS_PACKED);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const dv = new DataView(bytes.buffer);
  let o = 0;
  const lineCount = dv.getUint16(o, true); o += 2;
  const lines: Float32Array[] = [];
  for (let l = 0; l < lineCount; l++) {
    const n = dv.getUint16(o, true); o += 2;
    const pts = new Float32Array(n * 2);
    for (let i = 0; i < n; i++) {
      pts[i * 2]     = dv.getInt16(o, true) / 90; o += 2;
      pts[i * 2 + 1] = dv.getInt16(o, true) / 90; o += 2;
    }
    lines.push(pts);
  }
  return lines;
}
`;

await writeFile(new URL('../src-frontend/components/landDots.ts', import.meta.url), out);
let count = 0;
for (const b of bytes) count += ((b * 0x08040201) >>> 3) & 0x11111111 ? 0 : 0;
let total = 0;
for (const b of bytes) { let v = b; while (v) { total += v & 1; v >>= 1; } }
console.log(`baked ${total} land dots (${COLS}x${ROWS}, ${Math.round(b64.length / 1024)}KB) + ${lines.length} border lines / ${totalPts} pts (${Math.round(bordersB64.length / 1024)}KB) → landDots.ts`);
