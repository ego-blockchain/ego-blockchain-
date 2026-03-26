'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

function crc32(data) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
    }
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function u32(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

function chunk(type, data) {
  const typeBytes = Buffer.from(type, 'ascii');
  const lenBytes = u32(data.length);
  const crcInput = Buffer.concat([typeBytes, data]);
  const crcBytes = u32(crc32(crcInput));
  return Buffer.concat([lenBytes, typeBytes, data, crcBytes]);
}

function makePNG(size, r, g, b) {

  const pixels = [];
  const cx = size / 2;
  const cy = size / 2;
  const radius = size / 2;

  for (let y = 0; y < size; y++) {
    const row = [];
    for (let x = 0; x < size; x++) {
      const dx = x - cx + 0.5;
      const dy = y - cy + 0.5;
      const dist = Math.sqrt(dx*dx + dy*dy);

      if (dist <= radius) {

        const t = dist / radius;
        const pr = Math.round(37 + t * (124 - 37));
        const pg = Math.round(99 + t * (58 - 99));
        const pb = Math.round(235 + t * (237 - 235));
        row.push(pr, pg, pb, 255);
      } else {
        row.push(0, 0, 0, 0);
      }
    }
    pixels.push(row);
  }

  const s = size;
  const margin = Math.round(s * 0.25);
  const mid = Math.round(s * 0.45);
  const midEnd = Math.round(s * 0.55);
  const right = Math.round(s * 0.75);
  const barH = Math.max(1, Math.round(s * 0.1));

  function setWhite(x, y) {
    if (x < 0 || y < 0 || x >= size || y >= size) return;
    pixels[y][x * 4] = 255;
    pixels[y][x * 4 + 1] = 255;
    pixels[y][x * 4 + 2] = 255;
    pixels[y][x * 4 + 3] = 255;
  }

  for (let y = margin; y < s - margin; y++) {
    for (let bx = 0; bx < barH; bx++) {
      setWhite(margin + bx, y);
    }
  }

  for (let x = margin; x < right; x++) {
    for (let by = 0; by < barH; by++) {
      setWhite(x, margin + by);
    }
  }

  for (let x = margin; x < Math.round(s * 0.65); x++) {
    for (let by = 0; by < barH; by++) {
      setWhite(x, mid + by);
    }
  }

  for (let x = margin; x < right; x++) {
    for (let by = 0; by < barH; by++) {
      setWhite(x, s - margin - barH + by);
    }
  }

  const rawRows = [];
  for (let y = 0; y < size; y++) {
    const row = Buffer.alloc(1 + size * 4);
    row[0] = 0;
    for (let x = 0; x < size; x++) {
      row[1 + x * 4] = pixels[y][x * 4];
      row[1 + x * 4 + 1] = pixels[y][x * 4 + 1];
      row[1 + x * 4 + 2] = pixels[y][x * 4 + 2];
      row[1 + x * 4 + 3] = pixels[y][x * 4 + 3];
    }
    rawRows.push(row);
  }
  const rawData = Buffer.concat(rawRows);
  const compressed = zlib.deflateSync(rawData, { level: 9 });

  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const ihdr = chunk('IHDR', Buffer.concat([
    u32(size), u32(size),
    Buffer.from([8, 6, 0, 0, 0]),
  ]));
  const idat = chunk('IDAT', compressed);
  const iend = chunk('IEND', Buffer.alloc(0));

  return Buffer.concat([signature, ihdr, idat, iend]);
}

const sizes = [16, 48, 128];
for (const sz of sizes) {
  const png = makePNG(sz);
  const outPath = path.join(__dirname, `icon${sz}.png`);
  fs.writeFileSync(outPath, png);
  console.log(`Written: ${outPath} (${png.length} bytes)`);
}

console.log('Icons generated successfully.');
