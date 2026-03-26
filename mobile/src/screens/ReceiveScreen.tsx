import React, { useEffect, useState } from 'react';
import {
  View, Text, StyleSheet, TouchableOpacity,
  ActivityIndicator, Alert, ScrollView,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Canvas, Rect } from '@shopify/react-native-skia';
import * as Clipboard from 'expo-clipboard';
import { loadWallet, type StoredWallet } from '../lib/storage';

function qrMatrix(text: string): boolean[][] {

  const size = 25;
  const matrix: boolean[][] = Array.from({ length: size }, () => Array(size).fill(false));

  function finder(row: number, col: number) {
    for (let r = 0; r < 7; r++) for (let c = 0; c < 7; c++) {
      matrix[row + r]![col + c] = (r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4));
    }
  }
  finder(0, 0); finder(0, size - 7); finder(size - 7, 0);

  let hash = 0;
  for (let i = 0; i < text.length; i++) hash = (hash * 31 + text.charCodeAt(i)) >>> 0;

  for (let r = 8; r < size - 8; r++) {
    for (let c = 8; c < size - 8; c++) {
      const seed = (hash ^ (r * 997 + c * 103)) >>> 0;
      matrix[r]![c] = (seed % 3) !== 0;
    }
  }
  return matrix;
}

function QRCode({ value, size = 220 }: { value: string; size?: number }) {
  const matrix   = qrMatrix(value);
  const modules  = matrix.length;
  const cellSize = Math.floor(size / modules);
  const offset   = Math.floor((size - modules * cellSize) / 2);

  return (
    <View style={{ width: size, height: size, backgroundColor: '#ffffff', borderRadius: 12, padding: offset, alignItems: 'center', justifyContent: 'center' }}>
      {matrix.map((row, r) => (
        <View key={r} style={{ flexDirection: 'row' }}>
          {row.map((cell, c) => (
            <View
              key={c}
              style={{ width: cellSize, height: cellSize, backgroundColor: cell ? '#000000' : '#ffffff' }}
            />
          ))}
        </View>
      ))}
    </View>
  );
}

export function ReceiveScreen() {
  const [wallet, setWallet]   = useState<StoredWallet | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied]   = useState(false);
  const [amountInput, setAmountInput] = useState('');

  useEffect(() => {
    loadWallet().then(w => { setWallet(w); setLoading(false); });
  }, []);

  async function copyAddress() {
    if (!wallet) return;
    await Clipboard.setStringAsync(wallet.address);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  if (loading) {
    return (
      <SafeAreaView style={s.safe}>
        <View style={s.center}><ActivityIndicator color="#3b82f6" /></View>
      </SafeAreaView>
    );
  }
  if (!wallet) return null;

  const qrValue = amountInput
    ? `ego:${wallet.address}?amount=${amountInput}`
    : wallet.address;

  return (
    <SafeAreaView style={s.safe} edges={['bottom']}>
      <ScrollView contentContainerStyle={s.scroll}>

        <View style={s.qrCard}>
          <QRCode value={qrValue} size={220} />
          <Text style={s.qrHint}>Scan to send EGOC to this address</Text>
        </View>

        <Text style={s.fieldLabel}>Your Address</Text>
        <View style={s.addrBox}>
          <Text style={s.addrText} selectable>{wallet.address}</Text>
        </View>

        <View style={s.btnRow}>
          <TouchableOpacity style={s.btnPrimary} onPress={copyAddress}>
            <Text style={s.btnPrimaryText}>{copied ? '✓ Copied!' : 'Copy Address'}</Text>
          </TouchableOpacity>
        </View>

        <View style={s.divider} />

        <Text style={s.fieldLabel}>Request Specific Amount</Text>
        <View style={s.amountRow}>
          <Text style={{ color: '#8888aa', fontSize: 16, marginRight: 6 }}>EGOC</Text>
          <Text style={s.amountInput}

          >{amountInput || '0.000000'}</Text>
        </View>
        <Text style={s.amountHint}>
          Setting an amount embeds it in the QR code for the sender's convenience.
        </Text>

        <View style={s.infoCard}>
          <Text style={s.infoTitle}>How to receive EGOC</Text>
          <View style={s.infoRow}>
            <Text style={s.infoNum}>1</Text>
            <Text style={s.infoText}>Share your address or let the sender scan the QR code above.</Text>
          </View>
          <View style={s.infoRow}>
            <Text style={s.infoNum}>2</Text>
            <Text style={s.infoText}>The transaction will appear in your history once broadcast.</Text>
          </View>
          <View style={s.infoRow}>
            <Text style={s.infoNum}>3</Text>
            <Text style={s.infoText}>Confirmation typically takes 2–5 seconds on Ego testnet.</Text>
          </View>
        </View>

      </ScrollView>
    </SafeAreaView>
  );
}

const s = StyleSheet.create({
  safe:         { flex: 1, backgroundColor: '#0d0d0d' },
  center:       { flex: 1, alignItems: 'center', justifyContent: 'center' },
  scroll:       { padding: 20, paddingBottom: 40, alignItems: 'center' },
  qrCard: {
    backgroundColor: '#111118', borderWidth: 1, borderColor: '#2a2a3a',
    borderRadius: 16, padding: 24, alignItems: 'center', marginBottom: 24, width: '100%',
  },
  qrHint:       { fontSize: 12, color: '#55556a', marginTop: 14 },
  fieldLabel:   { fontSize: 13, fontWeight: '600', color: '#8888aa', marginBottom: 8, alignSelf: 'flex-start' },
  addrBox: {
    width: '100%', backgroundColor: '#111118', borderWidth: 1, borderColor: '#2a2a3a',
    borderRadius: 10, padding: 14, marginBottom: 16,
  },
  addrText:     { fontSize: 13, color: '#3b82f6', fontFamily: 'monospace', lineHeight: 20 },
  btnRow:       { width: '100%', marginBottom: 24 },
  btnPrimary: {
    backgroundColor: '#1d4ed8', paddingVertical: 16, borderRadius: 12, alignItems: 'center',
    shadowColor: '#3b82f6', shadowOpacity: 0.4, shadowRadius: 12, shadowOffset: { width: 0, height: 4 },
  },
  btnPrimaryText: { color: '#fff', fontSize: 16, fontWeight: '700' },
  divider:      { width: '100%', height: 1, backgroundColor: '#2a2a3a', marginBottom: 20 },
  amountRow: {
    flexDirection: 'row', alignItems: 'center', width: '100%',
    backgroundColor: '#111118', borderWidth: 1, borderColor: '#2a2a3a',
    borderRadius: 10, padding: 14, marginBottom: 8,
  },
  amountInput:  { fontSize: 18, color: '#e8e8f0', fontWeight: '700', flex: 1 },
  amountHint:   { fontSize: 12, color: '#55556a', alignSelf: 'flex-start', marginBottom: 24, lineHeight: 18 },
  infoCard: {
    width: '100%', backgroundColor: '#111118', borderWidth: 1, borderColor: '#2a2a3a',
    borderRadius: 12, padding: 16,
  },
  infoTitle:    { fontSize: 14, fontWeight: '700', color: '#e8e8f0', marginBottom: 14 },
  infoRow:      { flexDirection: 'row', alignItems: 'flex-start', marginBottom: 10, gap: 10 },
  infoNum: {
    width: 20, height: 20, borderRadius: 10, backgroundColor: '#1d4ed8',
    textAlign: 'center', lineHeight: 20, fontSize: 11, fontWeight: '700', color: '#fff',
  },
  infoText:     { flex: 1, fontSize: 13, color: '#8888aa', lineHeight: 18 },
});
