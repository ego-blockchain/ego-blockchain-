/**
 * HistoryScreen — full transaction history with filtering.
 */

import React, { useCallback, useEffect, useState } from 'react';
import {
  View, Text, StyleSheet, FlatList, TouchableOpacity,
  RefreshControl, ActivityIndicator, Modal, ScrollView,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import * as Clipboard from 'expo-clipboard';
import { loadWallet, type StoredWallet } from '../lib/storage';
import { getTransactions, uEgocToEgoc, type RpcTransaction } from '../lib/rpc';

type Filter = 'all' | 'sent' | 'received' | 'pending';

export function HistoryScreen() {
  const [wallet, setWallet]         = useState<StoredWallet | null>(null);
  const [txs, setTxs]               = useState<RpcTransaction[]>([]);
  const [filter, setFilter]         = useState<Filter>('all');
  const [loading, setLoading]       = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selected, setSelected]     = useState<RpcTransaction | null>(null);
  const [copied, setCopied]         = useState(false);

  async function load(spinner = true) {
    if (spinner) setLoading(true);
    try {
      const w = await loadWallet();
      if (!w) return;
      setWallet(w);
      const list = await getTransactions(w.address, 100).catch(() => []);
      setTxs(list.sort((a, b) => b.timestamp - a.timestamp));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => { load(); }, []);
  const onRefresh = useCallback(() => { setRefreshing(true); load(false); }, []);

  const filtered = txs.filter(tx => {
    if (!wallet) return true;
    if (filter === 'sent')     return tx.from === wallet.address;
    if (filter === 'received') return tx.to   === wallet.address;
    if (filter === 'pending')  return tx.status === 'pending';
    return true;
  });

  async function copyHash(hash: string) {
    await Clipboard.setStringAsync(hash);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  function TxRow({ item }: { item: RpcTransaction }) {
    const isOut = wallet && item.from === wallet.address;
    const other  = isOut ? item.to : item.from;
    const value  = uEgocToEgoc(BigInt(item.value));
    const ts     = new Date(item.timestamp * 1000);

    const statusColor = { confirmed: '#10b981', pending: '#f59e0b', failed: '#ef4444' }[item.status] ?? '#8888aa';
    const statusLabel = { confirmed: 'Confirmed', pending: 'Pending', failed: 'Failed' }[item.status] ?? item.status;

    return (
      <TouchableOpacity style={s.txRow} onPress={() => setSelected(item)} activeOpacity={0.7}>
        <View style={[s.txDot, { backgroundColor: isOut ? '#1a1030' : '#0d1f14' }]}>
          <Text style={{ fontSize: 18 }}>{isOut ? '↑' : '↓'}</Text>
        </View>
        <View style={s.txInfo}>
          <Text style={s.txType}>{isOut ? 'Sent' : 'Received'}</Text>
          <Text style={s.txAddr} numberOfLines={1}>
            {other.length > 18 ? other.slice(0, 10) + '…' + other.slice(-6) : other}
          </Text>
          <View style={[s.statusPill, { backgroundColor: statusColor + '18' }]}>
            <Text style={[s.statusText, { color: statusColor }]}>{statusLabel}</Text>
          </View>
        </View>
        <View style={s.txRight}>
          <Text style={[s.txValue, { color: isOut ? '#ef4444' : '#10b981' }]}>
            {isOut ? '−' : '+'}{value}
          </Text>
          <Text style={s.txCurrency}>EGOC</Text>
          <Text style={s.txDate}>
            {ts.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
          </Text>
          <Text style={s.txTime}>
            {ts.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}
          </Text>
        </View>
      </TouchableOpacity>
    );
  }

  if (loading) {
    return (
      <SafeAreaView style={s.safe}>
        <View style={s.center}><ActivityIndicator color="#3b82f6" size="large" /></View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={s.safe}>
      <View style={s.topBar}>
        <Text style={s.topTitle}>History</Text>
        <Text style={s.topCount}>{filtered.length} txs</Text>
      </View>

      <View style={s.filterRow}>
        {(['all', 'sent', 'received', 'pending'] as Filter[]).map(f => (
          <TouchableOpacity
            key={f}
            style={[s.filterBtn, filter === f && s.filterBtnActive]}
            onPress={() => setFilter(f)}
          >
            <Text style={[s.filterText, filter === f && s.filterTextActive]}>
              {f.charAt(0).toUpperCase() + f.slice(1)}
            </Text>
          </TouchableOpacity>
        ))}
      </View>

      <FlatList
        data={filtered}
        keyExtractor={item => item.hash}
        renderItem={({ item }) => <TxRow item={item} />}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#3b82f6" />}
        ListEmptyComponent={
          <View style={s.empty}>
            <Text style={s.emptyIcon}>📋</Text>
            <Text style={s.emptyText}>No transactions found</Text>
          </View>
        }
      />

      {/* Detail modal */}
      <Modal visible={!!selected} transparent animationType="slide" onRequestClose={() => setSelected(null)}>
        <View style={s.modalOverlay}>
          <View style={s.modal}>
            <Text style={s.modalTitle}>Transaction Detail</Text>
            {selected && <>
              <DetailRow label="Hash"   value={selected.hash}      mono />
              <DetailRow label="From"   value={selected.from}      mono />
              <DetailRow label="To"     value={selected.to}        mono />
              <DetailRow label="Amount" value={uEgocToEgoc(BigInt(selected.value)) + ' EGOC'} />
              <DetailRow label="Status" value={selected.status}    />
              <DetailRow label="Time"   value={new Date(selected.timestamp * 1000).toLocaleString()} />
              {selected.data && selected.data !== '0x' && <DetailRow label="Data" value={selected.data} mono />}
              <TouchableOpacity style={s.copyHashBtn} onPress={() => copyHash(selected.hash)}>
                <Text style={s.copyHashText}>{copied ? '✓ Copied' : 'Copy Hash'}</Text>
              </TouchableOpacity>
            </>}
            <TouchableOpacity style={s.closeBtn} onPress={() => setSelected(null)}>
              <Text style={s.closeBtnText}>Close</Text>
            </TouchableOpacity>
          </View>
        </View>
      </Modal>
    </SafeAreaView>
  );
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <View style={dr.row}>
      <Text style={dr.label}>{label}</Text>
      <Text style={[dr.value, mono && dr.mono]} numberOfLines={2} selectable>{value}</Text>
    </View>
  );
}
const dr = StyleSheet.create({
  row:   { marginBottom: 12 },
  label: { fontSize: 11, color: '#55556a', marginBottom: 2 },
  value: { fontSize: 13, color: '#e8e8f0' },
  mono:  { fontFamily: 'monospace', fontSize: 12, color: '#3b82f6' },
});

const s = StyleSheet.create({
  safe:     { flex: 1, backgroundColor: '#0d0d0d' },
  center:   { flex: 1, alignItems: 'center', justifyContent: 'center' },
  topBar:   { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', paddingHorizontal: 20, paddingVertical: 14 },
  topTitle: { fontSize: 20, fontWeight: '800', color: '#e8e8f0' },
  topCount: { fontSize: 12, color: '#55556a', backgroundColor: '#111118', borderRadius: 20, paddingHorizontal: 10, paddingVertical: 3 },

  filterRow:      { flexDirection: 'row', paddingHorizontal: 16, gap: 8, marginBottom: 8 },
  filterBtn:      { paddingHorizontal: 14, paddingVertical: 7, borderRadius: 20, borderWidth: 1, borderColor: '#2a2a3a' },
  filterBtnActive:{ backgroundColor: 'rgba(59,130,246,0.12)', borderColor: '#3b82f6' },
  filterText:     { fontSize: 12, fontWeight: '500', color: '#55556a' },
  filterTextActive:{ color: '#60a5fa' },

  txRow: {
    flexDirection: 'row', alignItems: 'center', gap: 12,
    paddingHorizontal: 20, paddingVertical: 14,
    borderBottomWidth: 1, borderBottomColor: '#1a1a24',
  },
  txDot:       { width: 42, height: 42, borderRadius: 21, alignItems: 'center', justifyContent: 'center' },
  txInfo:      { flex: 1 },
  txType:      { fontSize: 14, fontWeight: '600', color: '#e8e8f0', marginBottom: 2 },
  txAddr:      { fontSize: 12, color: '#55556a', fontFamily: 'monospace', marginBottom: 4 },
  statusPill:  { alignSelf: 'flex-start', paddingHorizontal: 8, paddingVertical: 2, borderRadius: 20 },
  statusText:  { fontSize: 10, fontWeight: '600' },
  txRight:     { alignItems: 'flex-end' },
  txValue:     { fontSize: 14, fontWeight: '700' },
  txCurrency:  { fontSize: 10, color: '#8888aa', marginBottom: 4 },
  txDate:      { fontSize: 11, color: '#55556a' },
  txTime:      { fontSize: 10, color: '#3d3d50' },

  empty:       { alignItems: 'center', paddingVertical: 60 },
  emptyIcon:   { fontSize: 36, marginBottom: 12 },
  emptyText:   { fontSize: 15, color: '#8888aa' },

  modalOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.75)', justifyContent: 'flex-end' },
  modal: {
    backgroundColor: '#111118', borderTopLeftRadius: 20, borderTopRightRadius: 20,
    borderWidth: 1, borderBottomWidth: 0, borderColor: '#2a2a3a', padding: 24, paddingBottom: 40,
  },
  modalTitle:   { fontSize: 17, fontWeight: '800', color: '#e8e8f0', marginBottom: 20 },
  copyHashBtn:  { backgroundColor: '#1d4ed8', borderRadius: 10, paddingVertical: 12, alignItems: 'center', marginTop: 8, marginBottom: 10 },
  copyHashText: { color: '#fff', fontWeight: '600', fontSize: 14 },
  closeBtn:     { alignItems: 'center', paddingVertical: 14 },
  closeBtnText: { color: '#8888aa', fontSize: 15 },
});
