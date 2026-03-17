/**
 * HomeScreen — main wallet dashboard.
 *
 * Shows: address (tap to copy), EGOC balance, Send/Receive buttons,
 * and a live list of recent transactions fetched from ego-node.
 */

import React, { useCallback, useEffect, useState } from 'react';
import {
  View, Text, StyleSheet, TouchableOpacity, FlatList,
  RefreshControl, ActivityIndicator, Alert,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import * as Clipboard from 'expo-clipboard';
import type { StackNavigationProp } from '@react-navigation/stack';
import type { RootStackParamList } from '../../App';
import { loadWallet, type StoredWallet, type StoredTransaction, loadLocalTransactions } from '../lib/storage';
import { getBalance, getTransactions, uEgocToEgoc, type RpcTransaction } from '../lib/rpc';

type Nav = StackNavigationProp<RootStackParamList, 'MainTabs'>;

function mergeTransactions(remote: RpcTransaction[], local: StoredTransaction[]): RpcTransaction[] {
  const seen = new Set(remote.map(t => t.hash));
  const extra = local
    .filter(t => !seen.has(t.hash))
    .map(t => ({
      hash: t.hash, from: t.from, to: t.to,
      value: t.value, data: '', nonce: 0,
      status: t.status as any, blockHash: '', timestamp: t.timestamp,
    } as RpcTransaction));
  return [...remote, ...extra].sort((a, b) => b.timestamp - a.timestamp);
}

export function HomeScreen({ navigation }: { navigation: Nav }) {
  const [wallet, setWallet]         = useState<StoredWallet | null>(null);
  const [balance, setBalance]       = useState<bigint>(0n);
  const [txs, setTxs]               = useState<RpcTransaction[]>([]);
  const [loading, setLoading]       = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [copied, setCopied]         = useState(false);

  async function loadData(showSpinner = true) {
    if (showSpinner) setLoading(true);
    try {
      const w = await loadWallet();
      if (!w) { navigation.replace('Welcome'); return; }
      setWallet(w);

      const [bal, remoteTxs, localTxs] = await Promise.allSettled([
        getBalance(w.address),
        getTransactions(w.address, 30),
        loadLocalTransactions(),
      ]);

      if (bal.status === 'fulfilled') setBalance(bal.value);
      const rt = remoteTxs.status === 'fulfilled' ? remoteTxs.value : [];
      const lt = localTxs.status === 'fulfilled'  ? localTxs.value  : [];
      setTxs(mergeTransactions(rt, lt));
    } catch (e: any) {
      console.warn('HomeScreen load error:', e.message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => { loadData(); }, []);

  const onRefresh = useCallback(() => {
    setRefreshing(true);
    loadData(false);
  }, []);

  async function copyAddress() {
    if (!wallet) return;
    await Clipboard.setStringAsync(wallet.address);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  // ── Render helpers ───────────────────────────────────────────────────────

  function TxItem({ item }: { item: RpcTransaction }) {
    const isOut = wallet && item.from === wallet.address;
    const other  = isOut ? item.to : item.from;
    const shortOther = other.length > 14 ? other.slice(0, 8) + '…' + other.slice(-5) : other;
    const valueEgoc  = uEgocToEgoc(BigInt(item.value));
    const date       = new Date(item.timestamp * 1000);
    const dateStr    = date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });

    const statusColor = item.status === 'confirmed' ? '#10b981' : item.status === 'failed' ? '#ef4444' : '#f59e0b';

    return (
      <View style={s.txRow}>
        <View style={[s.txIcon, { backgroundColor: isOut ? '#1a1030' : '#0d1f14' }]}>
          <Text style={{ fontSize: 16 }}>{isOut ? '↑' : '↓'}</Text>
        </View>
        <View style={s.txInfo}>
          <Text style={s.txType}>{isOut ? 'Sent' : 'Received'}</Text>
          <Text style={s.txAddr}>{shortOther}</Text>
        </View>
        <View style={s.txRight}>
          <Text style={[s.txValue, { color: isOut ? '#ef4444' : '#10b981' }]}>
            {isOut ? '−' : '+'}{valueEgoc} EGOC
          </Text>
          <View style={s.txMeta}>
            <Text style={[s.txStatus, { color: statusColor }]}>
              {item.status === 'confirmed' ? '✓' : item.status === 'failed' ? '✗' : '⏳'}
            </Text>
            <Text style={s.txDate}>{dateStr}</Text>
          </View>
        </View>
      </View>
    );
  }

  if (loading) {
    return (
      <SafeAreaView style={s.safe}>
        <View style={s.center}>
          <ActivityIndicator color="#3b82f6" size="large" />
        </View>
      </SafeAreaView>
    );
  }

  const egocStr    = uEgocToEgoc(balance);
  const shortAddr  = wallet ? wallet.address.slice(0, 10) + '…' + wallet.address.slice(-6) : '';

  return (
    <SafeAreaView style={s.safe}>
      <FlatList
        data={txs}
        keyExtractor={item => item.hash}
        renderItem={({ item }) => <TxItem item={item} />}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor="#3b82f6" />}
        ListHeaderComponent={
          <View style={s.header}>
            {/* Address bar */}
            <TouchableOpacity style={s.addressBar} onPress={copyAddress} activeOpacity={0.7}>
              <Text style={s.addressText}>{shortAddr}</Text>
              <Text style={s.copyBtn}>{copied ? '✓ Copied' : 'Copy'}</Text>
            </TouchableOpacity>

            {/* Balance card */}
            <View style={s.balanceCard}>
              <Text style={s.balanceLabel}>Total Balance</Text>
              <Text style={s.balanceValue}>{egocStr}</Text>
              <Text style={s.balanceCurrency}>EGOC</Text>
              <Text style={s.networkBadge}>Testnet</Text>
            </View>

            {/* Action buttons */}
            <View style={s.actionRow}>
              <TouchableOpacity style={s.actionBtn} onPress={() => navigation.navigate('Send')}>
                <Text style={s.actionIcon}>↑</Text>
                <Text style={s.actionLabel}>Send</Text>
              </TouchableOpacity>
              <TouchableOpacity style={s.actionBtn} onPress={() => navigation.navigate('Receive')}>
                <Text style={s.actionIcon}>↓</Text>
                <Text style={s.actionLabel}>Receive</Text>
              </TouchableOpacity>
            </View>

            {/* Tx list header */}
            <View style={s.sectionHead}>
              <Text style={s.sectionTitle}>Recent Transactions</Text>
              <Text style={s.sectionCount}>{txs.length}</Text>
            </View>
          </View>
        }
        ListEmptyComponent={
          <View style={s.emptyWrap}>
            <Text style={s.emptyIcon}>📭</Text>
            <Text style={s.emptyText}>No transactions yet</Text>
            <Text style={s.emptySubtext}>Send or receive EGOC to get started</Text>
          </View>
        }
        contentContainerStyle={s.listContent}
      />
    </SafeAreaView>
  );
}

const s = StyleSheet.create({
  safe:         { flex: 1, backgroundColor: '#0d0d0d' },
  center:       { flex: 1, alignItems: 'center', justifyContent: 'center' },
  listContent:  { paddingBottom: 40 },

  header:       { padding: 20 },

  addressBar: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between',
    backgroundColor: '#111118', borderWidth: 1, borderColor: '#2a2a3a',
    borderRadius: 10, paddingHorizontal: 14, paddingVertical: 10, marginBottom: 16,
  },
  addressText:  { fontSize: 13, color: '#8888aa', fontFamily: 'monospace', flex: 1 },
  copyBtn:      { fontSize: 12, color: '#3b82f6', fontWeight: '600' },

  balanceCard: {
    backgroundColor: '#111118', borderWidth: 1, borderColor: '#2a2a3a',
    borderRadius: 16, padding: 24, alignItems: 'center', marginBottom: 20,
    shadowColor: '#3b82f6', shadowOpacity: 0.06, shadowRadius: 20, shadowOffset: { width: 0, height: 4 },
  },
  balanceLabel:   { fontSize: 12, color: '#8888aa', textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 8 },
  balanceValue:   { fontSize: 40, fontWeight: '800', color: '#e8e8f0', letterSpacing: -1 },
  balanceCurrency: { fontSize: 16, color: '#3b82f6', fontWeight: '600', marginTop: 2 },
  networkBadge: {
    marginTop: 10, fontSize: 11, color: '#f59e0b', backgroundColor: 'rgba(245,158,11,0.1)',
    borderWidth: 1, borderColor: 'rgba(245,158,11,0.2)', borderRadius: 20,
    paddingHorizontal: 10, paddingVertical: 2,
  },

  actionRow: { flexDirection: 'row', gap: 12, marginBottom: 24 },
  actionBtn: {
    flex: 1, backgroundColor: '#111118', borderWidth: 1, borderColor: '#2a2a3a',
    borderRadius: 12, paddingVertical: 18, alignItems: 'center',
  },
  actionIcon:   { fontSize: 22, color: '#3b82f6', marginBottom: 4 },
  actionLabel:  { fontSize: 13, fontWeight: '600', color: '#e8e8f0' },

  sectionHead: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 },
  sectionTitle: { fontSize: 16, fontWeight: '700', color: '#e8e8f0' },
  sectionCount: { fontSize: 12, color: '#55556a', backgroundColor: '#111118', borderRadius: 20, paddingHorizontal: 8, paddingVertical: 2 },

  txRow: {
    flexDirection: 'row', alignItems: 'center', gap: 12,
    paddingHorizontal: 20, paddingVertical: 14,
    borderBottomWidth: 1, borderBottomColor: '#1a1a24',
  },
  txIcon: { width: 40, height: 40, borderRadius: 20, alignItems: 'center', justifyContent: 'center' },
  txInfo: { flex: 1 },
  txType: { fontSize: 14, fontWeight: '600', color: '#e8e8f0', marginBottom: 2 },
  txAddr: { fontSize: 12, color: '#55556a', fontFamily: 'monospace' },
  txRight: { alignItems: 'flex-end' },
  txValue: { fontSize: 14, fontWeight: '700', marginBottom: 3 },
  txMeta: { flexDirection: 'row', gap: 6, alignItems: 'center' },
  txStatus: { fontSize: 11 },
  txDate: { fontSize: 11, color: '#55556a' },

  emptyWrap: { alignItems: 'center', paddingVertical: 60 },
  emptyIcon: { fontSize: 40, marginBottom: 12 },
  emptyText: { fontSize: 16, fontWeight: '600', color: '#8888aa', marginBottom: 4 },
  emptySubtext: { fontSize: 13, color: '#55556a' },
});
