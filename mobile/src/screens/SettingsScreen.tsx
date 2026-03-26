import React, { useEffect, useState } from 'react';
import {
  View, Text, StyleSheet, TouchableOpacity, Switch,
  Alert, Modal, ScrollView, TextInput, ActivityIndicator,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import * as Clipboard from 'expo-clipboard';
import type { StackNavigationProp } from '@react-navigation/stack';
import type { RootStackParamList } from '../../App';
import { loadWallet, saveSettings, loadSettings, deleteWallet, type StoredWallet, type StoredSettings } from '../lib/storage';
import { hexToBytes, seedToMnemonic } from '../lib/crypto';
import { setRpcUrl } from '../lib/rpc';

type Nav = StackNavigationProp<RootStackParamList>;

export function SettingsScreen({ navigation }: { navigation: Nav }) {
  const [wallet, setWallet]       = useState<StoredWallet | null>(null);
  const [settings, setSettings]   = useState<StoredSettings | null>(null);
  const [showPhrase, setShowPhrase] = useState(false);
  const [phrase, setPhrase]       = useState<string[]>([]);
  const [pinInput, setPinInput]   = useState('');
  const [showPinModal, setShowPinModal] = useState(false);
  const [pinTarget, setPinTarget] = useState<'reveal' | 'lock'>('reveal');
  const [copied, setCopied]       = useState(false);
  const [loading, setLoading]     = useState(true);

  useEffect(() => {
    Promise.all([loadWallet(), loadSettings()]).then(([w, s]) => {
      setWallet(w); setSettings(s); setLoading(false);
    });
  }, []);

  async function toggleNetwork(isMainnet: boolean) {
    const network = isMainnet ? 'mainnet' : 'testnet';
    const url     = isMainnet ? 'http://127.0.0.1:8545' : 'http://127.0.0.1:8545';
    await saveSettings({ network, rpcUrl: url });
    setRpcUrl(url);
    setSettings(prev => prev ? { ...prev, network } : prev);
  }

  function promptRevealPhrase() {
    setPinTarget('reveal');
    setShowPinModal(true);
  }

  function handlePinConfirm() {

    setShowPinModal(false);
    setPinInput('');
    if (pinTarget === 'reveal') {
      if (!wallet) return;
      const seed    = hexToBytes(wallet.seedHex);
      const mnemonic = seedToMnemonic(seed);
      setPhrase(mnemonic.split(' '));
      setShowPhrase(true);
    } else {
      handleLock();
    }
  }

  async function handleLock() {
    Alert.alert('Lock Wallet', 'This will remove your wallet from this device. Make sure you have your recovery phrase saved.', [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Lock', style: 'destructive',
        onPress: async () => {
          await deleteWallet();
          navigation.replace('Welcome');
        },
      },
    ]);
  }

  async function copyPhrase() {
    await Clipboard.setStringAsync(phrase.join(' '));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function SettingRow({
    icon, title, subtitle, onPress, right, danger = false,
  }: { icon: string; title: string; subtitle?: string; onPress?: () => void; right?: React.ReactNode; danger?: boolean }) {
    return (
      <TouchableOpacity style={s.row} onPress={onPress} disabled={!onPress} activeOpacity={onPress ? 0.7 : 1}>
        <View style={[s.rowIcon, danger && { backgroundColor: '#1f0a0a' }]}>
          <Text style={{ fontSize: 18 }}>{icon}</Text>
        </View>
        <View style={s.rowInfo}>
          <Text style={[s.rowTitle, danger && { color: '#ef4444' }]}>{title}</Text>
          {subtitle && <Text style={s.rowSub}>{subtitle}</Text>}
        </View>
        {right ?? (onPress && <Text style={s.rowArrow}>›</Text>)}
      </TouchableOpacity>
    );
  }

  if (loading || !settings) {
    return (
      <SafeAreaView style={s.safe}>
        <View style={s.center}><ActivityIndicator color="#3b82f6" /></View>
      </SafeAreaView>
    );
  }

  const isMainnet = settings.network === 'mainnet';
  const shortAddr = wallet ? wallet.address.slice(0, 10) + '…' + wallet.address.slice(-6) : '—';

  return (
    <SafeAreaView style={s.safe}>
      <ScrollView contentContainerStyle={s.scroll}>
        <Text style={s.pageTitle}>Settings</Text>

        {}
        <View style={s.section}>
          <View style={s.walletCard}>
            <View style={s.walletIcon}><Text style={{ fontSize: 22 }}>👛</Text></View>
            <View style={{ flex: 1 }}>
              <Text style={s.walletLabel}>Connected Wallet</Text>
              <Text style={s.walletAddr}>{shortAddr}</Text>
            </View>
            <View style={[s.networkBadge, isMainnet && { borderColor: '#10b981', backgroundColor: '#0d1f14' }]}>
              <Text style={[s.networkBadgeText, isMainnet && { color: '#10b981' }]}>
                {isMainnet ? 'Mainnet' : 'Testnet'}
              </Text>
            </View>
          </View>
        </View>

        {}
        <Text style={s.sectionLabel}>Security</Text>
        <View style={s.section}>
          <SettingRow
            icon="🔑"
            title="Recovery Phrase"
            subtitle="View your 24-word backup phrase"
            onPress={promptRevealPhrase}
          />
          <View style={s.divider} />
          <SettingRow
            icon="🔒"
            title="Lock Wallet"
            subtitle="Remove wallet from this device"
            onPress={handleLock}
            danger
          />
        </View>

        {}
        <Text style={s.sectionLabel}>Network</Text>
        <View style={s.section}>
          <SettingRow
            icon="🌐"
            title="Mainnet"
            subtitle="Switch between testnet and mainnet"
            right={
              <Switch
                value={isMainnet}
                onValueChange={toggleNetwork}
                trackColor={{ false: '#2a2a3a', true: '#1d4ed8' }}
                thumbColor={isMainnet ? '#3b82f6' : '#55556a'}
              />
            }
          />
          <View style={s.divider} />
          <SettingRow
            icon="🔗"
            title="RPC Endpoint"
            subtitle={settings.rpcUrl}
          />
        </View>

        {}
        <Text style={s.sectionLabel}>About</Text>
        <View style={s.section}>
          <SettingRow icon="ℹ️" title="Version"    subtitle="1.0.0 (testnet)" />
          <View style={s.divider} />
          <SettingRow icon="📄" title="EGO-25 WalletConnect" subtitle="sdk/walletconnect" />
          <View style={s.divider} />
          <SettingRow icon="⛓" title="Chain ID"  subtitle="1 (Ego Testnet)" />
        </View>

      </ScrollView>

      {}
      <Modal visible={showPinModal} transparent animationType="fade" onRequestClose={() => setShowPinModal(false)}>
        <View style={s.modalOverlay}>
          <View style={s.modal}>
            <Text style={s.modalTitle}>Confirm Identity</Text>
            <Text style={s.modalSubtitle}>Enter your PIN or leave blank to continue</Text>
            <TextInput
              style={s.pinInput}
              placeholder="PIN (optional)"
              placeholderTextColor="#55556a"
              value={pinInput}
              onChangeText={setPinInput}
              secureTextEntry
              keyboardType="numeric"
              maxLength={8}
            />
            <View style={s.modalBtnRow}>
              <TouchableOpacity style={s.btnGhost} onPress={() => { setShowPinModal(false); setPinInput(''); }}>
                <Text style={s.btnGhostText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity style={s.btnPrimary} onPress={handlePinConfirm}>
                <Text style={s.btnPrimaryText}>Continue</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>

      {}
      <Modal visible={showPhrase} transparent animationType="slide" onRequestClose={() => setShowPhrase(false)}>
        <View style={s.phraseOverlay}>
          <View style={s.phraseModal}>
            <Text style={s.phraseTitle}>Your Recovery Phrase</Text>
            <View style={s.warningBox}>
              <Text style={s.warningText}>Never share this with anyone. Store it offline securely.</Text>
            </View>
            <View style={s.phraseGrid}>
              {phrase.map((word, i) => (
                <View key={i} style={s.phraseItem}>
                  <Text style={s.phraseNum}>{i + 1}</Text>
                  <Text style={s.phraseWord}>{word}</Text>
                </View>
              ))}
            </View>
            <TouchableOpacity style={s.copyPhraseBtn} onPress={copyPhrase}>
              <Text style={s.copyPhraseBtnText}>{copied ? '✓ Copied!' : 'Copy to clipboard'}</Text>
            </TouchableOpacity>
            <TouchableOpacity style={s.closeBtn} onPress={() => setShowPhrase(false)}>
              <Text style={s.closeBtnText}>Done</Text>
            </TouchableOpacity>
          </View>
        </View>
      </Modal>
    </SafeAreaView>
  );
}

const s = StyleSheet.create({
  safe:         { flex: 1, backgroundColor: '#0d0d0d' },
  center:       { flex: 1, alignItems: 'center', justifyContent: 'center' },
  scroll:       { padding: 20, paddingBottom: 40 },
  pageTitle:    { fontSize: 22, fontWeight: '800', color: '#e8e8f0', marginBottom: 20 },
  sectionLabel: { fontSize: 11, fontWeight: '600', color: '#55556a', textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 8, marginLeft: 4 },
  section: {
    backgroundColor: '#111118', borderWidth: 1, borderColor: '#2a2a3a',
    borderRadius: 14, marginBottom: 24, overflow: 'hidden',
  },
  walletCard: {
    flexDirection: 'row', alignItems: 'center', gap: 12, padding: 16,
  },
  walletIcon: { width: 44, height: 44, borderRadius: 22, backgroundColor: '#1a1a28', alignItems: 'center', justifyContent: 'center' },
  walletLabel: { fontSize: 11, color: '#55556a', marginBottom: 2 },
  walletAddr:  { fontSize: 13, color: '#e8e8f0', fontFamily: 'monospace' },
  networkBadge: { paddingHorizontal: 10, paddingVertical: 4, borderRadius: 20, borderWidth: 1, borderColor: '#f59e0b', backgroundColor: 'rgba(245,158,11,0.08)' },
  networkBadgeText: { fontSize: 11, fontWeight: '600', color: '#f59e0b' },
  row:       { flexDirection: 'row', alignItems: 'center', padding: 16, gap: 12 },
  rowIcon:   { width: 38, height: 38, borderRadius: 10, backgroundColor: '#1a1a28', alignItems: 'center', justifyContent: 'center' },
  rowInfo:   { flex: 1 },
  rowTitle:  { fontSize: 14, fontWeight: '600', color: '#e8e8f0', marginBottom: 1 },
  rowSub:    { fontSize: 12, color: '#55556a' },
  rowArrow:  { fontSize: 20, color: '#3d3d50' },
  divider:   { height: 1, backgroundColor: '#1a1a24', marginLeft: 64 },
  modalOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.75)', alignItems: 'center', justifyContent: 'center' },
  modal: {
    width: '85%', backgroundColor: '#111118', borderWidth: 1, borderColor: '#2a2a3a',
    borderRadius: 16, padding: 24,
  },
  modalTitle:    { fontSize: 18, fontWeight: '800', color: '#e8e8f0', marginBottom: 6 },
  modalSubtitle: { fontSize: 13, color: '#8888aa', marginBottom: 18 },
  pinInput: {
    backgroundColor: '#0d0d0d', borderWidth: 1, borderColor: '#2a2a3a',
    borderRadius: 10, padding: 14, color: '#e8e8f0', fontSize: 18,
    textAlign: 'center', letterSpacing: 4, marginBottom: 20,
  },
  modalBtnRow: { flexDirection: 'row', gap: 10 },
  btnGhost: { flex: 1, borderWidth: 1, borderColor: '#2a2a3a', borderRadius: 10, paddingVertical: 14, alignItems: 'center' },
  btnGhostText: { color: '#8888aa', fontWeight: '600' },
  btnPrimary: { flex: 1, backgroundColor: '#1d4ed8', borderRadius: 10, paddingVertical: 14, alignItems: 'center' },
  btnPrimaryText: { color: '#fff', fontWeight: '700' },
  phraseOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.85)', justifyContent: 'flex-end' },
  phraseModal: {
    backgroundColor: '#111118', borderTopLeftRadius: 20, borderTopRightRadius: 20,
    borderWidth: 1, borderBottomWidth: 0, borderColor: '#2a2a3a', padding: 24, paddingBottom: 50,
  },
  phraseTitle: { fontSize: 18, fontWeight: '800', color: '#e8e8f0', marginBottom: 14 },
  warningBox:  { backgroundColor: '#1f1200', borderWidth: 1, borderColor: '#92400e', borderRadius: 8, padding: 10, marginBottom: 16 },
  warningText: { fontSize: 12, color: '#fbbf24', lineHeight: 16 },
  phraseGrid:  { flexDirection: 'row', flexWrap: 'wrap', gap: 6, marginBottom: 20 },
  phraseItem: {
    width: '30%', flexDirection: 'row', alignItems: 'center', gap: 4,
    backgroundColor: '#0d0d0d', borderWidth: 1, borderColor: '#2a2a3a',
    borderRadius: 6, paddingHorizontal: 6, paddingVertical: 6,
  },
  phraseNum:  { fontSize: 9, color: '#55556a', width: 14 },
  phraseWord: { fontSize: 12, fontWeight: '600', color: '#e8e8f0' },
  copyPhraseBtn: { backgroundColor: '#1d4ed8', borderRadius: 10, paddingVertical: 12, alignItems: 'center', marginBottom: 10 },
  copyPhraseBtnText: { color: '#fff', fontWeight: '700' },
  closeBtn: { alignItems: 'center', paddingVertical: 10 },
  closeBtnText: { color: '#8888aa', fontSize: 15 },
});
