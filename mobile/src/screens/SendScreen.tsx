import React, { useState, useRef } from 'react';
import {
  View, Text, StyleSheet, TouchableOpacity, TextInput, Modal,
  ActivityIndicator, Alert, KeyboardAvoidingView, Platform, ScrollView,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { CameraView, useCameraPermissions } from 'expo-camera';
import type { StackNavigationProp } from '@react-navigation/stack';
import type { RootStackParamList } from '../../App';
import { loadWallet } from '../lib/storage';
import { signTransaction, hexToBytes } from '../lib/crypto';
import { sendRawTransaction, getNonce, egocToUEgoc, uEgocToEgoc } from '../lib/rpc';
import { appendTransaction } from '../lib/storage';

type Nav = StackNavigationProp<RootStackParamList, 'Send'>;

const FEE_UEGOC = 1000n;

export function SendScreen({ navigation }: { navigation: Nav }) {
  const [toAddress, setToAddress]   = useState('');
  const [amount, setAmount]         = useState('');
  const [showScanner, setShowScanner] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [sending, setSending]       = useState(false);
  const [txHash, setTxHash]         = useState<string | null>(null);
  const [permission, requestPerm]   = useCameraPermissions();
  const scanned = useRef(false);

  async function openScanner() {
    if (!permission?.granted) {
      const r = await requestPerm();
      if (!r.granted) { Alert.alert('Permission denied', 'Camera permission is required to scan QR codes.'); return; }
    }
    scanned.current = false;
    setShowScanner(true);
  }

  function handleBarCode({ data }: { data: string }) {
    if (scanned.current) return;
    scanned.current = true;
    setShowScanner(false);

    let addr = data;
    let amt  = '';
    if (data.startsWith('ego:')) {
      const url = new URL(data.replace('ego:', 'ego://'));
      addr = (url.hostname || url.pathname).replace(/^\/+/, '');
      amt  = url.searchParams.get('amount') ?? '';
    }
    setToAddress(addr);
    if (amt) setAmount(amt);
  }

  function validate(): string | null {
    if (!toAddress.startsWith('egot1')) return 'Invalid address (must start with egot1)';
    const amtNum = parseFloat(amount);
    if (isNaN(amtNum) || amtNum <= 0) return 'Enter a valid amount';
    return null;
  }

  function openConfirm() {
    const err = validate();
    if (err) { Alert.alert('Invalid input', err); return; }
    setShowConfirm(true);
  }

  async function confirmSend() {
    setSending(true);
    try {
      const wallet = await loadWallet();
      if (!wallet) { Alert.alert('No wallet', 'Wallet not found.'); return; }

      const valueUegoc = egocToUEgoc(amount);
      const nonce      = await getNonce(wallet.address).catch(() => 0);
      const seed       = hexToBytes(wallet.seedHex);

      const signedHex = signTransaction(
        { from: wallet.address, to: toAddress, value: valueUegoc.toString(), nonce },
        seed
      );

      const hash = await sendRawTransaction(signedHex);
      setTxHash(hash);

      await appendTransaction({
        hash,
        from:      wallet.address,
        to:        toAddress,
        value:     valueUegoc.toString(),
        status:    'pending',
        timestamp: Math.floor(Date.now() / 1000),
      });

      setShowConfirm(false);
    } catch (e: any) {
      Alert.alert('Transaction failed', e.message);
    } finally {
      setSending(false);
    }
  }

  if (txHash) {
    return (
      <SafeAreaView style={s.safe}>
        <View style={s.successWrap}>
          <View style={s.successIcon}><Text style={{ fontSize: 36 }}>✓</Text></View>
          <Text style={s.successTitle}>Transaction Sent!</Text>
          <Text style={s.successSubtext}>Your transaction is broadcasting to the network.</Text>
          <View style={s.hashBox}>
            <Text style={s.hashLabel}>Transaction Hash</Text>
            <Text style={s.hashValue} numberOfLines={2}>{txHash}</Text>
          </View>
          <TouchableOpacity style={s.btnPrimary} onPress={() => navigation.goBack()}>
            <Text style={s.btnPrimaryText}>Done</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  const feeStr   = uEgocToEgoc(FEE_UEGOC);
  const totalStr = amount ? uEgocToEgoc(egocToUEgoc(amount) + FEE_UEGOC) : '—';

  return (
    <KeyboardAvoidingView behavior={Platform.OS === 'ios' ? 'padding' : undefined} style={{ flex: 1 }}>
      <SafeAreaView style={s.safe} edges={['bottom']}>
        <ScrollView contentContainerStyle={s.scroll} keyboardShouldPersistTaps="handled">

          <Text style={s.fieldLabel}>Recipient Address</Text>
          <View style={s.addrRow}>
            <TextInput
              style={[s.input, { flex: 1 }]}
              placeholder="egot1…"
              placeholderTextColor="#55556a"
              value={toAddress}
              onChangeText={setToAddress}
              autoCapitalize="none"
              autoCorrect={false}
            />
            <TouchableOpacity style={s.qrBtn} onPress={openScanner}>
              <Text style={s.qrBtnText}>QR</Text>
            </TouchableOpacity>
          </View>

          <Text style={s.fieldLabel}>Amount (EGOC)</Text>
          <TextInput
            style={s.input}
            placeholder="0.000000"
            placeholderTextColor="#55556a"
            value={amount}
            onChangeText={setAmount}
            keyboardType="decimal-pad"
          />

          <View style={s.feeCard}>
            <View style={s.feeRow}>
              <Text style={s.feeLabel}>Network fee</Text>
              <Text style={s.feeValue}>{feeStr} EGOC</Text>
            </View>
            <View style={[s.feeRow, { marginTop: 8, borderTopWidth: 1, borderTopColor: '#2a2a3a', paddingTop: 8 }]}>
              <Text style={[s.feeLabel, { color: '#e8e8f0', fontWeight: '700' }]}>Total</Text>
              <Text style={[s.feeValue, { color: '#e8e8f0', fontWeight: '700' }]}>{totalStr} EGOC</Text>
            </View>
          </View>

          <TouchableOpacity style={s.btnPrimary} onPress={openConfirm}>
            <Text style={s.btnPrimaryText}>Continue →</Text>
          </TouchableOpacity>
        </ScrollView>

        {}
        <Modal visible={showScanner} animationType="slide" onRequestClose={() => setShowScanner(false)}>
          <SafeAreaView style={{ flex: 1, backgroundColor: '#000' }}>
            <CameraView
              style={{ flex: 1 }}
              facing="back"
              onBarcodeScanned={handleBarCode}
              barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
            />
            <TouchableOpacity style={s.closeScannerBtn} onPress={() => setShowScanner(false)}>
              <Text style={s.closeScannerText}>Cancel</Text>
            </TouchableOpacity>
          </SafeAreaView>
        </Modal>

        {}
        <Modal visible={showConfirm} transparent animationType="fade" onRequestClose={() => setShowConfirm(false)}>
          <View style={s.modalOverlay}>
            <View style={s.modal}>
              <Text style={s.modalTitle}>Confirm Transaction</Text>
              <View style={s.confirmDetail}>
                <Text style={s.confirmLabel}>To</Text>
                <Text style={s.confirmValue} numberOfLines={2}>{toAddress}</Text>
              </View>
              <View style={s.confirmDetail}>
                <Text style={s.confirmLabel}>Amount</Text>
                <Text style={[s.confirmValue, { color: '#ef4444', fontSize: 20 }]}>{amount} EGOC</Text>
              </View>
              <View style={s.confirmDetail}>
                <Text style={s.confirmLabel}>Fee</Text>
                <Text style={s.confirmValue}>{feeStr} EGOC</Text>
              </View>
              <View style={[s.confirmDetail, { borderTopWidth: 1, borderTopColor: '#2a2a3a', paddingTop: 12, marginTop: 4 }]}>
                <Text style={[s.confirmLabel, { fontWeight: '700' }]}>Total deducted</Text>
                <Text style={[s.confirmValue, { fontWeight: '700' }]}>{totalStr} EGOC</Text>
              </View>
              <View style={s.modalBtnRow}>
                <TouchableOpacity style={s.btnGhost} onPress={() => setShowConfirm(false)}>
                  <Text style={s.btnGhostText}>Cancel</Text>
                </TouchableOpacity>
                <TouchableOpacity style={[s.btnPrimary, { flex: 1, marginBottom: 0 }]} onPress={confirmSend} disabled={sending}>
                  {sending ? <ActivityIndicator color="#fff" /> : <Text style={s.btnPrimaryText}>Send</Text>}
                </TouchableOpacity>
              </View>
            </View>
          </View>
        </Modal>
      </SafeAreaView>
    </KeyboardAvoidingView>
  );
}

const s = StyleSheet.create({
  safe:         { flex: 1, backgroundColor: '#0d0d0d' },
  scroll:       { padding: 20, paddingBottom: 40 },
  fieldLabel:   { fontSize: 13, fontWeight: '600', color: '#8888aa', marginBottom: 8, marginTop: 4 },
  addrRow:      { flexDirection: 'row', gap: 8, marginBottom: 20 },
  input: {
    backgroundColor: '#111118', borderWidth: 1, borderColor: '#2a2a3a',
    borderRadius: 10, padding: 14, color: '#e8e8f0', fontSize: 15, marginBottom: 20,
  },
  qrBtn: {
    backgroundColor: '#1d4ed8', borderRadius: 10, paddingHorizontal: 16,
    alignItems: 'center', justifyContent: 'center',
  },
  qrBtnText:    { color: '#fff', fontWeight: '700', fontSize: 13 },
  feeCard: {
    backgroundColor: '#111118', borderWidth: 1, borderColor: '#2a2a3a',
    borderRadius: 10, padding: 14, marginBottom: 24,
  },
  feeRow:       { flexDirection: 'row', justifyContent: 'space-between' },
  feeLabel:     { fontSize: 13, color: '#8888aa' },
  feeValue:     { fontSize: 13, color: '#8888aa' },
  btnPrimary: {
    backgroundColor: '#1d4ed8', paddingVertical: 16, borderRadius: 12,
    alignItems: 'center', marginBottom: 12,
    shadowColor: '#3b82f6', shadowOpacity: 0.4, shadowRadius: 12, shadowOffset: { width: 0, height: 4 },
  },
  btnPrimaryText: { color: '#fff', fontSize: 16, fontWeight: '700' },
  closeScannerBtn: {
    position: 'absolute', bottom: 48, alignSelf: 'center',
    backgroundColor: 'rgba(0,0,0,0.7)', paddingVertical: 12, paddingHorizontal: 32, borderRadius: 24,
  },
  closeScannerText: { color: '#fff', fontSize: 16, fontWeight: '600' },
  modalOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.75)', alignItems: 'center', justifyContent: 'center' },
  modal: {
    width: '90%', backgroundColor: '#111118', borderWidth: 1, borderColor: '#2a2a3a',
    borderRadius: 16, padding: 24,
  },
  modalTitle:   { fontSize: 18, fontWeight: '800', color: '#e8e8f0', marginBottom: 20 },
  confirmDetail: { marginBottom: 12 },
  confirmLabel: { fontSize: 12, color: '#8888aa', marginBottom: 2 },
  confirmValue: { fontSize: 15, color: '#e8e8f0', fontFamily: 'monospace' },
  modalBtnRow:  { flexDirection: 'row', gap: 10, marginTop: 20 },
  btnGhost: {
    flex: 1, borderWidth: 1, borderColor: '#2a2a3a', borderRadius: 12,
    paddingVertical: 14, alignItems: 'center',
  },
  btnGhostText: { color: '#8888aa', fontSize: 15, fontWeight: '600' },
  successWrap:  { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 28 },
  successIcon:  { width: 72, height: 72, borderRadius: 36, backgroundColor: '#064e3b', alignItems: 'center', justifyContent: 'center', marginBottom: 20 },
  successTitle: { fontSize: 24, fontWeight: '800', color: '#10b981', marginBottom: 8 },
  successSubtext: { fontSize: 14, color: '#8888aa', marginBottom: 28, textAlign: 'center' },
  hashBox: {
    width: '100%', backgroundColor: '#111118', borderWidth: 1, borderColor: '#2a2a3a',
    borderRadius: 10, padding: 14, marginBottom: 28,
  },
  hashLabel:    { fontSize: 11, color: '#55556a', marginBottom: 6 },
  hashValue:    { fontSize: 13, color: '#3b82f6', fontFamily: 'monospace' },
});
