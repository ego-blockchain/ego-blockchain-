import React, { useState } from 'react';
import {
  View, Text, StyleSheet, TouchableOpacity, TextInput,
  ScrollView, Alert, ActivityIndicator, KeyboardAvoidingView, Platform,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import type { StackNavigationProp } from '@react-navigation/stack';
import type { RootStackParamList } from '../../App';
import { generateKeyPair, keyPairFromSeed, mnemonicToSeed, seedToMnemonic, bytesToHex } from '../lib/crypto';
import { saveWallet } from '../lib/storage';

type Nav = StackNavigationProp<RootStackParamList, 'Welcome'>;

export function WelcomeScreen({ navigation }: { navigation: Nav }) {
  const [mode, setMode]         = useState<'home' | 'create' | 'import'>('home');
  const [mnemonic, setMnemonic] = useState('');
  const [newPhrase, setNewPhrase] = useState<string | null>(null);
  const [loading, setLoading]   = useState(false);

  async function handleCreate() {
    setLoading(true);
    try {
      const kp      = generateKeyPair();
      const phrase  = seedToMnemonic(kp.seed);
      setNewPhrase(phrase);
      await saveWallet({
        address:      kp.address,
        publicKeyHex: bytesToHex(kp.publicKey),
        seedHex:      bytesToHex(kp.seed),
        createdAt:    Math.floor(Date.now() / 1000),
        network:      'testnet',
      });
      setMode('create');
    } catch (e: any) {
      Alert.alert('Error', e.message);
    } finally {
      setLoading(false);
    }
  }

  function handleCreateDone() {
    navigation.replace('MainTabs');
  }

  async function handleImport() {
    const words = mnemonic.trim().split(/\s+/);
    if (words.length !== 24) {
      Alert.alert('Invalid phrase', 'Please enter all 24 recovery words.');
      return;
    }
    setLoading(true);
    try {
      const seed = mnemonicToSeed(mnemonic);
      if (!seed) {
        Alert.alert('Invalid phrase', 'Recovery phrase checksum failed — check every word and their order.');
        return;
      }
      const kp   = keyPairFromSeed(seed);
      await saveWallet({
        address:      kp.address,
        publicKeyHex: bytesToHex(kp.publicKey),
        seedHex:      bytesToHex(kp.seed),
        createdAt:    Math.floor(Date.now() / 1000),
        network:      'testnet',
      });
      navigation.replace('MainTabs');
    } catch (e: any) {
      Alert.alert('Import failed', e.message);
    } finally {
      setLoading(false);
    }
  }

  if (mode === 'home') {
    return (
      <SafeAreaView style={s.safe}>
        <View style={s.center}>
          <View style={s.logoWrap}>
            <Text style={s.logoLetter}>E</Text>
          </View>
          <Text style={s.title}>Ego Wallet</Text>
          <Text style={s.subtitle}>Your gateway to the Ego blockchain</Text>

          <View style={s.featureList}>
            {['Secure Ed25519 key management','Send & receive EGOC','Connect to dApps','Full transaction history'].map(f => (
              <View key={f} style={s.featureRow}>
                <Text style={s.featureDot}>◆</Text>
                <Text style={s.featureText}>{f}</Text>
              </View>
            ))}
          </View>

          <TouchableOpacity style={s.btnPrimary} onPress={handleCreate} disabled={loading}>
            {loading ? <ActivityIndicator color="#fff" /> : <Text style={s.btnPrimaryText}>Create New Wallet</Text>}
          </TouchableOpacity>
          <TouchableOpacity style={s.btnSecondary} onPress={() => setMode('import')}>
            <Text style={s.btnSecondaryText}>Import Existing Wallet</Text>
          </TouchableOpacity>

          <Text style={s.disclaimer}>
            Testnet version — do not use with real assets.
          </Text>
        </View>
      </SafeAreaView>
    );
  }

  if (mode === 'create' && newPhrase) {
    const words = newPhrase.split(' ');
    return (
      <SafeAreaView style={s.safe}>
        <ScrollView contentContainerStyle={s.scrollContent}>
          <Text style={s.pageTitle}>Save Your Recovery Phrase</Text>
          <View style={s.warningBox}>
            <Text style={s.warningText}>
              Write down these 24 words in order and store them safely. This is the ONLY way to recover your wallet.
            </Text>
          </View>
          <View style={s.phraseGrid}>
            {words.map((word, i) => (
              <View key={i} style={s.phraseItem}>
                <Text style={s.phraseNum}>{i + 1}</Text>
                <Text style={s.phraseWord}>{word}</Text>
              </View>
            ))}
          </View>
          <TouchableOpacity style={s.btnPrimary} onPress={handleCreateDone}>
            <Text style={s.btnPrimaryText}>I've Saved My Phrase →</Text>
          </TouchableOpacity>
        </ScrollView>
      </SafeAreaView>
    );
  }

  // ── Import ───────────────────────────────────────────────────────────────

  return (
    <KeyboardAvoidingView behavior={Platform.OS === 'ios' ? 'padding' : undefined} style={{ flex: 1 }}>
      <SafeAreaView style={s.safe}>
        <ScrollView contentContainerStyle={s.scrollContent}>
          <TouchableOpacity onPress={() => setMode('home')} style={s.backBtn}>
            <Text style={s.backBtnText}>← Back</Text>
          </TouchableOpacity>
          <Text style={s.pageTitle}>Import Wallet</Text>
          <Text style={s.pageSubtitle}>Enter your 24-word recovery phrase, separated by spaces.</Text>
          <TextInput
            style={s.phraseInput}
            multiline
            numberOfLines={6}
            placeholder="Enter 24 recovery words..."
            placeholderTextColor="#55556a"
            value={mnemonic}
            onChangeText={setMnemonic}
            autoCapitalize="none"
            autoCorrect={false}
            spellCheck={false}
          />
          <Text style={s.wordCount}>{mnemonic.trim() ? mnemonic.trim().split(/\s+/).length : 0} / 24 words</Text>
          <TouchableOpacity style={s.btnPrimary} onPress={handleImport} disabled={loading}>
            {loading ? <ActivityIndicator color="#fff" /> : <Text style={s.btnPrimaryText}>Import Wallet</Text>}
          </TouchableOpacity>
        </ScrollView>
      </SafeAreaView>
    </KeyboardAvoidingView>
  );
}

const s = StyleSheet.create({
  safe:           { flex: 1, backgroundColor: '#0d0d0d' },
  center:         { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 28 },
  scrollContent:  { padding: 24, paddingBottom: 40 },
  logoWrap: {
    width: 80, height: 80, borderRadius: 20,
    backgroundColor: '#1d4ed8', alignItems: 'center', justifyContent: 'center',
    marginBottom: 20,
    shadowColor: '#3b82f6', shadowOpacity: 0.5, shadowRadius: 20, shadowOffset: { width: 0, height: 4 },
  },
  logoLetter:     { fontSize: 44, fontWeight: '900', color: '#fff' },
  title:          { fontSize: 28, fontWeight: '800', color: '#e8e8f0', marginBottom: 8, letterSpacing: -0.5 },
  subtitle:       { fontSize: 15, color: '#8888aa', marginBottom: 32, textAlign: 'center' },
  featureList:    { width: '100%', marginBottom: 36 },
  featureRow:     { flexDirection: 'row', alignItems: 'center', marginBottom: 10 },
  featureDot:     { fontSize: 10, color: '#3b82f6', marginRight: 10 },
  featureText:    { fontSize: 14, color: '#8888aa' },
  btnPrimary: {
    width: '100%', backgroundColor: '#1d4ed8', paddingVertical: 16, borderRadius: 12,
    alignItems: 'center', marginBottom: 12,
    shadowColor: '#3b82f6', shadowOpacity: 0.4, shadowRadius: 12, shadowOffset: { width: 0, height: 4 },
  },
  btnPrimaryText: { color: '#fff', fontSize: 16, fontWeight: '700' },
  btnSecondary: {
    width: '100%', borderWidth: 1, borderColor: '#2a2a3a', paddingVertical: 16,
    borderRadius: 12, alignItems: 'center', marginBottom: 24,
  },
  btnSecondaryText: { color: '#8888aa', fontSize: 15, fontWeight: '600' },
  disclaimer:     { fontSize: 11, color: '#55556a', textAlign: 'center' },
  backBtn:        { marginBottom: 16 },
  backBtnText:    { color: '#3b82f6', fontSize: 14 },
  pageTitle:      { fontSize: 22, fontWeight: '800', color: '#e8e8f0', marginBottom: 8 },
  pageSubtitle:   { fontSize: 14, color: '#8888aa', marginBottom: 20, lineHeight: 20 },
  warningBox:     { backgroundColor: '#1f1200', borderWidth: 1, borderColor: '#92400e', borderRadius: 10, padding: 14, marginBottom: 20 },
  warningText:    { fontSize: 13, color: '#fbbf24', lineHeight: 18 },
  phraseGrid:     { flexDirection: 'row', flexWrap: 'wrap', gap: 8, marginBottom: 28 },
  phraseItem: {
    width: '30%', flexDirection: 'row', alignItems: 'center', gap: 4,
    backgroundColor: '#111118', borderWidth: 1, borderColor: '#2a2a3a',
    borderRadius: 8, paddingHorizontal: 8, paddingVertical: 8,
  },
  phraseNum:      { fontSize: 10, color: '#55556a', width: 18 },
  phraseWord:     { fontSize: 13, fontWeight: '600', color: '#e8e8f0' },
  phraseInput: {
    backgroundColor: '#111118', borderWidth: 1, borderColor: '#2a2a3a',
    borderRadius: 10, padding: 14, color: '#e8e8f0', fontSize: 14,
    minHeight: 130, textAlignVertical: 'top', marginBottom: 8,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  wordCount:      { fontSize: 12, color: '#55556a', marginBottom: 20, alignSelf: 'flex-end' },
});
