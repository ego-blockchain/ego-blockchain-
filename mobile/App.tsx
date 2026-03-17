/**
 * Ego Mobile Wallet — Root Navigator
 *
 * Stack structure:
 *   WelcomeScreen  (no wallet found)
 *     └─> CreateWalletScreen / ImportWalletScreen
 *   MainTabs  (wallet loaded)
 *     ├── HomeScreen
 *     ├── HistoryScreen
 *     └── SettingsScreen
 *   Modal screens pushed from MainTabs:
 *     SendScreen, ReceiveScreen
 */

import React, { useEffect, useState } from 'react';
import { NavigationContainer, DefaultTheme } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { StatusBar } from 'expo-status-bar';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { GestureHandlerRootView } from 'react-native-gesture-handler';
import { View, Text, StyleSheet, ActivityIndicator } from 'react-native';

import { WelcomeScreen }  from './src/screens/WelcomeScreen';
import { HomeScreen }     from './src/screens/HomeScreen';
import { SendScreen }     from './src/screens/SendScreen';
import { ReceiveScreen }  from './src/screens/ReceiveScreen';
import { HistoryScreen }  from './src/screens/HistoryScreen';
import { SettingsScreen } from './src/screens/SettingsScreen';
import { loadWallet }     from './src/lib/storage';

// ── Types ──────────────────────────────────────────────────────────────────

export type RootStackParamList = {
  Welcome:  undefined;
  MainTabs: undefined;
  Send:     undefined;
  Receive:  undefined;
};

export type TabParamList = {
  Home:     undefined;
  History:  undefined;
  Settings: undefined;
};

// ── Theme ──────────────────────────────────────────────────────────────────

const EgoDarkTheme = {
  ...DefaultTheme,
  colors: {
    ...DefaultTheme.colors,
    background:   '#0d0d0d',
    card:         '#111118',
    text:         '#e8e8f0',
    border:       '#2a2a3a',
    notification: '#3b82f6',
    primary:      '#3b82f6',
  },
};

// ── Navigators ─────────────────────────────────────────────────────────────

const Stack = createStackNavigator<RootStackParamList>();
const Tab   = createBottomTabNavigator<TabParamList>();

function TabIcon({ name, focused }: { name: string; focused: boolean }) {
  const icons: Record<string, string> = { Home: '⬡', History: '⏱', Settings: '⚙' };
  return (
    <Text style={{ fontSize: 18, color: focused ? '#3b82f6' : '#55556a' }}>
      {icons[name] ?? '●'}
    </Text>
  );
}

function MainTabs() {
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        headerShown: false,
        tabBarStyle: {
          backgroundColor: '#111118',
          borderTopColor:  '#2a2a3a',
          borderTopWidth:  1,
          height:          60,
          paddingBottom:   8,
        },
        tabBarActiveTintColor:   '#3b82f6',
        tabBarInactiveTintColor: '#55556a',
        tabBarLabelStyle: { fontSize: 11, fontWeight: '500' },
        tabBarIcon: ({ focused }) => <TabIcon name={route.name} focused={focused} />,
      })}
    >
      <Tab.Screen name="Home"     component={HomeScreen}     options={{ title: 'Wallet' }} />
      <Tab.Screen name="History"  component={HistoryScreen}  options={{ title: 'History' }} />
      <Tab.Screen name="Settings" component={SettingsScreen} options={{ title: 'Settings' }} />
    </Tab.Navigator>
  );
}

// ── Root ───────────────────────────────────────────────────────────────────

export default function App() {
  const [loading, setLoading]       = useState(true);
  const [hasWallet, setHasWallet]   = useState(false);

  useEffect(() => {
    loadWallet()
      .then(w => setHasWallet(!!w?.address))
      .catch(() => setHasWallet(false))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <View style={styles.splash}>
        <Text style={styles.splashLogo}>E</Text>
        <Text style={styles.splashName}>Ego Wallet</Text>
        <ActivityIndicator color="#3b82f6" style={{ marginTop: 32 }} />
      </View>
    );
  }

  return (
    <GestureHandlerRootView style={{ flex: 1 }}>
      <SafeAreaProvider>
        <StatusBar style="light" />
        <NavigationContainer theme={EgoDarkTheme}>
          <Stack.Navigator
            initialRouteName={hasWallet ? 'MainTabs' : 'Welcome'}
            screenOptions={{
              headerShown: false,
              cardStyle:   { backgroundColor: '#0d0d0d' },
            }}
          >
            <Stack.Screen name="Welcome"  component={WelcomeScreen}  />
            <Stack.Screen name="MainTabs" component={MainTabs}        />
            <Stack.Screen
              name="Send"
              component={SendScreen}
              options={{ headerShown: true, headerTitle: 'Send EGOC', headerStyle: { backgroundColor: '#111118' }, headerTintColor: '#e8e8f0' }}
            />
            <Stack.Screen
              name="Receive"
              component={ReceiveScreen}
              options={{ headerShown: true, headerTitle: 'Receive EGOC', headerStyle: { backgroundColor: '#111118' }, headerTintColor: '#e8e8f0' }}
            />
          </Stack.Navigator>
        </NavigationContainer>
      </SafeAreaProvider>
    </GestureHandlerRootView>
  );
}

const styles = StyleSheet.create({
  splash: {
    flex: 1,
    backgroundColor: '#0d0d0d',
    alignItems: 'center',
    justifyContent: 'center',
  },
  splashLogo: {
    width: 72,
    height: 72,
    borderRadius: 18,
    backgroundColor: '#1d4ed8',
    textAlign: 'center',
    lineHeight: 72,
    fontSize: 40,
    fontWeight: '900',
    color: '#fff',
    overflow: 'hidden',
  },
  splashName: {
    fontSize: 24,
    fontWeight: '700',
    color: '#e8e8f0',
    marginTop: 16,
    letterSpacing: -0.5,
  },
});
