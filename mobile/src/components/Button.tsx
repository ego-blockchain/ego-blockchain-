/**
 * Button — reusable button component for the Ego Mobile Wallet.
 */

import React from 'react';
import { TouchableOpacity, Text, StyleSheet, ActivityIndicator, ViewStyle } from 'react-native';

interface ButtonProps {
  label: string;
  onPress: () => void;
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
  loading?: boolean;
  disabled?: boolean;
  style?: ViewStyle;
  fullWidth?: boolean;
}

export function Button({ label, onPress, variant = 'primary', loading, disabled, style, fullWidth = true }: ButtonProps) {
  const isDisabled = disabled || loading;
  return (
    <TouchableOpacity
      style={[
        s.base,
        s[variant],
        fullWidth && s.fullWidth,
        isDisabled && s.disabled,
        style,
      ]}
      onPress={onPress}
      disabled={isDisabled}
      activeOpacity={0.8}
    >
      {loading
        ? <ActivityIndicator color={variant === 'primary' ? '#fff' : '#3b82f6'} />
        : <Text style={[s.text, s[`text_${variant}` as keyof typeof s]]}>{label}</Text>
      }
    </TouchableOpacity>
  );
}

const s = StyleSheet.create({
  base: {
    paddingVertical: 15, borderRadius: 12, alignItems: 'center', justifyContent: 'center',
  },
  fullWidth:   { width: '100%' },
  disabled:    { opacity: 0.5 },
  primary: {
    backgroundColor: '#1d4ed8',
    shadowColor: '#3b82f6', shadowOpacity: 0.35, shadowRadius: 12, shadowOffset: { width: 0, height: 4 },
  },
  secondary: {
    backgroundColor: '#111118', borderWidth: 1, borderColor: '#2a2a3a',
  },
  ghost: {
    backgroundColor: 'transparent', borderWidth: 1, borderColor: '#2a2a3a',
  },
  danger: {
    backgroundColor: 'rgba(239,68,68,0.12)', borderWidth: 1, borderColor: 'rgba(239,68,68,0.3)',
  },
  text:          { fontSize: 15, fontWeight: '700' },
  text_primary:  { color: '#fff' },
  text_secondary:{ color: '#e8e8f0' },
  text_ghost:    { color: '#8888aa' },
  text_danger:   { color: '#ef4444' },
});
