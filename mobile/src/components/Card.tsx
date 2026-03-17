/**
 * Card — container component with Ego dark-theme styling.
 */

import React from 'react';
import { View, StyleSheet, ViewStyle } from 'react-native';

interface CardProps {
  children: React.ReactNode;
  style?: ViewStyle;
  padding?: number;
  noBorder?: boolean;
}

export function Card({ children, style, padding = 16, noBorder = false }: CardProps) {
  return (
    <View style={[s.card, !noBorder && s.border, { padding }, style]}>
      {children}
    </View>
  );
}

const s = StyleSheet.create({
  card: {
    backgroundColor: '#111118',
    borderRadius: 14,
    overflow: 'hidden',
  },
  border: {
    borderWidth: 1,
    borderColor: '#2a2a3a',
  },
});
