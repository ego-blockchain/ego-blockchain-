/**
 * TokenAmount — displays a formatted EGOC amount with optional USD equivalent.
 */

import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { uEgocToEgoc } from '../lib/rpc';

interface TokenAmountProps {
  /** Amount in uEGOC (as bigint or decimal string). */
  uEgoc: bigint | string;
  /** Display size: 'sm' | 'md' | 'lg' | 'xl' */
  size?: 'sm' | 'md' | 'lg' | 'xl';
  /** Colour hint for positive/negative display. */
  direction?: 'in' | 'out' | 'neutral';
  /** Show unit label ("EGOC"). Default true. */
  showUnit?: boolean;
  /** Optional USD price per EGOC for fiat conversion. */
  egocUsdPrice?: number;
}

const SIZE_MAP = { sm: 13, md: 16, lg: 22, xl: 36 };
const UNIT_MAP = { sm: 11, md: 13, lg: 16, xl: 20 };

const DIRECTION_COLOR = {
  in:      '#10b981',
  out:     '#ef4444',
  neutral: '#e8e8f0',
};

export function TokenAmount({
  uEgoc, size = 'md', direction = 'neutral', showUnit = true, egocUsdPrice,
}: TokenAmountProps) {
  const value = typeof uEgoc === 'string' ? BigInt(uEgoc) : uEgoc;
  const egocStr = uEgocToEgoc(value);
  const color   = DIRECTION_COLOR[direction];
  const prefix  = direction === 'in' ? '+' : direction === 'out' ? '−' : '';

  const usdStr = egocUsdPrice
    ? (parseFloat(egocStr) * egocUsdPrice).toLocaleString('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: 2 })
    : null;

  return (
    <View style={s.wrap}>
      <View style={s.row}>
        {prefix ? <Text style={[s.amount, { fontSize: SIZE_MAP[size], color }]}>{prefix}</Text> : null}
        <Text style={[s.amount, { fontSize: SIZE_MAP[size], color }]}>
          {egocStr}
        </Text>
        {showUnit && (
          <Text style={[s.unit, { fontSize: UNIT_MAP[size] }]}> EGOC</Text>
        )}
      </View>
      {usdStr && (
        <Text style={s.usd}>{usdStr}</Text>
      )}
    </View>
  );
}

const s = StyleSheet.create({
  wrap: { alignItems: 'flex-start' },
  row:  { flexDirection: 'row', alignItems: 'baseline' },
  amount: {
    fontWeight: '700',
    letterSpacing: -0.5,
    fontVariant: ['tabular-nums'],
  },
  unit: {
    color: '#8888aa',
    fontWeight: '500',
  },
  usd: {
    fontSize: 12,
    color: '#55556a',
    marginTop: 2,
  },
});
