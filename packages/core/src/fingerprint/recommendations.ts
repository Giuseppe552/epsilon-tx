/**
 * Privacy improvement recommendations based on fingerprint analysis.
 *
 * Each recommendation addresses a specific leakage source with a
 * concrete action and estimated bits saved.
 *
 * The philosophy: don't just score — tell the user what to do.
 * "Switch to P2TR. Randomise input ordering. Use custom fee."
 *
 * Reference: Bitcoin Wiki — Privacy page, "How to improve privacy" section.
 */

import type { TransactionFeatures, WalletFingerprint } from './wallet.js'
import type { TimingAnalysis } from '../entropy/timing.js'

export interface Recommendation {
  source: string
  action: string
  estimatedSavings: number  // bits
  priority: 'high' | 'medium' | 'low'
}

/**
 * Generate privacy improvement recommendations.
 */
export function generateRecommendations(
  fingerprint: WalletFingerprint | null,
  timing: TimingAnalysis | null,
  changeDetectedCount: number,
  correlationCount: number,
  clusterSize: number,
): Recommendation[] {
  const recs: Recommendation[] = []

  if (fingerprint) {
    const f = fingerprint.features

    // BIP-69 ordering → switch to random
    if (f.inputOrdering === 'bip69' || f.outputOrdering === 'bip69') {
      recs.push({
        source: 'wallet-fingerprint',
        action: 'Switch to a wallet with random input/output ordering (Bitcoin Core, Sparrow). BIP-69 lexicographic ordering identifies Electrum.',
        estimatedSavings: 0.8,
        priority: 'high',
      })
    }

    // Mixed script types
    if (f.mixedScriptTypes) {
      recs.push({
        source: 'wallet-fingerprint',
        action: 'Avoid mixing script types in a single transaction. Use one address format consistently (ideally P2TR for maximum anonymity set).',
        estimatedSavings: 0.5,
        priority: 'medium',
      })
    }

    // Not using Taproot
    if (!f.scriptTypes.includes('p2tr')) {
      recs.push({
        source: 'wallet-fingerprint',
        action: 'Upgrade to P2TR (Taproot) addresses (bc1p...). Taproot makes all spend types look identical on-chain — multisig, timelocks, and simple payments all produce the same output script.',
        estimatedSavings: 0.4,
        priority: 'medium',
      })
    }

    // No anti-fee-sniping
    if (!f.hasAntiFeeSniping) {
      recs.push({
        source: 'wallet-fingerprint',
        action: 'Enable anti-fee-sniping (nLockTime = current block height). Bitcoin Core and Sparrow do this by default. It makes your txs indistinguishable from theirs.',
        estimatedSavings: 0.3,
        priority: 'low',
      })
    }

    // Predictable change position
    if (f.changePosition === 'last' || f.changePosition === 'first') {
      recs.push({
        source: 'wallet-fingerprint',
        action: `Change output is always ${f.changePosition}. Use a wallet that randomises change position (Bitcoin Core, Wasabi, Sparrow).`,
        estimatedSavings: 0.4,
        priority: 'medium',
      })
    }

    // Round fee rate
    if (f.feeRateRound) {
      recs.push({
        source: 'wallet-fingerprint',
        action: 'Fee rate is rounded to integer sat/vB (Electrum pattern). Use a wallet with precise fee estimation to blend with Bitcoin Core users.',
        estimatedSavings: 0.2,
        priority: 'low',
      })
    }
  }

  // Change detection
  if (changeDetectedCount > 0) {
    recs.push({
      source: 'amount-analysis',
      action: `Change was identifiable in ${changeDetectedCount} transactions (round payment amounts or script type mismatch). Use CoinJoin or equal-output transactions to increase amount entropy.`,
      estimatedSavings: 0.5,
      priority: 'medium',
    })
  }

  // Amount correlation
  if (correlationCount > 0) {
    recs.push({
      source: 'amount-correlation',
      action: `${correlationCount} near-matching amount pairs detected between incoming and outgoing transactions. Split payments across multiple transactions with different amounts to break the correlation.`,
      estimatedSavings: 0.3 * Math.min(correlationCount, 3),
      priority: correlationCount > 2 ? 'high' : 'medium',
    })
  }

  // Timing
  if (timing) {
    if (timing.isScheduled) {
      recs.push({
        source: 'timing',
        action: 'Transaction timing is non-random (KS test rejected exponential distribution). Add random delays between transactions. Avoid DCA at the same time each week.',
        estimatedSavings: 0.8,
        priority: 'high',
      })
    }

    if (timing.timezoneConfidence > 0.3) {
      recs.push({
        source: 'timing',
        action: `Timezone estimated as UTC${timing.timezoneEstimate >= 0 ? '+' : ''}${timing.timezoneEstimate} (${(timing.timezoneConfidence * 100).toFixed(0)}% confidence). Spread transactions across all hours or use delayed broadcasting to obscure your timezone.`,
        estimatedSavings: timing.timezoneConfidence * 1.0,
        priority: timing.timezoneConfidence > 0.6 ? 'high' : 'medium',
      })
    }

    if (timing.periodicityLags.length > 0) {
      const patterns = timing.periodicityLags.map(l => l.label).join(', ')
      recs.push({
        source: 'timing',
        action: `Detected periodic patterns: ${patterns}. Randomise transaction timing to break the schedule.`,
        estimatedSavings: 0.5,
        priority: 'medium',
      })
    }
  }

  // Cluster size
  if (clusterSize > 5) {
    recs.push({
      source: 'clustering',
      action: `${clusterSize} addresses linked in your co-spend cluster. Avoid using multiple addresses as inputs in the same transaction. Use coin control to keep UTXOs separate.`,
      estimatedSavings: Math.min(Math.log2(clusterSize), 3),
      priority: clusterSize > 20 ? 'high' : 'medium',
    })
  }

  return recs.sort((a, b) => b.estimatedSavings - a.estimatedSavings)
}
