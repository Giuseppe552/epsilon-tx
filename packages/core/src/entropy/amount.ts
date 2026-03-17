/**
 * Amount-based privacy analysis.
 *
 * Reference: Bitcoin Wiki — Privacy page, "Amount correlation" section.
 * Reference: Androulaki et al. (2013). "Evaluating User Privacy in Bitcoin."
 *            Financial Cryptography. §4 — change address heuristics.
 *
 * Transaction amounts leak information in several ways:
 *
 * 1. Unique amounts: if you send exactly 0.03471892 BTC, that amount
 *    is likely unique on the chain. An adversary searching for it
 *    finds your transaction instantly.
 *
 * 2. Round amounts: payments to humans are often round numbers
 *    (0.1 BTC, 0.01 BTC). Change is the odd remainder. This
 *    identifies which output is the payment and which is change.
 *
 * 3. Amount correlation across transactions: if you receive 1.5 BTC
 *    and later send 1.4998 BTC, the near-match links the two txs.
 *
 * We measure all three as information leakage in bits.
 *
 * Reference: Bitcoin Wiki Privacy page — Amount correlation section.
 */

import { shannonEntropy, binaryEntropy } from './shannon.js'
import type { Transaction } from '../graph/cospend.js'

/**
 * Compute the amount entropy of a transaction's outputs.
 *
 * For a 2-output transaction where one output is clearly the payment
 * and one is change: H ≈ 0 bits (the adversary knows which is which).
 *
 * For a CoinJoin with k equal-value outputs: H = log₂(k) bits (the
 * adversary can't distinguish them).
 *
 * @param tx - The transaction to analyse
 * @returns Amount entropy in bits + explanation
 */
export function amountEntropy(tx: Transaction): {
  entropy: number
  changeDetected: boolean
  explanation: string
} {
  if (tx.outputs.length === 0) {
    return { entropy: 0, changeDetected: false, explanation: 'no outputs' }
  }

  if (tx.outputs.length === 1) {
    return { entropy: 0, changeDetected: false, explanation: 'single output — no ambiguity' }
  }

  // Check for equal-value outputs (CoinJoin pattern)
  const values = tx.outputs.map(o => o.value)
  const valueCounts = new Map<number, number>()
  for (const v of values) {
    valueCounts.set(v, (valueCounts.get(v) ?? 0) + 1)
  }

  const maxEqualCount = Math.max(...valueCounts.values())
  if (maxEqualCount >= 3) {
    // CoinJoin-like: multiple equal outputs
    const entropy = Math.log2(maxEqualCount)
    return {
      entropy,
      changeDetected: false,
      explanation: `${maxEqualCount} equal-value outputs (${maxEqualCount === values.length ? 'perfect' : 'partial'} CoinJoin). Entropy: ${entropy.toFixed(2)} bits.`,
    }
  }

  // 2-output transaction: check for round-number payment
  if (tx.outputs.length === 2) {
    const [v0, v1] = values
    const r0 = roundness(v0)
    const r1 = roundness(v1)

    if (r0 > r1) {
      // v0 is rounder → likely payment, v1 is change
      const confidence = Math.min(0.95, 0.5 + (r0 - r1) * 0.3)
      const entropy = binaryEntropy(1 - confidence)
      return {
        entropy,
        changeDetected: true,
        explanation: `output[0] (${satsToBtc(v0)} BTC) is rounder than output[1] (${satsToBtc(v1)} BTC). Change detection confidence: ${(confidence * 100).toFixed(0)}%. Entropy: ${entropy.toFixed(2)} bits.`,
      }
    }

    if (r1 > r0) {
      const confidence = Math.min(0.95, 0.5 + (r1 - r0) * 0.3)
      const entropy = binaryEntropy(1 - confidence)
      return {
        entropy,
        changeDetected: true,
        explanation: `output[1] (${satsToBtc(v1)} BTC) is rounder than output[0] (${satsToBtc(v0)} BTC). Change detection confidence: ${(confidence * 100).toFixed(0)}%. Entropy: ${entropy.toFixed(2)} bits.`,
      }
    }

    // Neither is rounder → max ambiguity for a 2-output tx
    return {
      entropy: 1.0,
      changeDetected: false,
      explanation: `both outputs have similar roundness. Max entropy for 2-output tx: 1.0 bit.`,
    }
  }

  // 3+ outputs (non-CoinJoin): compute distribution entropy
  const total = values.reduce((s, v) => s + v, 0)
  const probs = values.map(v => v / total)
  const entropy = shannonEntropy(probs)

  return {
    entropy,
    changeDetected: false,
    explanation: `${values.length} outputs with varying amounts. Entropy: ${entropy.toFixed(2)} bits.`,
  }
}

/**
 * Measure how "round" an amount is. Higher = more likely a deliberate payment.
 *
 * Based on trailing zeros in the satoshi value:
 * - 100,000,000 (1 BTC) → roundness 8
 * - 10,000,000 (0.1 BTC) → roundness 7
 * - 1,000,000 (0.01 BTC) → roundness 6
 * - 100,000 (0.001 BTC) → roundness 5
 * - 12,345,678 → roundness 0
 */
export function roundness(sats: number): number {
  if (sats === 0) return 0
  let r = 0
  let v = sats
  while (v % 10 === 0 && v > 0) {
    r++
    v = Math.floor(v / 10)
  }
  return r
}

/**
 * Detect amount correlation between two sets of transactions.
 *
 * Finds pairs of (input_tx, output_tx) where the amounts are
 * suspiciously close — suggesting the same funds were moved.
 *
 * @param incoming - Transactions received by the wallet
 * @param outgoing - Transactions sent by the wallet
 * @param tolerancePct - Maximum difference as % (default 1%)
 */
export function amountCorrelation(
  incoming: { txid: string; value: number }[],
  outgoing: { txid: string; value: number }[],
  tolerancePct: number = 1,
): { inTxid: string; outTxid: string; inValue: number; outValue: number; diffPct: number }[] {
  const matches: { inTxid: string; outTxid: string; inValue: number; outValue: number; diffPct: number }[] = []

  for (const inc of incoming) {
    for (const out of outgoing) {
      if (inc.value === 0 || out.value === 0) continue
      const diff = Math.abs(inc.value - out.value)
      const pct = (diff / inc.value) * 100
      if (pct <= tolerancePct) {
        matches.push({
          inTxid: inc.txid,
          outTxid: out.txid,
          inValue: inc.value,
          outValue: out.value,
          diffPct: pct,
        })
      }
    }
  }

  return matches.sort((a, b) => a.diffPct - b.diffPct)
}

function satsToBtc(sats: number): string {
  return (sats / 100_000_000).toFixed(8).replace(/\.?0+$/, '')
}
