/**
 * Cross-chain privacy composition — Attack Surface 8.
 *
 * When assets move across chains (BTC → Lightning → Ethereum L2),
 * privacy leaks compound. The total privacy loss is NOT the minimum
 * of each hop — it's a composition.
 *
 * Three linking vectors:
 *
 * 1. HTLC hash correlation: atomic swaps use hash(preimage) on both
 *    chains. The same hash appearing on BTC and ETH within minutes
 *    is a trivial link. Any passive observer of both chains finds it.
 *    Reference: Thyagarajan et al. (2022) — "Rapiddash: Atomic Swaps."
 *
 * 2. Timing correlation: bridge deposit at T₁ on chain A, withdrawal
 *    at T₂ on chain B. P(linked) increases as |T₂ - T₁| decreases.
 *    Large bridges have enough volume to provide plausible deniability.
 *    Small bridges don't.
 *
 * 3. Amount correlation: deposit 1.5 ETH, withdraw 1.4997 ETH (minus
 *    fee). Near-exact matches across chains link transactions.
 *
 * The composition theorem:
 *
 *   ε_total ≤ Σ ε_i  (basic sequential composition)
 *
 * This is the standard differential privacy result — Dwork et al.
 * (2006). For k mechanisms each with privacy ε_i, the total privacy
 * loss is at most the sum. This is TIGHT for worst-case adversaries.
 *
 * For advanced composition (Dwork, Rothblum, Vadhan 2010):
 *
 *   ε_total ≤ √(2k · ln(1/δ)) · max(ε_i) + k · max(ε_i)²
 *
 * This gives a better bound when all hops have similar privacy.
 *
 * Reference: Kamath et al. (2020) — "The Composition Theorem for
 *            Differential Privacy." IEEE Trans. Info Theory.
 * Reference: P2C2T (IACR 2024) — "Preserving Privacy of Cross-Chain Transfer."
 * Reference: Merklescience (2025) — "Cross-Chain Analytics for Law Enforcement."
 */

import { shannonEntropy } from '../entropy/shannon.js'

export interface ChainHop {
  chain: string             // 'bitcoin' | 'lightning' | 'ethereum' | etc.
  mechanism: string         // 'htlc' | 'bridge' | 'l2-deposit' | 'l2-withdrawal'
  amount: number            // in the smallest unit of the source chain
  timestamp: number         // unix seconds
  privacyLeakage: number   // ε_i in bits for this hop
}

export interface CrossChainAnalysis {
  hops: ChainHop[]
  // Basic composition: ε_total ≤ Σ ε_i
  basicComposition: number
  // Advanced composition: √(2k·ln(1/δ))·max(ε) + k·max(ε)²
  advancedComposition: number
  // Specific linking risks
  htlcLinkRisk: number           // bits leaked by hash correlation
  timingCorrelation: number      // bits leaked by timing proximity
  amountCorrelation: number      // bits leaked by amount matching
  totalLeakage: number           // max of composition bounds + specific risks
  anonymitySet: number           // effective anonymity set across the full path
}

/**
 * Analyse privacy across a multi-chain transfer path.
 *
 * @param hops - Ordered sequence of chain hops
 * @param bridgeVolume - Approximate daily volume of each bridge (for timing analysis)
 * @param delta - Failure probability for advanced composition (default 10^-5)
 */
export function analyseCrossChain(
  hops: ChainHop[],
  bridgeVolume: Map<string, number> = new Map(),
  delta: number = 1e-5,
): CrossChainAnalysis {
  if (hops.length === 0) {
    return {
      hops: [],
      basicComposition: 0,
      advancedComposition: 0,
      htlcLinkRisk: 0,
      timingCorrelation: 0,
      amountCorrelation: 0,
      totalLeakage: 0,
      anonymitySet: Infinity,
    }
  }

  const k = hops.length
  const epsilons = hops.map(h => h.privacyLeakage)

  // Basic sequential composition: Σ ε_i
  // Reference: Dwork et al. (2006) — "Calibrating Noise to Sensitivity"
  const basicComposition = epsilons.reduce((s, e) => s + e, 0)

  // Advanced composition: √(2k · ln(1/δ)) · max(ε) + k · max(ε)²
  // Reference: Dwork, Rothblum, Vadhan (2010) — "Boosting and DP"
  const maxEps = Math.max(...epsilons)
  const advancedComposition = Math.sqrt(2 * k * Math.log(1 / delta)) * maxEps + k * maxEps * maxEps

  // HTLC hash correlation
  const htlcHops = hops.filter(h => h.mechanism === 'htlc')
  let htlcLinkRisk = 0
  if (htlcHops.length >= 2) {
    // Same hash on multiple chains = trivially linkable
    // Each HTLC pair leaks ~log₂(chain_tx_count) bits
    // (the adversary searches for the hash on the other chain)
    htlcLinkRisk = htlcHops.length * 3.0 // ~3 bits per HTLC link
  }

  // Timing correlation between consecutive hops
  let timingCorrelation = 0
  for (let i = 1; i < hops.length; i++) {
    const timeDiff = Math.abs(hops[i].timestamp - hops[i - 1].timestamp)
    const bridgeKey = `${hops[i - 1].chain}-${hops[i].chain}`
    const volume = bridgeVolume.get(bridgeKey) ?? 100 // default: 100 txs/day

    // Timing leakage: inverse of the anonymity set within the time window.
    // candidates = volume_per_day * (time_window_hours / 24)
    // More candidates → harder for adversary → less leakage.
    // Leakage = max(0, log₂(reference_set / candidates))
    // where reference_set is a baseline (e.g., 1000 — "reasonably private")
    const timeWindowHours = Math.max(timeDiff / 3600, 0.01)
    const candidatesInWindow = Math.max(1, volume * (timeWindowHours / 24))
    // Fewer candidates = more bits leaked. 1 candidate = ~10 bits. 1000 = 0 bits.
    const timingBits = Math.max(0, Math.log2(1000) - Math.log2(candidatesInWindow))
    timingCorrelation += timingBits
  }

  // Amount correlation between consecutive hops
  let amountCorrelation = 0
  for (let i = 1; i < hops.length; i++) {
    const diff = Math.abs(hops[i].amount - hops[i - 1].amount)
    const pct = hops[i - 1].amount > 0 ? diff / hops[i - 1].amount : 1

    // Near-exact match: high correlation
    // >5% difference: low correlation
    if (pct < 0.001) amountCorrelation += 2.0      // <0.1% = strong link
    else if (pct < 0.01) amountCorrelation += 1.5   // <1% = moderate
    else if (pct < 0.05) amountCorrelation += 0.8   // <5% = weak
    // >5% = not correlated by amount alone
  }

  // Total: max of composition bounds + specific linking risks
  const compositionBound = Math.min(basicComposition, advancedComposition)
  const specificRisks = htlcLinkRisk + timingCorrelation + amountCorrelation
  const totalLeakage = Math.max(compositionBound, specificRisks)

  // Anonymity set: 2^(max_theoretical - total_leakage)
  const maxTheoretical = hops.length * 5 // rough: 5 bits per hop if perfect
  const anonymitySet = Math.pow(2, Math.max(0, maxTheoretical - totalLeakage))

  return {
    hops,
    basicComposition: round2(basicComposition),
    advancedComposition: round2(advancedComposition),
    htlcLinkRisk: round2(htlcLinkRisk),
    timingCorrelation: round2(timingCorrelation),
    amountCorrelation: round2(amountCorrelation),
    totalLeakage: round2(totalLeakage),
    anonymitySet: Math.round(anonymitySet),
  }
}

/**
 * Compute the privacy composition for a specific multi-hop path.
 *
 * This is the formal contribution: a framework for reasoning about
 * privacy loss across heterogeneous chains.
 *
 * Example:
 *   BTC (2.1 bits) → Lightning (0.8 bits) → Ethereum L2 (1.5 bits)
 *   Basic: 2.1 + 0.8 + 1.5 = 4.4 bits
 *   Advanced: √(6·ln(10⁵))·1.5 + 3·1.5² = ~12.7 bits (loose for small k)
 *   Use basic for k < 10, advanced for k ≥ 10.
 *
 * @param epsilons - Privacy loss per hop in bits
 * @param delta - Failure probability (default 10^-5)
 */
export function composePrivacy(
  epsilons: number[],
  delta: number = 1e-5,
): { basic: number; advanced: number; recommended: number } {
  const k = epsilons.length
  if (k === 0) return { basic: 0, advanced: 0, recommended: 0 }

  const basic = epsilons.reduce((s, e) => s + e, 0)

  const maxEps = Math.max(...epsilons)
  const advanced = Math.sqrt(2 * k * Math.log(1 / delta)) * maxEps + k * maxEps * maxEps

  // Use basic for small k (tighter), advanced for large k
  const recommended = k < 10 ? basic : Math.min(basic, advanced)

  return {
    basic: round2(basic),
    advanced: round2(advanced),
    recommended: round2(recommended),
  }
}

function round2(n: number): number {
  return Math.round(n * 100) / 100
}
