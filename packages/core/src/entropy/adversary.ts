/**
 * Adversary models — different attackers have different capabilities.
 *
 * A casual blockchain observer can see on-chain data only.
 * An exchange compliance team has KYC data + on-chain.
 * A law enforcement agency has KYC + subpoena power + chain analysis
 * tools + network-level surveillance capabilities.
 *
 * Each model assigns different weights to each attack surface.
 * The same transaction can have a privacy score of 2 bits against
 * a casual observer but 6 bits against law enforcement.
 *
 * The user selects the adversary model. ε-tx computes accordingly.
 *
 * Reference: Narayanan & Möser (2017). "Obfuscation in Bitcoin:
 * Techniques and Politics." — adversary capability taxonomy.
 */

export type AdversaryModel = 'casual' | 'exchange' | 'law-enforcement' | 'nation-state'

export interface AdversaryWeights {
  model: AdversaryModel
  description: string
  capabilities: string[]
  weights: {
    clustering: number
    walletFingerprint: number
    amountAnalysis: number
    amountCorrelation: number
    timing: number
    network: number
    coinjoin: number       // ability to analyse CoinJoin effectiveness
    crosschain: number     // ability to correlate across chains
    adversarialMl: number  // access to ML classifiers
  }
}

/**
 * Adversary model definitions.
 *
 * Weights represent relative importance (0-1). Higher = the adversary
 * is better at exploiting this attack surface.
 */
export const ADVERSARY_MODELS: Record<AdversaryModel, AdversaryWeights> = {
  casual: {
    model: 'casual',
    description: 'passive blockchain observer with no special tools',
    capabilities: [
      'public block explorer access',
      'basic address search',
    ],
    weights: {
      clustering: 0.3,        // can see co-spends but not follow deeply
      walletFingerprint: 0.1, // doesn't check tx structure
      amountAnalysis: 0.4,    // can spot round numbers
      amountCorrelation: 0.2, // manual search only
      timing: 0.1,            // doesn't analyse timestamps
      network: 0.0,           // no network access
      coinjoin: 0.0,          // doesn't understand CoinJoin
      crosschain: 0.0,        // single-chain view only
      adversarialMl: 0.0,     // no ML
    },
  },

  exchange: {
    model: 'exchange',
    description: 'exchange compliance team with KYC data and chain analysis subscription',
    capabilities: [
      'KYC identity linked to deposit/withdrawal addresses',
      'Chainalysis/Elliptic subscription',
      'transaction monitoring alerts',
      'suspicious activity reports (SARs)',
    ],
    weights: {
      clustering: 0.8,        // Chainalysis clusters well
      walletFingerprint: 0.5, // chain analysis tools detect some
      amountAnalysis: 0.7,    // automated amount matching
      amountCorrelation: 0.6, // cross-reference with KYC deposits
      timing: 0.4,            // timestamp analysis available
      network: 0.1,           // no network surveillance
      coinjoin: 0.7,          // CoinJoin flagging is standard
      crosschain: 0.5,        // some cross-chain capability
      adversarialMl: 0.8,     // ML classifiers are the product
    },
  },

  'law-enforcement': {
    model: 'law-enforcement',
    description: 'law enforcement with subpoena power, chain analysis tools, and network surveillance',
    capabilities: [
      'all exchange capabilities',
      'subpoena exchanges for full KYC records',
      'ISP data requests (IP ↔ timestamp)',
      'Chainalysis Reactor / Elliptic Investigator',
      'international cooperation (MLATs)',
      'blockchain analytics training',
    ],
    weights: {
      clustering: 0.9,
      walletFingerprint: 0.6,
      amountAnalysis: 0.8,
      amountCorrelation: 0.8,
      timing: 0.7,            // can correlate with ISP logs
      network: 0.6,           // can request ISP data
      coinjoin: 0.8,          // specialised CoinJoin analysis
      crosschain: 0.7,        // cross-chain tools improving rapidly
      adversarialMl: 0.9,     // state-of-the-art classifiers
    },
  },

  'nation-state': {
    model: 'nation-state',
    description: 'nation-state adversary with global network surveillance and unlimited resources',
    capabilities: [
      'all law enforcement capabilities',
      'passive internet backbone surveillance',
      'active node injection (Sybil attacks)',
      'ISP-level traffic correlation',
      'exchange infiltration',
      'zero-day exploits against wallet software',
      'unlimited compute for analysis',
    ],
    weights: {
      clustering: 1.0,
      walletFingerprint: 0.8,
      amountAnalysis: 0.9,
      amountCorrelation: 0.9,
      timing: 0.9,
      network: 0.9,           // backbone-level surveillance
      coinjoin: 0.9,
      crosschain: 0.9,
      adversarialMl: 1.0,
    },
  },
}

/**
 * Apply adversary weights to raw leakage scores.
 *
 * The weighted score reflects what the adversary can ACTUALLY exploit,
 * not the theoretical maximum leakage. A casual observer can't use
 * network-level timing even if it leaks 2 bits — their weight for
 * network is 0.
 *
 * @param rawLeakages - Leakage per attack surface in bits
 * @param model - Which adversary to model
 * @returns Weighted leakages and total
 */
export function applyAdversaryModel(
  rawLeakages: Record<string, number>,
  model: AdversaryModel,
): {
  model: AdversaryModel
  weighted: { source: string; raw: number; weight: number; effective: number }[]
  totalRaw: number
  totalEffective: number
} {
  const weights = ADVERSARY_MODELS[model].weights
  const weighted: { source: string; raw: number; weight: number; effective: number }[] = []

  const weightMap: Record<string, number> = {
    clustering: weights.clustering,
    'wallet-fingerprint': weights.walletFingerprint,
    'amount-analysis': weights.amountAnalysis,
    'amount-correlation': weights.amountCorrelation,
    timing: weights.timing,
    network: weights.network,
    coinjoin: weights.coinjoin,
    crosschain: weights.crosschain,
    'adversarial-ml': weights.adversarialMl,
  }

  let totalRaw = 0
  let totalEffective = 0

  for (const [source, raw] of Object.entries(rawLeakages)) {
    const weight = weightMap[source] ?? 0.5
    const effective = raw * weight
    weighted.push({ source, raw, weight, effective })
    totalRaw += raw
    totalEffective += effective
  }

  return {
    model,
    weighted: weighted.sort((a, b) => b.effective - a.effective),
    totalRaw: Math.round(totalRaw * 100) / 100,
    totalEffective: Math.round(totalEffective * 100) / 100,
  }
}
