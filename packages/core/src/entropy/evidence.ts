/**
 * Dempster-Shafer evidence fusion for privacy analysis.
 *
 * Each heuristic (clustering, fingerprinting, timing, amounts) produces
 * a mass function over Θ = {EXPOSED, PRIVATE}. Dempster's combination
 * rule fuses them, handling conflicting evidence properly.
 *
 * This replaces basic composition (ε_total ≤ Σ ε_i) with proper
 * belief function theory. The basic theorem is loose — if clustering
 * says "exposed" and timing says "private", basic composition adds
 * both leakages. Dempster-Shafer detects the conflict and adjusts.
 *
 * Reference: Dempster, A.P. (1967). "Upper and lower probabilities
 * induced by a multivalued mapping."
 * Reference: Shafer, G. (1976). "A Mathematical Theory of Evidence."
 */

export interface MassFunction {
  exposed: number    // m({EXPOSED}) — evidence of privacy loss
  private_: number   // m({PRIVATE}) — evidence of privacy preservation
  uncertain: number  // m({EXPOSED, PRIVATE}) — can't tell
  source: string
}

export interface FusedResult {
  belief: number       // Bel(EXPOSED) — lower bound on exposure
  plausibility: number // Pl(EXPOSED) = 1 - m({PRIVATE})
  uncertainty: number  // Pl - Bel = width of the interval
  conflict: number     // K — total conflicting mass
  sources: string[]
}

/**
 * Create a mass function from a privacy leakage score.
 *
 * @param leakageBits - Information leakage in bits (from any analysis module)
 * @param maxBits - Maximum possible leakage for this source (for normalisation)
 * @param reliability - How reliable is this heuristic? (0-1)
 * @param source - Name of the analysis module
 */
export function createMass(
  leakageBits: number,
  maxBits: number,
  reliability: number,
  source: string,
): MassFunction {
  const normalisedLeakage = maxBits > 0 ? Math.min(leakageBits / maxBits, 1) : 0
  const informative = reliability

  return {
    exposed: informative * normalisedLeakage,
    private_: informative * (1 - normalisedLeakage),
    uncertain: 1 - informative,
    source,
  }
}

/**
 * Dempster's combination rule for two mass functions.
 *
 * Focal elements: {EXPOSED}, {PRIVATE}, {EXPOSED, PRIVATE}
 *
 * Intersections:
 *   {EXPOSED} ∩ {EXPOSED} = {EXPOSED}
 *   {PRIVATE} ∩ {PRIVATE} = {PRIVATE}
 *   {EXPOSED} ∩ {PRIVATE} = ∅  (conflict)
 *   Any ∩ Θ = Any
 *   Θ ∩ Θ = Θ
 */
export function combine(m1: MassFunction, m2: MassFunction): MassFunction {
  const ee = m1.exposed * m2.exposed
  const eu = m1.exposed * m2.uncertain
  const ue = m1.uncertain * m2.exposed
  const pp = m1.private_ * m2.private_
  const pu = m1.private_ * m2.uncertain
  const up = m1.uncertain * m2.private_
  const uu = m1.uncertain * m2.uncertain

  // Conflict mass
  const K = m1.exposed * m2.private_ + m1.private_ * m2.exposed
  const norm = 1 - K

  if (norm <= 0) {
    return { exposed: 0, private_: 0, uncertain: 1, source: `${m1.source}+${m2.source}` }
  }

  return {
    exposed: (ee + eu + ue) / norm,
    private_: (pp + pu + up) / norm,
    uncertain: uu / norm,
    source: `${m1.source}+${m2.source}`,
  }
}

/**
 * Fuse all evidence sources using iterated Dempster combination.
 */
export function fuseEvidence(masses: MassFunction[]): FusedResult {
  if (masses.length === 0) {
    return { belief: 0, plausibility: 1, uncertainty: 1, conflict: 0, sources: [] }
  }

  if (masses.length === 1) {
    const m = masses[0]
    return {
      belief: m.exposed,
      plausibility: 1 - m.private_,
      uncertainty: (1 - m.private_) - m.exposed,
      conflict: 0,
      sources: [m.source],
    }
  }

  let fused = masses[0]
  let totalConflict = 0

  for (let i = 1; i < masses.length; i++) {
    const K = fused.exposed * masses[i].private_ + fused.private_ * masses[i].exposed
    totalConflict = 1 - (1 - totalConflict) * (1 - K)
    fused = combine(fused, masses[i])
  }

  return {
    belief: fused.exposed,
    plausibility: 1 - fused.private_,
    uncertainty: (1 - fused.private_) - fused.exposed,
    conflict: totalConflict,
    sources: masses.map(m => m.source),
  }
}

/**
 * Reliability parameters for each analysis module.
 *
 * Higher = more weight in the fusion. Based on the accuracy of
 * each heuristic from published research.
 */
export const HEURISTIC_RELIABILITY: Record<string, number> = {
  clustering: 0.85,           // co-spend heuristic is strong but CoinJoin breaks it
  'wallet-fingerprint': 0.45, // ~45% accuracy per Ishaana Misra's research
  'amount-analysis': 0.60,    // round numbers are reliable, correlations less so
  'amount-correlation': 0.50, // near-matches could be coincidence
  timing: 0.40,               // timezone inference ±1-2 hours, patterns less reliable
}

/**
 * Maximum leakage in bits for each source.
 * Used to normalise leakage into [0, 1] for mass function creation.
 */
export const MAX_LEAKAGE_BITS: Record<string, number> = {
  clustering: 10,             // log₂(1024) — very large cluster
  'wallet-fingerprint': 2.3,  // log₂(5) — 5 wallet types
  'amount-analysis': 1.0,     // max 1 bit for 2-output change detection
  'amount-correlation': 2.0,  // up to 2 bits from amount matching
  timing: 5.0,                // timezone (1.5) + periodicity (2) + distribution (1.5)
}
