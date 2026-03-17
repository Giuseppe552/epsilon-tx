import { describe, it, expect } from 'vitest'
import { analyseRing, constructOptimalRing, type RingMember } from './ring.js'

/**
 * Tests for Monero ring signature analysis.
 *
 * Mathematical properties verified:
 * 1. H(ring) ≤ log₂(ringSize) — entropy can't exceed uniform
 * 2. H(ring) ≥ 0 — entropy is non-negative
 * 3. Σ P_i = 1 — probabilities sum to 1
 * 4. Newer outputs have higher P (OSPEAD finding)
 * 5. Optimal ring has higher entropy than default
 *
 * Reference: OSPEAD (Monero Research, 2025) — §2, §4.
 * Reference: Möser et al. (2018) — "An Empirical Analysis of
 *            Traceability in the Monero Blockchain." PoPETs.
 */

function ringWithAges(ages: number[]): RingMember[] {
  return ages.map((age, i) => ({
    outputIndex: i * 1000,
    age,
    amount: 0, // RingCT
    isDecoy: null,
  }))
}

describe('analyseRing — OSPEAD (2025)', () => {
  it('uniform ages → near-maximum entropy', () => {
    // All members same age → ratio ≈ 1 for all → uniform probs
    const members = ringWithAges(new Array(16).fill(86400)) // all 1 day old
    const result = analyseRing(members)
    expect(result.entropy).toBeCloseTo(4.0, 0) // close to log₂(16)
  })

  it('one very recent + 15 old → low entropy (newest is likely real)', () => {
    // 1 minute old + 15 at 1 year old
    const ages = [60, ...new Array(15).fill(365 * 86400)]
    const result = analyseRing(ringWithAges(ages))
    expect(result.entropy).toBeLessThan(3.5)
    expect(result.mostLikelyReal).toBe(0) // newest is most likely
  })

  it('entropy ≤ log₂(ringSize) always', () => {
    const cases = [
      ringWithAges([10, 100, 1000, 10000, 100000, 1000000, 60, 600, 6000, 60000, 300, 3000, 30000, 300000, 500, 5000]),
      ringWithAges(new Array(16).fill(3600)),
      ringWithAges([1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 2, 20, 200, 2000, 20000, 200000, 3, 30]),
    ]
    for (const members of cases) {
      const result = analyseRing(members)
      expect(result.entropy).toBeLessThanOrEqual(4.01) // log₂(16) + tolerance
    }
  })

  it('entropy ≥ 0 always', () => {
    const result = analyseRing(ringWithAges([1, 1000000, 1000000, 1000000, 1000000, 1000000, 1000000, 1000000, 1000000, 1000000, 1000000, 1000000, 1000000, 1000000, 1000000, 1000000]))
    expect(result.entropy).toBeGreaterThanOrEqual(0)
  })

  it('probabilities sum to 1', () => {
    const result = analyseRing(ringWithAges([60, 600, 6000, 60000, 600000, 120, 1200, 12000, 120000, 1200000, 300, 3000, 30000, 300000, 3000000, 30]))
    const sum = result.memberProbabilities.reduce((s, p) => s + p, 0)
    expect(sum).toBeCloseTo(1.0, 2)
  })

  it('effective anonymity set = 2^entropy', () => {
    const members = ringWithAges(new Array(16).fill(86400))
    const result = analyseRing(members)
    expect(result.effectiveAnonymitySet).toBeCloseTo(Math.pow(2, result.entropy), 0)
  })

  it('entropy loss = theoretical - actual', () => {
    const result = analyseRing(ringWithAges([60, ...new Array(15).fill(86400 * 30)]))
    expect(result.entropyLoss).toBeCloseTo(result.theoreticalEntropy - result.entropy, 2)
  })

  it('empty ring → zero entropy', () => {
    const result = analyseRing([])
    expect(result.entropy).toBe(0)
    expect(result.ringSize).toBe(0)
  })
})

describe('constructOptimalRing — inverse-OSPEAD', () => {
  it('returns 15 decoys for ring size 16', () => {
    const result = constructOptimalRing(3600, 16) // 1 hour old output
    expect(result.selectedDecoyAges).toHaveLength(15)
  })

  it('optimal entropy > default entropy', () => {
    const result = constructOptimalRing(3600, 16)
    // Default is ~2.0 bits; optimal should be higher
    expect(result.expectedEntropy).toBeGreaterThan(2.0)
    expect(result.improvementOverDefault).toBeGreaterThan(0)
  })

  it('all decoy ages are positive', () => {
    const result = constructOptimalRing(86400, 16)
    for (const age of result.selectedDecoyAges) {
      expect(age).toBeGreaterThan(0)
    }
  })

  it('decoy ages are spread out (not all the same)', () => {
    const result = constructOptimalRing(3600, 16)
    const unique = new Set(result.selectedDecoyAges)
    expect(unique.size).toBeGreaterThan(5) // at least 5 distinct ages
  })

  it('expected entropy ≤ log₂(ringSize)', () => {
    const result = constructOptimalRing(3600, 16)
    expect(result.expectedEntropy).toBeLessThanOrEqual(4.01) // log₂(16)
  })
})
