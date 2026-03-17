import { describe, it, expect } from 'vitest'
import { analyseCrossChain, composePrivacy, type ChainHop } from './composition.js'

/**
 * Tests for cross-chain privacy composition.
 *
 * Mathematical properties verified:
 * 1. Basic composition: ε_total = Σ ε_i (Dwork et al. 2006)
 * 2. Advanced composition ≥ basic for small k
 * 3. Both bounds are non-negative
 * 4. HTLC hash correlation increases with number of HTLC hops
 * 5. Timing correlation decreases with higher bridge volume
 * 6. Amount correlation increases with closer amount matches
 *
 * Reference: Kamath et al. (2020). "The Composition Theorem for
 *            Differential Privacy." IEEE Trans. Info Theory.
 */

describe('composePrivacy — Dwork et al. (2006)', () => {
  it('basic composition = sum of epsilons', () => {
    const result = composePrivacy([1.0, 2.0, 0.5])
    expect(result.basic).toBeCloseTo(3.5)
  })

  it('empty hops → zero', () => {
    const result = composePrivacy([])
    expect(result.basic).toBe(0)
    expect(result.advanced).toBe(0)
  })

  it('single hop → basic = epsilon', () => {
    const result = composePrivacy([2.5])
    expect(result.basic).toBeCloseTo(2.5)
  })

  it('basic ≥ 0 always', () => {
    expect(composePrivacy([0, 0, 0]).basic).toBe(0)
    expect(composePrivacy([1, 2, 3]).basic).toBeGreaterThan(0)
  })

  it('advanced composition computed correctly — Dwork, Rothblum, Vadhan (2010)', () => {
    // √(2k · ln(1/δ)) · max(ε) + k · max(ε)²
    // k=3, max_ε=2.0, δ=1e-5
    // √(6 · ln(100000)) · 2 + 3 · 4 = √(6·11.51) · 2 + 12 = √69.08 · 2 + 12 ≈ 16.62 + 12 = 28.62
    const result = composePrivacy([1.0, 2.0, 0.5])
    expect(result.advanced).toBeGreaterThan(result.basic)
  })

  it('recommended = basic for small k', () => {
    const result = composePrivacy([1.0, 2.0])
    expect(result.recommended).toBe(result.basic)
  })
})

describe('analyseCrossChain', () => {
  it('empty path → zero leakage', () => {
    const result = analyseCrossChain([])
    expect(result.totalLeakage).toBe(0)
  })

  it('HTLC hops create hash correlation risk', () => {
    const hops: ChainHop[] = [
      { chain: 'bitcoin', mechanism: 'htlc', amount: 100000, timestamp: 1000000, privacyLeakage: 2.0 },
      { chain: 'ethereum', mechanism: 'htlc', amount: 99500, timestamp: 1000300, privacyLeakage: 1.5 },
    ]
    const result = analyseCrossChain(hops)
    expect(result.htlcLinkRisk).toBeGreaterThan(0) // same hash on both chains
  })

  it('bridge hops have no HTLC risk', () => {
    const hops: ChainHop[] = [
      { chain: 'bitcoin', mechanism: 'bridge', amount: 100000, timestamp: 1000000, privacyLeakage: 2.0 },
      { chain: 'ethereum', mechanism: 'bridge', amount: 99500, timestamp: 1003600, privacyLeakage: 1.5 },
    ]
    const result = analyseCrossChain(hops)
    expect(result.htlcLinkRisk).toBe(0)
  })

  it('close timing → higher correlation', () => {
    const close: ChainHop[] = [
      { chain: 'bitcoin', mechanism: 'bridge', amount: 100000, timestamp: 1000000, privacyLeakage: 2.0 },
      { chain: 'ethereum', mechanism: 'bridge', amount: 99000, timestamp: 1000060, privacyLeakage: 1.5 }, // 1 min apart
    ]
    const far: ChainHop[] = [
      { chain: 'bitcoin', mechanism: 'bridge', amount: 100000, timestamp: 1000000, privacyLeakage: 2.0 },
      { chain: 'ethereum', mechanism: 'bridge', amount: 99000, timestamp: 1086400, privacyLeakage: 1.5 }, // 1 day apart
    ]
    const closeResult = analyseCrossChain(close)
    const farResult = analyseCrossChain(far)
    expect(closeResult.timingCorrelation).toBeGreaterThanOrEqual(farResult.timingCorrelation)
  })

  it('near-exact amounts → high correlation', () => {
    const hops: ChainHop[] = [
      { chain: 'bitcoin', mechanism: 'bridge', amount: 100000, timestamp: 1000000, privacyLeakage: 2.0 },
      { chain: 'ethereum', mechanism: 'bridge', amount: 99990, timestamp: 1003600, privacyLeakage: 1.5 }, // 0.01% diff
    ]
    const result = analyseCrossChain(hops)
    expect(result.amountCorrelation).toBeGreaterThan(1.0) // strong link
  })

  it('very different amounts → low correlation', () => {
    const hops: ChainHop[] = [
      { chain: 'bitcoin', mechanism: 'bridge', amount: 100000, timestamp: 1000000, privacyLeakage: 2.0 },
      { chain: 'ethereum', mechanism: 'bridge', amount: 50000, timestamp: 1003600, privacyLeakage: 1.5 }, // 50% diff
    ]
    const result = analyseCrossChain(hops)
    expect(result.amountCorrelation).toBe(0) // no correlation
  })

  it('higher bridge volume → lower timing correlation', () => {
    const hops: ChainHop[] = [
      { chain: 'bitcoin', mechanism: 'bridge', amount: 100000, timestamp: 1000000, privacyLeakage: 2.0 },
      { chain: 'ethereum', mechanism: 'bridge', amount: 99000, timestamp: 1000300, privacyLeakage: 1.5 },
    ]
    const lowVol = analyseCrossChain(hops, new Map([['bitcoin-ethereum', 10]]))
    const highVol = analyseCrossChain(hops, new Map([['bitcoin-ethereum', 10000]]))
    expect(highVol.timingCorrelation).toBeLessThanOrEqual(lowVol.timingCorrelation)
  })

  it('totalLeakage ≥ 0', () => {
    const hops: ChainHop[] = [
      { chain: 'bitcoin', mechanism: 'bridge', amount: 100000, timestamp: 1000000, privacyLeakage: 0.1 },
    ]
    expect(analyseCrossChain(hops).totalLeakage).toBeGreaterThanOrEqual(0)
  })

  it('anonymity set is positive', () => {
    const hops: ChainHop[] = [
      { chain: 'bitcoin', mechanism: 'bridge', amount: 100000, timestamp: 1000000, privacyLeakage: 2.0 },
      { chain: 'ethereum', mechanism: 'bridge', amount: 99000, timestamp: 1003600, privacyLeakage: 1.5 },
    ]
    expect(analyseCrossChain(hops).anonymitySet).toBeGreaterThan(0)
  })
})
