import { describe, it, expect } from 'vitest'
import {
  shannonEntropy,
  conditionalEntropy,
  mutualInformation,
  binaryEntropy,
  anonymitySetSize,
  composedPrivacyScore,
} from './shannon.js'

describe('shannonEntropy', () => {
  it('uniform distribution has max entropy', () => {
    // 4 equally likely outcomes → log₂(4) = 2 bits
    expect(shannonEntropy([0.25, 0.25, 0.25, 0.25])).toBeCloseTo(2.0)
  })

  it('certain outcome has zero entropy', () => {
    expect(shannonEntropy([1, 0, 0, 0])).toBe(0)
  })

  it('binary fair coin = 1 bit', () => {
    expect(shannonEntropy([0.5, 0.5])).toBeCloseTo(1.0)
  })

  it('skewed distribution has lower entropy', () => {
    const skewed = shannonEntropy([0.9, 0.1])
    const uniform = shannonEntropy([0.5, 0.5])
    expect(skewed).toBeLessThan(uniform)
  })

  it('empty array returns 0', () => {
    expect(shannonEntropy([])).toBe(0)
  })

  // Monero ring with 16 members, all equally likely → 4 bits
  it('ring size 16 uniform → 4 bits', () => {
    const ring = new Array(16).fill(1 / 16)
    expect(shannonEntropy(ring)).toBeCloseTo(4.0)
  })

  // Monero ring where newest member is 80% likely (OSPEAD finding)
  it('ring size 16, newest=80% → ~1.2 bits', () => {
    const ring = new Array(16).fill(0)
    ring[0] = 0.8
    const remaining = 0.2 / 15
    for (let i = 1; i < 16; i++) ring[i] = remaining
    const H = shannonEntropy(ring)
    expect(H).toBeGreaterThan(0.8)
    expect(H).toBeLessThan(1.6)
  })
})

describe('conditionalEntropy', () => {
  it('independent X and Y → H(X|Y) = H(X)', () => {
    // P(x,y) = P(x)·P(y) means observing Y tells nothing about X
    const joint = [
      [0.25, 0.25],
      [0.25, 0.25],
    ]
    const Hx = shannonEntropy([0.5, 0.5])
    const HxGivenY = conditionalEntropy(joint)
    expect(HxGivenY).toBeCloseTo(Hx)
  })

  it('perfectly correlated → H(X|Y) = 0', () => {
    // P(x=0,y=0) = 0.5, P(x=1,y=1) = 0.5, all others 0
    const joint = [
      [0.5, 0],
      [0, 0.5],
    ]
    expect(conditionalEntropy(joint)).toBeCloseTo(0)
  })

  it('H(X|Y) ≤ H(X) always (conditioning reduces entropy)', () => {
    const joint = [
      [0.3, 0.1],
      [0.1, 0.5],
    ]
    const pX = [0.4, 0.6]
    const Hx = shannonEntropy(pX)
    const HxGivenY = conditionalEntropy(joint)
    expect(HxGivenY).toBeLessThanOrEqual(Hx + 0.001) // small tolerance
  })
})

describe('mutualInformation', () => {
  it('independent variables → I = 0', () => {
    const joint = [
      [0.25, 0.25],
      [0.25, 0.25],
    ]
    expect(mutualInformation(joint)).toBeCloseTo(0)
  })

  it('perfectly correlated → I = H(X)', () => {
    const joint = [
      [0.5, 0],
      [0, 0.5],
    ]
    expect(mutualInformation(joint)).toBeCloseTo(1.0)
  })

  it('I(X;Y) ≥ 0 always', () => {
    const joint = [
      [0.1, 0.2, 0.05],
      [0.15, 0.1, 0.3],
      [0.05, 0.02, 0.03],
    ]
    expect(mutualInformation(joint)).toBeGreaterThanOrEqual(0)
  })
})

describe('binaryEntropy', () => {
  it('fair coin = 1 bit', () => {
    expect(binaryEntropy(0.5)).toBeCloseTo(1.0)
  })

  it('certain outcome = 0 bits', () => {
    expect(binaryEntropy(0)).toBe(0)
    expect(binaryEntropy(1)).toBe(0)
  })

  it('symmetric: H(p) = H(1-p)', () => {
    expect(binaryEntropy(0.3)).toBeCloseTo(binaryEntropy(0.7))
  })
})

describe('anonymitySetSize', () => {
  it('4 bits → 16', () => {
    expect(anonymitySetSize(4)).toBe(16)
  })

  it('0 bits → 1 (no anonymity)', () => {
    expect(anonymitySetSize(0)).toBe(1)
  })

  it('1 bit → 2', () => {
    expect(anonymitySetSize(1)).toBe(2)
  })
})

describe('composedPrivacyScore', () => {
  it('sums independent leakages', () => {
    const result = composedPrivacyScore([
      { source: 'clustering', bits: 1.5 },
      { source: 'timing', bits: 0.8 },
      { source: 'amount', bits: 0.3 },
    ])
    expect(result.total).toBeCloseTo(2.6)
  })

  it('sorts by bits descending', () => {
    const result = composedPrivacyScore([
      { source: 'amount', bits: 0.3 },
      { source: 'clustering', bits: 1.5 },
      { source: 'timing', bits: 0.8 },
    ])
    expect(result.breakdown[0].source).toBe('clustering')
    expect(result.breakdown[2].source).toBe('amount')
  })

  it('empty leakages → 0', () => {
    expect(composedPrivacyScore([]).total).toBe(0)
  })
})
