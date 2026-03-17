import { describe, it, expect } from 'vitest'
import { computeBoltzmann } from './boltzmann.js'
import type { Transaction } from '../graph/cospend.js'

function tx(opts: {
  inputs: number[]
  outputs: number[]
  fee?: number
}): Transaction {
  return {
    txid: 'test',
    inputs: opts.inputs.map((v, i) => ({ address: `in${i}`, value: v })),
    outputs: opts.outputs.map((v, i) => ({ address: `out${i}`, value: v, index: i })),
    fee: opts.fee ?? 1000,
    timestamp: 0,
    blockHeight: 100,
  }
}

/**
 * Tests for Boltzmann entropy computation.
 *
 * Reference: LaurentMT (2016). "Introducing Boltzmann."
 * Reference: Samourai Whirlpool THEORY.md — efficiency must be 1.0.
 */

describe('equal-output CoinJoin (Whirlpool style)', () => {
  it('5 equal outputs → log₂(5!) ≈ 6.91 bits', () => {
    const result = computeBoltzmann(tx({
      inputs: [100000, 100000, 100000, 100000, 100000],
      outputs: [98000, 98000, 98000, 98000, 98000],
    }))
    expect(result.entropy).toBeCloseTo(Math.log2(120), 1) // 5! = 120
    expect(result.efficiency).toBe(1.0)
    expect(result.isLikelyCoinJoin).toBe(true)
  })

  it('3 equal outputs → log₂(3!) ≈ 2.58 bits', () => {
    const result = computeBoltzmann(tx({
      inputs: [50000, 50000, 50000],
      outputs: [49000, 49000, 49000],
    }))
    expect(result.entropy).toBeCloseTo(Math.log2(6), 1) // 3! = 6
    expect(result.isLikelyCoinJoin).toBe(true)
  })

  it('efficiency = 1.0 (max entropy for structure)', () => {
    const result = computeBoltzmann(tx({
      inputs: [100000, 100000, 100000, 100000],
      outputs: [99000, 99000, 99000, 99000],
    }))
    expect(result.efficiency).toBe(1.0)
  })
})

describe('standard transaction', () => {
  it('single output → 0 entropy', () => {
    const result = computeBoltzmann(tx({
      inputs: [50000],
      outputs: [49000],
    }))
    expect(result.entropy).toBe(0)
    expect(result.isLikelyCoinJoin).toBe(false)
  })

  it('2 outputs with distinguishable amounts → low entropy', () => {
    // 0.001 BTC (round) + 0.000345 BTC (odd) → change is obvious
    const result = computeBoltzmann(tx({
      inputs: [100000],
      outputs: [100000, 34500], // round vs odd
    }))
    expect(result.entropy).toBeLessThan(0.5)
  })

  it('2 outputs with similar roundness → higher entropy', () => {
    const result = computeBoltzmann(tx({
      inputs: [100000],
      outputs: [53217, 45783], // both odd
    }))
    expect(result.entropy).toBeCloseTo(1.0) // full 1-bit ambiguity
  })
})

describe('arbitrary-value CoinJoin (Wasabi 2.x style)', () => {
  it('multiple inputs + outputs → valid decompositions exist', () => {
    // Each input can fund any single output (all inputs > all outputs)
    // so the backtracker finds multiple valid assignments
    const result = computeBoltzmann(tx({
      inputs: [100000, 100000, 100000],
      outputs: [50000, 50000, 50000, 40000],
      fee: 10000,
    }))
    expect(result.entropy).toBeGreaterThanOrEqual(0)
    expect(result.interpretations).toBeGreaterThanOrEqual(1)
  })

  it('entropy ≤ maxEntropy always', () => {
    const result = computeBoltzmann(tx({
      inputs: [200000, 150000, 100000],
      outputs: [80000, 70000, 60000, 50000, 40000, 30000, 10000],
      fee: 10000,
    }))
    expect(result.entropy).toBeLessThanOrEqual(result.maxEntropy + 0.01)
  })

  it('link probability matrix rows sum to ~1', () => {
    const result = computeBoltzmann(tx({
      inputs: [100000, 80000, 60000],
      outputs: [50000, 40000, 30000, 15000],
      fee: 5000,
    }))
    for (const row of result.linkProbabilities.matrix) {
      const sum = row.reduce((s, v) => s + v, 0)
      if (sum > 0) expect(sum).toBeCloseTo(1.0, 1)
    }
  })
})

describe('mathematical properties', () => {
  it('entropy is non-negative', () => {
    const cases = [
      tx({ inputs: [50000], outputs: [49000] }),
      tx({ inputs: [50000, 50000], outputs: [49000, 49000] }),
      tx({ inputs: [100000], outputs: [60000, 39000] }),
    ]
    for (const t of cases) {
      expect(computeBoltzmann(t).entropy).toBeGreaterThanOrEqual(0)
    }
  })

  it('more equal outputs → more entropy (monotonic)', () => {
    const e3 = computeBoltzmann(tx({
      inputs: [50000, 50000, 50000],
      outputs: [49000, 49000, 49000],
    })).entropy

    const e5 = computeBoltzmann(tx({
      inputs: [50000, 50000, 50000, 50000, 50000],
      outputs: [49000, 49000, 49000, 49000, 49000],
    })).entropy

    expect(e5).toBeGreaterThan(e3)
  })

  it('efficiency is in [0, 1]', () => {
    const result = computeBoltzmann(tx({
      inputs: [100000, 80000, 60000],
      outputs: [50000, 40000, 30000, 15000],
      fee: 5000,
    }))
    expect(result.efficiency).toBeGreaterThanOrEqual(0)
    expect(result.efficiency).toBeLessThanOrEqual(1.01) // small tolerance
  })
})
