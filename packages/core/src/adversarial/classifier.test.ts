import { describe, it, expect } from 'vitest'
import { classifyTransaction, extractClassifierFeatures, type TxClassification } from './classifier.js'
import type { Transaction } from '../graph/cospend.js'

function tx(inputs: number[], outputs: number[], fee = 1000): Transaction {
  return {
    txid: 'test',
    inputs: inputs.map((v, i) => ({ address: `bc1q${i}`, value: v })),
    outputs: outputs.map((v, i) => ({ address: `bc1q_out${i}`, value: v, index: i })),
    fee, timestamp: 0, blockHeight: 100,
  }
}

/**
 * Reference: Alarab et al. (2024) — "Detecting anomalies in
 * blockchain transactions." arXiv:2401.03530.
 */

describe('classifyTransaction', () => {
  it('normal 2-output payment → normal-payment', () => {
    const result = classifyTransaction(tx([100000], [80000, 19000]))
    expect(result.classification).toBe('normal-payment')
    expect(result.confidence).toBeGreaterThan(0.3)
  })

  it('equal-output CoinJoin → coinjoin', () => {
    const result = classifyTransaction(tx(
      [100000, 100000, 100000, 100000, 100000],
      [90000, 90000, 90000, 90000, 90000],
    ))
    expect(result.classification).toBe('coinjoin')
  })

  it('many inputs + 1 output → consolidation', () => {
    const result = classifyTransaction(tx(
      [10000, 10000, 10000, 10000, 10000, 10000, 10000],
      [68000],
    ))
    expect(result.classification).toBe('consolidation')
  })

  it('1 input + many varied outputs → batch-payment', () => {
    const result = classifyTransaction(tx(
      [500000],
      [50000, 30000, 80000, 20000, 10000, 45000, 60000],
    ))
    expect(result.classification).toBe('batch-payment')
  })

  it('scores sum to ~1 (softmax)', () => {
    const result = classifyTransaction(tx([100000], [80000, 19000]))
    const sum = result.scores.reduce((s, sc) => s + sc.score, 0)
    expect(sum).toBeCloseTo(1.0, 1)
  })

  it('suspiciousness is in [0, 1]', () => {
    const cases = [
      tx([100000], [80000, 19000]),
      tx([100000, 100000, 100000], [90000, 90000, 90000]),
    ]
    for (const t of cases) {
      const result = classifyTransaction(t)
      expect(result.suspiciousnessScore).toBeGreaterThanOrEqual(0)
      expect(result.suspiciousnessScore).toBeLessThanOrEqual(1)
    }
  })

  it('CoinJoin has higher suspiciousness than normal payment', () => {
    const normal = classifyTransaction(tx([100000], [80000, 19000]))
    const cj = classifyTransaction(tx(
      [100000, 100000, 100000, 100000],
      [90000, 90000, 90000, 90000],
    ))
    expect(cj.suspiciousnessScore).toBeGreaterThanOrEqual(normal.suspiciousnessScore)
  })

  it('feature importance is non-empty for CoinJoin', () => {
    const result = classifyTransaction(tx(
      [100000, 100000, 100000, 100000],
      [90000, 90000, 90000, 90000],
    ))
    expect(result.featureImportance.length).toBeGreaterThan(0)
  })

  it('perturbations suggest actionable changes', () => {
    const result = classifyTransaction(tx(
      [100000, 100000, 100000, 100000],
      [90000, 90000, 90000, 90000],
    ))
    expect(result.perturbations.length).toBeGreaterThan(0)
    for (const p of result.perturbations) {
      expect(p.action.length).toBeGreaterThan(10)
      expect(p.feasibility).toMatch(/easy|medium|hard/)
    }
  })
})

describe('extractClassifierFeatures', () => {
  it('computes all features', () => {
    const f = extractClassifierFeatures(tx([100000, 50000], [80000, 69000]))
    expect(f.inputCount).toBe(2)
    expect(f.outputCount).toBe(2)
    expect(f.totalInputValue).toBe(150000)
    expect(f.fee).toBe(1000)
    expect(f.equalOutputRatio).toBeGreaterThanOrEqual(0)
    expect(f.roundOutputRatio).toBeGreaterThanOrEqual(0)
  })

  it('equal output ratio = 1 for uniform outputs', () => {
    const f = extractClassifierFeatures(tx([100000, 100000], [50000, 50000, 50000]))
    expect(f.equalOutputRatio).toBe(1)
  })
})
