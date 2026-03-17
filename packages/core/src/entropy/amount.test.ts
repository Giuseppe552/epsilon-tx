import { describe, it, expect } from 'vitest'
import { amountEntropy, roundness, amountCorrelation } from './amount.js'
import type { Transaction } from '../graph/cospend.js'

function tx(outputs: number[]): Transaction {
  return {
    txid: 'test',
    inputs: [{ address: 'a', value: outputs.reduce((s, v) => s + v, 0) + 1000 }],
    outputs: outputs.map((v, i) => ({ address: `out${i}`, value: v, index: i })),
    fee: 1000,
    timestamp: 0,
    blockHeight: 100,
  }
}

describe('roundness', () => {
  it('1 BTC (100M sats) → roundness 8', () => {
    expect(roundness(100_000_000)).toBe(8)
  })

  it('0.001 BTC (100K sats) → roundness 5', () => {
    expect(roundness(100_000)).toBe(5)
  })

  it('odd amount → roundness 0', () => {
    expect(roundness(12_345_678)).toBe(0)
  })

  it('0 → roundness 0', () => {
    expect(roundness(0)).toBe(0)
  })
})

describe('amountEntropy', () => {
  it('single output → 0 entropy', () => {
    const r = amountEntropy(tx([50000]))
    expect(r.entropy).toBe(0)
  })

  it('round vs odd → change detected', () => {
    const r = amountEntropy(tx([100_000, 34_567]))
    expect(r.changeDetected).toBe(true)
    expect(r.entropy).toBeLessThan(1.0) // low entropy = adversary knows which is change
  })

  it('both round → no change detected', () => {
    const r = amountEntropy(tx([100_000, 200_000]))
    expect(r.changeDetected).toBe(false)
    expect(r.entropy).toBe(1.0) // max ambiguity for 2 outputs
  })

  it('CoinJoin equal outputs → high entropy', () => {
    const r = amountEntropy(tx([50000, 50000, 50000, 50000, 12345]))
    expect(r.entropy).toBeGreaterThan(1.5)
  })

  it('many varying outputs → positive entropy', () => {
    const r = amountEntropy(tx([10000, 20000, 30000, 40000]))
    expect(r.entropy).toBeGreaterThan(0)
  })

  it('empty tx → 0', () => {
    const r = amountEntropy({ ...tx([]), outputs: [] })
    expect(r.entropy).toBe(0)
  })
})

describe('amountCorrelation', () => {
  it('exact match within tolerance', () => {
    const incoming = [{ txid: 'in1', value: 100_000 }]
    const outgoing = [{ txid: 'out1', value: 99_500 }]
    const matches = amountCorrelation(incoming, outgoing, 1)
    expect(matches).toHaveLength(1)
    expect(matches[0].diffPct).toBeLessThan(1)
  })

  it('no match outside tolerance', () => {
    const incoming = [{ txid: 'in1', value: 100_000 }]
    const outgoing = [{ txid: 'out1', value: 50_000 }]
    const matches = amountCorrelation(incoming, outgoing, 1)
    expect(matches).toHaveLength(0)
  })

  it('sorted by closest match first', () => {
    const incoming = [{ txid: 'in1', value: 100_000 }]
    const outgoing = [
      { txid: 'out1', value: 99_800 },
      { txid: 'out2', value: 99_500 },
    ]
    const matches = amountCorrelation(incoming, outgoing, 1)
    expect(matches[0].diffPct).toBeLessThan(matches[1].diffPct)
  })

  it('zero values ignored', () => {
    const incoming = [{ txid: 'in1', value: 0 }]
    const outgoing = [{ txid: 'out1', value: 0 }]
    expect(amountCorrelation(incoming, outgoing)).toHaveLength(0)
  })
})
