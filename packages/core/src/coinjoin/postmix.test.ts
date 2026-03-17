import { describe, it, expect } from 'vitest'
import { analysePostMix } from './postmix.js'
import type { BoltzmannResult } from './boltzmann.js'
import type { Transaction } from '../graph/cospend.js'

const mixResult: BoltzmannResult = {
  entropy: 6.9,
  maxEntropy: 6.9,
  efficiency: 1.0,
  interpretations: 120,
  linkProbabilities: { inputs: [], outputs: [], matrix: [] },
  isLikelyCoinJoin: true,
  txid: 'mix-tx-001',
}

function tx(opts: { txid: string; inputs: string[]; outputs: string[]; time: number }): Transaction {
  return {
    txid: opts.txid,
    inputs: opts.inputs.map(a => ({ address: a, value: 50000 })),
    outputs: opts.outputs.map((a, i) => ({ address: a, value: 49000, index: i })),
    fee: 1000,
    timestamp: opts.time,
    blockHeight: 100,
  }
}

/**
 * Reference: Maurer et al. (2025) — arXiv 2510.17284, §5
 */

describe('post-mix degradation', () => {
  const mixOutputs = ['mixed-a', 'mixed-b', 'mixed-c', 'mixed-d', 'mixed-e']
  const mixTime = 1700000000

  it('no subsequent spending → no degradation', () => {
    const result = analysePostMix(mixResult, mixOutputs, [])
    expect(result.degradation).toBe(0)
    expect(result.actualEntropy).toBeCloseTo(6.9)
    expect(result.issues).toHaveLength(0)
  })

  it('consolidation: 2 mix outputs spent together → critical', () => {
    const result = analysePostMix(mixResult, mixOutputs, [
      tx({ txid: 'spend-1', inputs: ['mixed-a', 'mixed-b'], outputs: ['dest'], time: mixTime + 86400 }),
    ])
    const consol = result.issues.find(i => i.type === 'consolidation')
    expect(consol).toBeDefined()
    expect(consol!.severity).toBe('critical')
    expect(result.degradation).toBeGreaterThan(0)
    expect(result.actualEntropy).toBeLessThan(6.9)
  })

  it('toxic change: mix output + non-mix input → high', () => {
    const result = analysePostMix(mixResult, mixOutputs, [
      tx({ txid: 'spend-2', inputs: ['mixed-a', 'unmixed-x'], outputs: ['dest'], time: mixTime + 86400 }),
    ])
    const toxic = result.issues.find(i => i.type === 'toxic-change')
    expect(toxic).toBeDefined()
    expect(toxic!.severity).toBe('high')
  })

  it('fast spending: <1h after mix → timing issue', () => {
    const result = analysePostMix(mixResult, mixOutputs, [
      // Mix tx itself (to establish timestamp)
      tx({ txid: 'mix-tx-001', inputs: ['pre-a'], outputs: ['mixed-a'], time: mixTime }),
      // Spend 30 minutes later
      tx({ txid: 'spend-3', inputs: ['mixed-a'], outputs: ['dest'], time: mixTime + 1800 }),
    ])
    const timing = result.issues.find(i => i.type === 'timing')
    expect(timing).toBeDefined()
    expect(timing!.severity).toBe('medium')
  })

  it('degradation percentage is correct', () => {
    const result = analysePostMix(mixResult, mixOutputs, [
      tx({ txid: 'spend-4', inputs: ['mixed-a', 'mixed-b', 'mixed-c'], outputs: ['dest'], time: mixTime + 86400 }),
    ])
    // Consolidation of 3 outputs → significant degradation
    expect(result.degradationPct).toBeGreaterThan(10)
    expect(result.degradationPct).toBeLessThanOrEqual(100)
  })

  it('actual entropy is non-negative', () => {
    // Worst case: all outputs consolidated
    const result = analysePostMix(mixResult, mixOutputs, [
      tx({ txid: 'spend-all', inputs: mixOutputs, outputs: ['dest'], time: mixTime + 86400 }),
    ])
    expect(result.actualEntropy).toBeGreaterThanOrEqual(0)
  })

  it('issues sorted by bitsLost descending', () => {
    const result = analysePostMix(mixResult, mixOutputs, [
      tx({ txid: 'mix-tx-001', inputs: ['pre-a'], outputs: ['mixed-a'], time: mixTime }),
      tx({ txid: 's1', inputs: ['mixed-a', 'mixed-b'], outputs: ['d1'], time: mixTime + 1800 }),
      tx({ txid: 's2', inputs: ['mixed-c', 'unmixed-x'], outputs: ['d2'], time: mixTime + 86400 }),
    ])
    for (let i = 1; i < result.issues.length; i++) {
      expect(result.issues[i].bitsLost).toBeLessThanOrEqual(result.issues[i - 1].bitsLost)
    }
  })
})
