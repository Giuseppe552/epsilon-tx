import { describe, it, expect } from 'vitest'
import {
  detectScriptType,
  detectChangeOutput,
  fingerprintTransaction,
  type ScriptType,
} from './wallet.js'
import type { Transaction } from '../graph/cospend.js'

function tx(opts: {
  inputs: { addr: string; value: number }[]
  outputs: { addr: string; value: number }[]
}): Transaction {
  return {
    txid: 'test',
    inputs: opts.inputs.map(i => ({ address: i.addr, value: i.value })),
    outputs: opts.outputs.map((o, idx) => ({ address: o.addr, value: o.value, index: idx })),
    fee: 1000,
    timestamp: 0,
    blockHeight: 100,
  }
}

describe('detectScriptType', () => {
  it('P2PKH starts with 1', () => {
    expect(detectScriptType('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')).toBe('p2pkh')
  })

  it('P2SH starts with 3', () => {
    expect(detectScriptType('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy')).toBe('p2sh')
  })

  it('P2WPKH starts with bc1q', () => {
    expect(detectScriptType('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')).toBe('p2wpkh')
  })

  it('P2TR starts with bc1p', () => {
    expect(detectScriptType('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0')).toBe('p2tr')
  })
})

describe('detectChangeOutput', () => {
  it('script type match identifies change', () => {
    const result = detectChangeOutput(tx({
      inputs: [{ addr: 'bc1qabc', value: 100000 }],
      outputs: [
        { addr: 'bc1qchange', value: 40000 },  // same type as input (bc1q)
        { addr: '3payment', value: 59000 },     // different type (3...)
      ],
    }))
    expect(result.changeIndex).toBe(0)
    expect(result.heuristic).toBe('script-type-match')
  })

  it('round payment amount identifies change', () => {
    const result = detectChangeOutput(tx({
      inputs: [{ addr: 'bc1qabc', value: 200000 }],
      outputs: [
        { addr: 'bc1qpayment', value: 100000 },  // round (0.001 BTC)
        { addr: 'bc1qchange', value: 99000 },      // not round
      ],
    }))
    expect(result.changeIndex).toBe(1) // non-round output is change
  })

  it('more than 2 outputs returns inconclusive', () => {
    const result = detectChangeOutput(tx({
      inputs: [{ addr: 'bc1qabc', value: 300000 }],
      outputs: [
        { addr: 'bc1qa', value: 100000 },
        { addr: 'bc1qb', value: 100000 },
        { addr: 'bc1qc', value: 99000 },
      ],
    }))
    expect(result.changeIndex).toBeNull()
    expect(result.heuristic).toBe('non-standard-output-count')
  })
})

describe('fingerprintTransaction', () => {
  it('BIP-69 ordered tx scores high for Electrum', () => {
    // Outputs sorted by value ascending (BIP-69)
    const fp = fingerprintTransaction(tx({
      inputs: [
        { addr: 'bc1qaaa', value: 50000 },
        { addr: 'bc1qbbb', value: 80000 },
      ],
      outputs: [
        { addr: 'bc1qsmall', value: 30000 },
        { addr: 'bc1qlarge', value: 99000 },
      ],
    }))

    const electrum = fp.scores.find(s => s.wallet === 'electrum')
    expect(electrum).toBeDefined()
    expect(electrum!.confidence).toBeGreaterThan(0.3)
  })

  it('legacy P2PKH tx scores high for legacy wallet', () => {
    const fp = fingerprintTransaction(tx({
      inputs: [{ addr: '1aaa', value: 50000 }],
      outputs: [
        { addr: '1bbb', value: 30000 },
        { addr: '1ccc', value: 19000 },
      ],
    }))

    const legacy = fp.scores.find(s => s.wallet === 'legacy')
    expect(legacy).toBeDefined()
    expect(legacy!.confidence).toBeGreaterThan(0.5)
  })

  it('mixed script types detected', () => {
    const fp = fingerprintTransaction(tx({
      inputs: [{ addr: 'bc1qabc', value: 50000 }],
      outputs: [
        { addr: '1legacy', value: 30000 },
        { addr: 'bc1qsegwit', value: 19000 },
      ],
    }))

    expect(fp.features.mixedScriptTypes).toBe(true)
  })

  it('anonymityReduction is non-negative', () => {
    const fp = fingerprintTransaction(tx({
      inputs: [{ addr: 'bc1qabc', value: 50000 }],
      outputs: [
        { addr: 'bc1qdef', value: 30000 },
        { addr: 'bc1qghi', value: 19000 },
      ],
    }))

    expect(fp.anonymityReduction).toBeGreaterThanOrEqual(0)
  })

  it('CoinJoin-like tx scores for Wasabi', () => {
    const fp = fingerprintTransaction(tx({
      inputs: [
        { addr: 'bc1q1', value: 50000 },
        { addr: 'bc1q2', value: 50000 },
        { addr: 'bc1q3', value: 50000 },
      ],
      outputs: [
        { addr: 'bc1qa', value: 30000 },
        { addr: 'bc1qb', value: 30000 },
        { addr: 'bc1qc', value: 30000 },
        { addr: 'bc1qd', value: 30000 },
        { addr: 'bc1qe', value: 28000 },
      ],
    }))

    const wasabi = fp.scores.find(s => s.wallet === 'wasabi')
    expect(wasabi).toBeDefined()
    expect(wasabi!.confidence).toBeGreaterThan(0.2)
  })
})
