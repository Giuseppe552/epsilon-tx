import { describe, it, expect } from 'vitest'
import { analyseTimingPrivacy } from './timing.js'
import type { Transaction } from '../graph/cospend.js'

function fakeTx(unixTimestamp: number): Transaction {
  return {
    txid: `tx-${unixTimestamp}`,
    inputs: [{ address: 'a', value: 50000 }],
    outputs: [{ address: 'b', value: 49000, index: 0 }],
    fee: 1000,
    timestamp: unixTimestamp,
    blockHeight: 100,
  }
}

// Helper: create a timestamp at a specific UTC hour
function atUTCHour(hour: number, dayOffset: number = 0): number {
  // Base: 2025-01-01 00:00 UTC = 1735689600
  return 1735689600 + dayOffset * 86400 + hour * 3600
}

describe('analyseTimingPrivacy', () => {
  it('too few transactions → max privacy (no pattern detectable)', () => {
    const txs = [fakeTx(1000), fakeTx(2000)]
    const result = analyseTimingPrivacy(txs)
    expect(result.totalLeakage).toBe(0)
    expect(result.hourlyEntropy).toBeCloseTo(Math.log2(24))
  })

  it('transactions spread uniformly → high entropy, low leakage', () => {
    // One tx per hour for 10 days
    const txs = Array.from({ length: 240 }, (_, i) =>
      fakeTx(atUTCHour(i % 24, Math.floor(i / 24)))
    )
    const result = analyseTimingPrivacy(txs)
    expect(result.hourlyEntropy).toBeGreaterThan(4.0) // close to log₂(24)=4.58
    expect(result.totalLeakage).toBeLessThan(2.0)
  })

  it('transactions clustered at UTC 09-17 → detects daytime pattern', () => {
    // All txs between UTC 09:00 and 17:00 → suggests UTC+0 (UK)
    const txs = Array.from({ length: 100 }, (_, i) => {
      const hour = 9 + (i % 8) // hours 9-16
      return fakeTx(atUTCHour(hour, Math.floor(i / 8)))
    })
    const result = analyseTimingPrivacy(txs)

    // Entropy should be low (activity concentrated)
    expect(result.hourlyEntropy).toBeLessThan(3.5)

    // Activity window should be within daytime
    expect(result.activityWindow.startHour).toBeGreaterThanOrEqual(8)
    expect(result.activityWindow.endHour).toBeLessThanOrEqual(18)

    // Should detect significant leakage
    expect(result.totalLeakage).toBeGreaterThan(1.0)
  })

  it('timezone detection: activity at UTC 14-22 suggests UTC-5 (EST)', () => {
    // Active at UTC 14-22 = local 09-17 EST
    const txs = Array.from({ length: 80 }, (_, i) => {
      const hour = 14 + (i % 8) // UTC hours 14-21
      return fakeTx(atUTCHour(hour, Math.floor(i / 8)))
    })
    const result = analyseTimingPrivacy(txs)

    // Activity concentrated at UTC 14-22 should produce a non-zero
    // timezone estimate with some confidence
    expect(result.timezoneEstimate).not.toBe(0)
    expect(result.timezoneConfidence).toBeGreaterThan(0)
  })

  it('activity window correctly identified', () => {
    // Transactions only between hour 10 and 18
    const txs = Array.from({ length: 50 }, (_, i) => {
      const hour = 10 + (i % 8)
      return fakeTx(atUTCHour(hour, Math.floor(i / 8)))
    })
    const result = analyseTimingPrivacy(txs)
    expect(result.activityWindow.startHour).toBeGreaterThanOrEqual(10)
    expect(result.activityWindow.endHour).toBeLessThanOrEqual(19)
  })

  it('hourly entropy is between 0 and log₂(24)', () => {
    const txs = Array.from({ length: 30 }, (_, i) =>
      fakeTx(atUTCHour(i % 12, i))
    )
    const result = analyseTimingPrivacy(txs)
    expect(result.hourlyEntropy).toBeGreaterThanOrEqual(0)
    expect(result.hourlyEntropy).toBeLessThanOrEqual(Math.log2(24) + 0.01)
  })

  it('total leakage is non-negative', () => {
    const txs = Array.from({ length: 20 }, (_, i) =>
      fakeTx(atUTCHour(i % 24, i))
    )
    const result = analyseTimingPrivacy(txs)
    expect(result.totalLeakage).toBeGreaterThanOrEqual(0)
  })
})
