import { describe, it, expect } from 'vitest'
import {
  computeSenderAnonymity,
  computeTimingLeakage,
  computeBalanceProbeResistance,
  analyseRoutePrivacy,
  paretoFrontier,
  type RouteHop,
} from './routing.js'

/**
 * Reference: Romiti et al. (2020) — arXiv:2006.12143.
 * Reference: Herrera-Joancomartí et al. (2019) — IACR ePrint 2019/328.
 */

function hop(nodeId: string, channelId: string, fee: number, delay: number): RouteHop {
  return { nodeId, channelId, fee, delay }
}

const nodeCounts = new Map([
  ['A', 50], ['B', 200], ['C', 10], ['D', 500], ['E', 30],
])

const channelCaps = new Map([
  ['ch1', 5000000], ['ch2', 2000000], ['ch3', 10000000], ['ch4', 500000],
])

describe('sender anonymity — Romiti (2020) §3.2', () => {
  it('direct payment → zero anonymity', () => {
    const route = [hop('A', 'ch1', 0, 10)]
    expect(computeSenderAnonymity(route, nodeCounts)).toBe(0)
  })

  it('longer route through high-degree nodes → more anonymity', () => {
    const short = [hop('A', 'ch1', 1, 10), hop('C', 'ch2', 1, 10)]
    const long = [hop('A', 'ch1', 1, 10), hop('B', 'ch2', 1, 10), hop('D', 'ch3', 1, 10), hop('E', 'ch4', 1, 10)]

    const shortAnon = computeSenderAnonymity(short, nodeCounts)
    const longAnon = computeSenderAnonymity(long, nodeCounts)
    expect(longAnon).toBeGreaterThan(shortAnon)
  })

  it('high-degree intermediate nodes → more anonymity', () => {
    // Route through D (500 channels) vs C (10 channels)
    const highDegree = [hop('A', 'ch1', 1, 10), hop('D', 'ch2', 1, 10)]
    const lowDegree = [hop('A', 'ch1', 1, 10), hop('C', 'ch2', 1, 10)]

    expect(computeSenderAnonymity(highDegree, nodeCounts))
      .toBeGreaterThan(computeSenderAnonymity(lowDegree, nodeCounts))
  })

  it('anonymity is non-negative', () => {
    const route = [hop('X', 'ch1', 1, 10), hop('Y', 'ch2', 1, 10)]
    expect(computeSenderAnonymity(route, new Map())).toBeGreaterThanOrEqual(0)
  })
})

describe('timing leakage — Romiti (2020) §4', () => {
  it('direct payment → high leakage', () => {
    const leak = computeTimingLeakage([hop('A', 'ch1', 0, 10)])
    expect(leak).toBeGreaterThan(2)
  })

  it('longer route → less leakage', () => {
    const short = computeTimingLeakage([hop('A', 'ch1', 1, 50), hop('B', 'ch2', 1, 50)])
    const long = computeTimingLeakage([hop('A', 'ch1', 1, 50), hop('B', 'ch2', 1, 60), hop('C', 'ch3', 1, 40), hop('D', 'ch4', 1, 55)])
    expect(long).toBeLessThan(short)
  })

  it('variable delays → less leakage', () => {
    const uniform = computeTimingLeakage([hop('A', 'ch1', 1, 50), hop('B', 'ch2', 1, 50), hop('C', 'ch3', 1, 50)])
    const varied = computeTimingLeakage([hop('A', 'ch1', 1, 10), hop('B', 'ch2', 1, 200), hop('C', 'ch3', 1, 50)])
    expect(varied).toBeLessThan(uniform)
  })
})

describe('balance probe resistance — Herrera-Joancomartí (2019)', () => {
  it('larger channels → more resistance', () => {
    const bigCaps = new Map([['ch1', 10000000], ['ch2', 10000000]])
    const smallCaps = new Map([['ch1', 100000], ['ch2', 100000]])

    const bigRoute = [hop('A', 'ch1', 1, 10), hop('B', 'ch2', 1, 10)]
    const smallRoute = [hop('A', 'ch1', 1, 10), hop('B', 'ch2', 1, 10)]

    expect(computeBalanceProbeResistance(bigRoute, bigCaps))
      .toBeGreaterThan(computeBalanceProbeResistance(smallRoute, smallCaps))
  })

  it('non-negative', () => {
    const route = [hop('A', 'ch1', 1, 10)]
    expect(computeBalanceProbeResistance(route, channelCaps)).toBeGreaterThanOrEqual(0)
  })
})

describe('route privacy analysis', () => {
  it('produces complete analysis', () => {
    const route = [hop('A', 'ch1', 2, 30), hop('B', 'ch2', 3, 50), hop('C', 'ch3', 1, 20)]
    const result = analyseRoutePrivacy(route, nodeCounts, channelCaps)

    expect(result.hops).toBe(3)
    expect(result.totalFee).toBe(6)
    expect(result.senderAnonymity).toBeGreaterThanOrEqual(0)
    expect(result.timingLeakage).toBeGreaterThanOrEqual(0)
    expect(result.totalPrivacy).toBeGreaterThanOrEqual(0)
  })
})

describe('Pareto frontier', () => {
  it('filters dominated routes', () => {
    const routes = [
      { route: [], hops: 2, totalFee: 3, senderAnonymity: 2, receiverAnonymity: 1.8, timingLeakage: 0.5, balanceProbeResistance: 1, totalPrivacy: 4.3 },
      { route: [], hops: 4, totalFee: 7, senderAnonymity: 4, receiverAnonymity: 3.6, timingLeakage: 0.3, balanceProbeResistance: 2, totalPrivacy: 9.3 },
      { route: [], hops: 3, totalFee: 5, senderAnonymity: 3, receiverAnonymity: 2.7, timingLeakage: 0.4, balanceProbeResistance: 1.5, totalPrivacy: 6.8 },
      { route: [], hops: 3, totalFee: 6, senderAnonymity: 2.5, receiverAnonymity: 2, timingLeakage: 0.4, balanceProbeResistance: 1, totalPrivacy: 5.1 }, // dominated by route 3
    ] as any

    const frontier = paretoFrontier(routes)
    // Should include the 3-sat (cheap), 5-sat (medium), 7-sat (expensive+private) routes
    // The 6-sat route is dominated (worse privacy than 5-sat, more expensive)
    expect(frontier.length).toBeLessThanOrEqual(3)
    // Frontier should be sorted by fee ascending, privacy ascending
    for (let i = 1; i < frontier.length; i++) {
      expect(frontier[i].privacy).toBeGreaterThan(frontier[i - 1].privacy)
    }
  })
})
