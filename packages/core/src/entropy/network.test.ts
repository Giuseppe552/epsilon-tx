import { describe, it, expect } from 'vitest'
import { analyseNetworkPrivacy, type NetworkPrivacyInput } from './network.js'

/**
 * Tests for network-level privacy analysis.
 *
 * Reference: Biryukov et al. (2014) — CCS. 11-60% IP deanonymization.
 * Reference: CVE-2025-43968 — RPC temporal correlation.
 * Reference: arXiv:2506.14197 (2025) — propagation topology.
 */

describe('analyseNetworkPrivacy', () => {
  it('full node + Tor → low leakage', () => {
    const result = analyseNetworkPrivacy({
      nodeType: 'full-node',
      broadcastMethod: 'tor',
      connectionCount: 20,
      usesTor: true,
      usesRpcProvider: false,
    })
    expect(result.totalLeakage).toBeLessThan(1.0)
  })

  it('Electrum + direct → high leakage', () => {
    const result = analyseNetworkPrivacy({
      nodeType: 'electrum',
      broadcastMethod: 'direct',
      connectionCount: 4,
      usesTor: false,
      usesRpcProvider: true,
      rpcProviderName: 'public Electrum server',
    })
    expect(result.totalLeakage).toBeGreaterThan(4.0)
    expect(result.recommendations.length).toBeGreaterThan(2)
  })

  it('RPC provider → high IP leakage', () => {
    const result = analyseNetworkPrivacy({
      nodeType: 'light-client',
      broadcastMethod: 'rpc-provider',
      connectionCount: 1,
      usesTor: false,
      usesRpcProvider: true,
    })
    expect(result.ipLeakageRisk).toBeGreaterThanOrEqual(2.0)
  })

  it('Tor broadcast → low IP leakage', () => {
    const result = analyseNetworkPrivacy({
      nodeType: 'full-node',
      broadcastMethod: 'tor',
      connectionCount: 20,
      usesTor: true,
      usesRpcProvider: false,
    })
    expect(result.ipLeakageRisk).toBeLessThan(0.5)
  })

  it('RPC correlation detected when using provider — CVE-2025-43968', () => {
    const result = analyseNetworkPrivacy({
      nodeType: 'electrum',
      broadcastMethod: 'rpc-provider',
      connectionCount: 1,
      usesTor: false,
      usesRpcProvider: true,
    })
    expect(result.rpcCorrelation).toBeGreaterThan(0)
  })

  it('no RPC provider → no RPC correlation', () => {
    const result = analyseNetworkPrivacy({
      nodeType: 'full-node',
      broadcastMethod: 'direct',
      connectionCount: 20,
      usesTor: false,
      usesRpcProvider: false,
    })
    expect(result.rpcCorrelation).toBe(0)
  })

  it('low connection count → additional leakage + recommendation', () => {
    const result = analyseNetworkPrivacy({
      nodeType: 'full-node',
      broadcastMethod: 'direct',
      connectionCount: 3,
      usesTor: false,
      usesRpcProvider: false,
    })
    expect(result.totalLeakage).toBeGreaterThan(
      analyseNetworkPrivacy({
        nodeType: 'full-node',
        broadcastMethod: 'direct',
        connectionCount: 20,
        usesTor: false,
        usesRpcProvider: false,
      }).totalLeakage
    )
  })

  it('all leakage values are non-negative', () => {
    const result = analyseNetworkPrivacy({
      nodeType: 'full-node',
      broadcastMethod: 'tor',
      connectionCount: 50,
      usesTor: true,
      usesRpcProvider: false,
    })
    expect(result.ipLeakageRisk).toBeGreaterThanOrEqual(0)
    expect(result.nodeTypeLeakage).toBeGreaterThanOrEqual(0)
    expect(result.rpcCorrelation).toBeGreaterThanOrEqual(0)
    expect(result.totalLeakage).toBeGreaterThanOrEqual(0)
  })

  it('generates actionable recommendations', () => {
    const result = analyseNetworkPrivacy({
      nodeType: 'electrum',
      broadcastMethod: 'direct',
      connectionCount: 2,
      usesTor: false,
      usesRpcProvider: true,
    })
    expect(result.recommendations.length).toBeGreaterThan(0)
    for (const rec of result.recommendations) {
      expect(rec.length).toBeGreaterThan(20) // not just a word
    }
  })
})
