import { describe, it, expect } from 'vitest'
import { analyseClusterSpectrum } from './spectral.js'
import { buildCoSpendGraph } from './cospend.js'
import type { Transaction } from './cospend.js'

function tx(txid: string, inputs: string[], outputs: string[]): Transaction {
  return {
    txid,
    inputs: inputs.map(a => ({ address: a, value: 50000 })),
    outputs: outputs.map((a, i) => ({ address: a, value: 49000, index: i })),
    fee: 1000, timestamp: 0, blockHeight: 100,
  }
}

/**
 * Tests for spectral graph analysis.
 *
 * Mathematical properties that MUST hold:
 * 1. Eigenvalues of normalized Laplacian are in [0, 2]
 *    — Fiedler (1973), Von Luxburg (2007) Proposition 2
 * 2. λ₁ = 0 always (trivial eigenvalue)
 * 3. λ₂ = 0 iff graph is disconnected
 * 4. λ₂ > 0 for connected graphs (algebraic connectivity)
 * 5. Number of zero eigenvalues = number of connected components
 * 6. Cluster entropy is non-negative
 */

describe('spectral analysis — Von Luxburg (2007)', () => {
  it('single address → trivial result', () => {
    const graph = buildCoSpendGraph([tx('tx1', ['a'], ['b'])])
    const result = analyseClusterSpectrum(graph, ['a'])
    expect(result.numSubClusters).toBe(1)
    expect(result.algebraicConnectivity).toBe(0)
  })

  it('two addresses → single cluster', () => {
    const graph = buildCoSpendGraph([tx('tx1', ['a', 'b'], ['c'])])
    const result = analyseClusterSpectrum(graph, ['a', 'b'])
    expect(result.numSubClusters).toBe(1)
    expect(result.subClusters.get('a')).toBe(result.subClusters.get('b'))
  })

  it('barbell graph → detects two communities', () => {
    // Two cliques connected by one edge
    const graph = buildCoSpendGraph([
      tx('t1', ['a1', 'a2'], ['x']),
      tx('t2', ['a2', 'a3'], ['y']),
      tx('t3', ['a1', 'a3'], ['z']),  // clique A
      tx('t4', ['b1', 'b2'], ['w']),
      tx('t5', ['b2', 'b3'], ['v']),
      tx('t6', ['b1', 'b3'], ['u']),  // clique B
      tx('t7', ['a3', 'b1'], ['q']),  // bridge
    ])
    const all = ['a1', 'a2', 'a3', 'b1', 'b2', 'b3']
    const result = analyseClusterSpectrum(graph, all)

    // Should find 2 sub-clusters
    const clusterA = result.subClusters.get('a1')!
    const clusterB = result.subClusters.get('b1')!
    expect(clusterA).not.toBe(clusterB)

    // All of clique A together, all of clique B together
    expect(result.subClusters.get('a2')).toBe(clusterA)
    expect(result.subClusters.get('a3')).toBe(clusterA)
    expect(result.subClusters.get('b2')).toBe(clusterB)
    expect(result.subClusters.get('b3')).toBe(clusterB)
  })

  it('connected graph has positive algebraic connectivity (λ₂ > 0)', () => {
    const graph = buildCoSpendGraph([
      tx('t1', ['a', 'b'], ['x']),
      tx('t2', ['b', 'c'], ['y']),
      tx('t3', ['c', 'd'], ['z']),
      tx('t4', ['a', 'd'], ['w']),  // cycle closes the graph
    ])
    const result = analyseClusterSpectrum(graph, ['a', 'b', 'c', 'd'])
    expect(result.algebraicConnectivity).toBeGreaterThan(0)
  })

  it('disconnected graph has λ₂ = 0', () => {
    const graph = buildCoSpendGraph([
      tx('t1', ['a', 'b'], ['x']),
      tx('t2', ['c', 'd'], ['y']),
    ])
    const result = analyseClusterSpectrum(graph, ['a', 'b', 'c', 'd'])
    expect(result.algebraicConnectivity).toBe(0)
  })

  it('bridge addresses detected at community boundary', () => {
    const graph = buildCoSpendGraph([
      tx('t1', ['a', 'b'], ['x']),
      tx('t2', ['b', 'c'], ['y']),
      tx('t3', ['c', 'd'], ['z']),
      tx('t4', ['d', 'e'], ['w']),
    ])
    const all = ['a', 'b', 'c', 'd', 'e']
    const result = analyseClusterSpectrum(graph, all)
    // Should have at least one bridge address
    expect(result.bridgeAddresses.length).toBeGreaterThan(0)
  })

  it('cluster entropy is non-negative', () => {
    const graph = buildCoSpendGraph([
      tx('t1', ['a', 'b', 'c'], ['x']),
      tx('t2', ['d', 'e'], ['y']),
    ])
    const result = analyseClusterSpectrum(graph, ['a', 'b', 'c', 'd', 'e'])
    expect(result.clusterEntropy).toBeGreaterThanOrEqual(0)
  })

  it('anomaly scores are non-negative', () => {
    const graph = buildCoSpendGraph([
      tx('t1', ['a', 'b'], ['x']),
      tx('t2', ['b', 'c'], ['y']),
      tx('t3', ['c', 'a'], ['z']),
    ])
    const result = analyseClusterSpectrum(graph, ['a', 'b', 'c'])
    for (const [, score] of result.anomalyScores) {
      expect(score).toBeGreaterThanOrEqual(0)
    }
  })
})
