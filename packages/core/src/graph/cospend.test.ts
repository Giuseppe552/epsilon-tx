import { describe, it, expect } from 'vitest'
import {
  buildCoSpendGraph,
  findClusters,
  clusterStats,
  privacyExposure,
  findBridgeTransactions,
  type Transaction,
} from './cospend.js'

function tx(txid: string, inputs: string[], outputs: string[], timestamp = 0): Transaction {
  return {
    txid,
    inputs: inputs.map(a => ({ address: a, value: 50000 })),
    outputs: outputs.map((a, i) => ({ address: a, value: 49000, index: i })),
    fee: 1000,
    timestamp,
    blockHeight: 100,
  }
}

describe('buildCoSpendGraph', () => {
  it('single-input tx creates no edges', () => {
    const graph = buildCoSpendGraph([tx('tx1', ['a'], ['b'])])
    expect(graph.addresses.size).toBe(0)
    expect(graph.edges.size).toBe(0)
  })

  it('multi-input tx creates edges between all input pairs', () => {
    const graph = buildCoSpendGraph([tx('tx1', ['a', 'b', 'c'], ['d'])])
    expect(graph.addresses.size).toBe(3)
    expect(graph.edges.get('a')?.has('b')).toBe(true)
    expect(graph.edges.get('a')?.has('c')).toBe(true)
    expect(graph.edges.get('b')?.has('c')).toBe(true)
  })

  it('edges are bidirectional', () => {
    const graph = buildCoSpendGraph([tx('tx1', ['a', 'b'], ['c'])])
    expect(graph.edges.get('a')?.has('b')).toBe(true)
    expect(graph.edges.get('b')?.has('a')).toBe(true)
  })

  it('tracks which tx created each edge', () => {
    const graph = buildCoSpendGraph([tx('tx1', ['a', 'b'], ['c'])])
    expect(graph.txLinks.get('a:b')).toEqual(['tx1'])
  })
})

describe('findClusters', () => {
  it('two separate pairs → two clusters', () => {
    const graph = buildCoSpendGraph([
      tx('tx1', ['a', 'b'], ['x']),
      tx('tx2', ['c', 'd'], ['y']),
    ])
    const clusters = findClusters(graph)
    expect(clusters.get('a')).toBe(clusters.get('b'))
    expect(clusters.get('c')).toBe(clusters.get('d'))
    expect(clusters.get('a')).not.toBe(clusters.get('c'))
  })

  it('transitive closure: a-b + b-c → all in one cluster', () => {
    const graph = buildCoSpendGraph([
      tx('tx1', ['a', 'b'], ['x']),
      tx('tx2', ['b', 'c'], ['y']),
    ])
    const clusters = findClusters(graph)
    expect(clusters.get('a')).toBe(clusters.get('b'))
    expect(clusters.get('b')).toBe(clusters.get('c'))
  })

  it('chain of 5 addresses → one cluster', () => {
    const graph = buildCoSpendGraph([
      tx('tx1', ['a', 'b'], ['x']),
      tx('tx2', ['b', 'c'], ['y']),
      tx('tx3', ['c', 'd'], ['z']),
      tx('tx4', ['d', 'e'], ['w']),
    ])
    const clusters = findClusters(graph)
    const ids = new Set(['a', 'b', 'c', 'd', 'e'].map(a => clusters.get(a)))
    expect(ids.size).toBe(1)
  })
})

describe('clusterStats', () => {
  it('returns correct cluster sizes', () => {
    const graph = buildCoSpendGraph([
      tx('tx1', ['a', 'b', 'c'], ['x']),
      tx('tx2', ['d', 'e'], ['y']),
    ])
    const clusters = findClusters(graph)
    const stats = clusterStats(clusters, graph)

    const sizes = [...stats.values()].map(s => s.size).sort((a, b) => b - a)
    expect(sizes).toEqual([3, 2])
  })

  it('tracks linking transactions', () => {
    const graph = buildCoSpendGraph([tx('tx1', ['a', 'b'], ['x'])])
    const clusters = findClusters(graph)
    const stats = clusterStats(clusters, graph)

    const cluster = [...stats.values()][0]
    expect(cluster.linkingTxs.has('tx1')).toBe(true)
  })
})

describe('privacyExposure', () => {
  it('single address in large cluster → high exposure', () => {
    const graph = buildCoSpendGraph([
      tx('tx1', ['target', 'a', 'b'], ['x']),
      tx('tx2', ['b', 'c', 'd'], ['y']),
    ])
    const clusters = findClusters(graph)
    const result = privacyExposure(['target'], clusters)
    // target is in a cluster with a, b, c, d → 5 addresses
    expect(result.exposedAddresses).toBe(5)
  })

  it('isolated address → zero exposure', () => {
    const graph = buildCoSpendGraph([tx('tx1', ['a', 'b'], ['x'])])
    const clusters = findClusters(graph)
    const result = privacyExposure(['z'], clusters) // z not in graph
    expect(result.exposedAddresses).toBe(0)
  })
})

describe('findBridgeTransactions', () => {
  it('finds the bridge in a barbell graph', () => {
    // Two groups connected by one tx: a-b-c + d-e-f, linked by b-d
    const graph = buildCoSpendGraph([
      tx('tx1', ['a', 'b'], ['x']),
      tx('tx2', ['b', 'c'], ['y']),
      tx('tx3', ['b', 'd'], ['z']),  // bridge
      tx('tx4', ['d', 'e'], ['w']),
      tx('tx5', ['d', 'f'], ['v']),
    ])
    const clusters = findClusters(graph)
    const clusterAddrs = [...clusters.keys()]

    const bridges = findBridgeTransactions(graph, clusterAddrs)
    // b-d should be a bridge (removing it splits the graph)
    const bridgeAddrs = bridges.map(b => [b.address1, b.address2].sort().join('-'))
    expect(bridgeAddrs).toContain('b-d')
  })

  it('no bridges in a fully connected cluster', () => {
    // Triangle: a-b, b-c, a-c — no bridges
    const graph = buildCoSpendGraph([
      tx('tx1', ['a', 'b'], ['x']),
      tx('tx2', ['b', 'c'], ['y']),
      tx('tx3', ['a', 'c'], ['z']),
    ])
    const bridges = findBridgeTransactions(graph, ['a', 'b', 'c'])
    expect(bridges).toHaveLength(0)
  })
})
