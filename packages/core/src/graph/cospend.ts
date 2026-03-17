/**
 * UTXO co-spend graph for wallet clustering.
 *
 * The common-input-ownership heuristic: if two addresses appear as
 * inputs in the same transaction, they're controlled by the same entity.
 * This is the foundation of all chain analysis (Chainalysis, Elliptic, etc.).
 *
 * We model this as an undirected graph G = (V, E) where:
 *   V = set of addresses
 *   E = {(a, b) : a and b are co-inputs in some transaction}
 *
 * Wallet clusters = connected components of G.
 * Privacy exposure = |component containing your addresses| / |V|
 *
 * The transitive closure is the key insight: if A co-spends with B,
 * and B co-spends with C, then A, B, C are all the same entity —
 * even if A and C never appeared together.
 *
 * Reference: Meiklejohn et al. (2013). "A Fistful of Bitcoins:
 * Characterizing Payments Among Men with No Names." IMC.
 */

export interface Transaction {
  txid: string
  inputs: { address: string; value: number }[]
  outputs: { address: string; value: number; index: number }[]
  fee: number
  timestamp: number
  blockHeight: number
}

export interface CoSpendGraph {
  addresses: Set<string>
  edges: Map<string, Set<string>>  // adjacency list
  txLinks: Map<string, string[]>   // edge → txids that created it
}

/**
 * Build the co-spend graph from a set of transactions.
 *
 * For each transaction with multiple inputs, create edges between
 * all pairs of input addresses. O(Σ k_i²) where k_i is the number
 * of inputs in transaction i.
 */
export function buildCoSpendGraph(transactions: Transaction[]): CoSpendGraph {
  const addresses = new Set<string>()
  const edges = new Map<string, Set<string>>()
  const txLinks = new Map<string, string[]>()

  for (const tx of transactions) {
    const inputAddrs = [...new Set(tx.inputs.map(i => i.address))]
    if (inputAddrs.length < 2) continue // single-input tx: no co-spend info

    for (const addr of inputAddrs) {
      addresses.add(addr)
      if (!edges.has(addr)) edges.set(addr, new Set())
    }

    // Create edges between all pairs of input addresses
    for (let i = 0; i < inputAddrs.length; i++) {
      for (let j = i + 1; j < inputAddrs.length; j++) {
        const a = inputAddrs[i], b = inputAddrs[j]
        edges.get(a)!.add(b)
        edges.get(b)!.add(a)

        // Track which transaction created this link
        const edgeKey = a < b ? `${a}:${b}` : `${b}:${a}`
        if (!txLinks.has(edgeKey)) txLinks.set(edgeKey, [])
        txLinks.get(edgeKey)!.push(tx.txid)
      }
    }
  }

  return { addresses, edges, txLinks }
}

/**
 * Find connected components (wallet clusters) via BFS.
 *
 * Returns a Map<address, clusterId>. Addresses in the same cluster
 * are believed to be controlled by the same entity.
 */
export function findClusters(graph: CoSpendGraph): Map<string, number> {
  const clusters = new Map<string, number>()
  let clusterId = 0

  for (const addr of graph.addresses) {
    if (clusters.has(addr)) continue

    // BFS from this address
    const queue = [addr]
    clusters.set(addr, clusterId)

    while (queue.length > 0) {
      const current = queue.shift()!
      const neighbors = graph.edges.get(current)
      if (!neighbors) continue

      for (const neighbor of neighbors) {
        if (!clusters.has(neighbor)) {
          clusters.set(neighbor, clusterId)
          queue.push(neighbor)
        }
      }
    }

    clusterId++
  }

  return clusters
}

/**
 * Compute cluster statistics.
 *
 * For each cluster, returns: size, list of addresses, and the
 * transactions that linked them.
 */
export function clusterStats(
  clusters: Map<string, number>,
  graph: CoSpendGraph,
): Map<number, { size: number; addresses: string[]; linkingTxs: Set<string> }> {
  const stats = new Map<number, { size: number; addresses: string[]; linkingTxs: Set<string> }>()

  for (const [addr, cid] of clusters) {
    if (!stats.has(cid)) {
      stats.set(cid, { size: 0, addresses: [], linkingTxs: new Set() })
    }
    const s = stats.get(cid)!
    s.size++
    s.addresses.push(addr)
  }

  // Find linking transactions per cluster
  for (const [edgeKey, txids] of graph.txLinks) {
    const [a] = edgeKey.split(':')
    const cid = clusters.get(a)
    if (cid === undefined) continue
    const s = stats.get(cid)
    if (!s) continue
    for (const txid of txids) s.linkingTxs.add(txid)
  }

  return stats
}

/**
 * Compute the privacy exposure of a set of addresses.
 *
 * Privacy exposure = the fraction of the graph that's in the same
 * cluster as any of the target addresses.
 *
 * @param targetAddresses - The user's known addresses
 * @param clusters - Cluster assignments from findClusters
 * @returns Exposure score in [0, 1] and the cluster details
 */
export function privacyExposure(
  targetAddresses: string[],
  clusters: Map<string, number>,
): {
  exposedAddresses: number
  totalAddresses: number
  exposure: number
  clusterIds: Set<number>
} {
  const totalAddresses = clusters.size
  const clusterIds = new Set<number>()

  for (const addr of targetAddresses) {
    const cid = clusters.get(addr)
    if (cid !== undefined) clusterIds.add(cid)
  }

  // Count all addresses in the same clusters
  let exposedAddresses = 0
  for (const [, cid] of clusters) {
    if (clusterIds.has(cid)) exposedAddresses++
  }

  return {
    exposedAddresses,
    totalAddresses,
    exposure: totalAddresses > 0 ? exposedAddresses / totalAddresses : 0,
    clusterIds,
  }
}

/**
 * Find the weakest link in a cluster — the single transaction that,
 * if removed, would split the cluster into two.
 *
 * Uses bridge detection: an edge is a bridge if removing it increases
 * the number of connected components. Found via Tarjan's bridge-finding
 * algorithm in O(V + E).
 *
 * This is the transaction that leaked the most privacy: it connected
 * two otherwise separate groups of addresses.
 */
export function findBridgeTransactions(
  graph: CoSpendGraph,
  clusterAddresses: string[],
): { address1: string; address2: string; txids: string[] }[] {
  const addrSet = new Set(clusterAddresses)
  const bridges: { address1: string; address2: string; txids: string[] }[] = []

  // Tarjan's bridge-finding
  const disc = new Map<string, number>()
  const low = new Map<string, number>()
  const parent = new Map<string, string | null>()
  let timer = 0

  function dfs(u: string) {
    disc.set(u, timer)
    low.set(u, timer)
    timer++

    for (const v of graph.edges.get(u) ?? []) {
      if (!addrSet.has(v)) continue

      if (!disc.has(v)) {
        parent.set(v, u)
        dfs(v)
        low.set(u, Math.min(low.get(u)!, low.get(v)!))

        // Bridge condition: low[v] > disc[u]
        if (low.get(v)! > disc.get(u)!) {
          const edgeKey = u < v ? `${u}:${v}` : `${v}:${u}`
          const txids = graph.txLinks.get(edgeKey) ?? []
          bridges.push({ address1: u, address2: v, txids })
        }
      } else if (v !== parent.get(u)) {
        low.set(u, Math.min(low.get(u)!, disc.get(v)!))
      }
    }
  }

  // Start DFS from first address
  if (clusterAddresses.length > 0) {
    parent.set(clusterAddresses[0], null)
    dfs(clusterAddresses[0])
  }

  return bridges
}
