/**
 * Spectral analysis of the UTXO co-spend graph.
 *
 * Beyond BFS clustering (which finds connected components), spectral
 * methods reveal SUB-structure within clusters: communities, bridge
 * nodes, and anomalous addresses.
 *
 * The normalized graph Laplacian L = I - D^{-1/2} A D^{-1/2} has
 * eigenvalues in [0, 2]. The second-smallest eigenvalue λ₂ (algebraic
 * connectivity / Fiedler value) measures how tightly connected the
 * graph is. The corresponding eigenvector (Fiedler vector) naturally
 * partitions the graph at the weakest point.
 *
 * For wallet clustering this means: even within a single cluster
 * (all addresses linked by co-spending), the Fiedler vector shows
 * which groups of addresses are most loosely connected — revealing
 * sub-wallets, temporary addresses, or mixing outputs.
 *
 * Reference: Fiedler, M. (1973). "Algebraic connectivity of graphs."
 * Reference: Von Luxburg, U. (2007). "A tutorial on spectral clustering."
 */

import type { CoSpendGraph } from './cospend.js'
import { shannonEntropy } from '../entropy/shannon.js'

export interface SpectralAnalysis {
  algebraicConnectivity: number   // λ₂ — 0 = disconnected, high = robust
  subClusters: Map<string, number> // address → sub-cluster ID
  numSubClusters: number
  bridgeAddresses: string[]       // addresses at community boundaries (high Fiedler values)
  anomalyScores: Map<string, number> // per-address anomaly (distance from community center)
  clusterEntropy: number          // bits — entropy of the sub-cluster size distribution
}

/**
 * Run spectral analysis on a set of addresses within a co-spend cluster.
 *
 * @param graph - The co-spend graph
 * @param clusterAddresses - Addresses in the cluster to analyse
 * @param maxSubClusters - Maximum sub-clusters to detect (default 8)
 */
export function analyseClusterSpectrum(
  graph: CoSpendGraph,
  clusterAddresses: string[],
  maxSubClusters: number = 8,
): SpectralAnalysis {
  const n = clusterAddresses.length
  if (n < 3) {
    return {
      algebraicConnectivity: n > 1 ? 1 : 0,
      subClusters: new Map(clusterAddresses.map((a, i) => [a, 0])),
      numSubClusters: 1,
      bridgeAddresses: [],
      anomalyScores: new Map(clusterAddresses.map(a => [a, 0])),
      clusterEntropy: 0,
    }
  }

  const idxMap = new Map<string, number>()
  clusterAddresses.forEach((a, i) => idxMap.set(a, i))

  // Build adjacency matrix (within cluster only)
  const adj: number[][] = Array.from({ length: n }, () => new Array(n).fill(0))
  for (let i = 0; i < n; i++) {
    const neighbors = graph.edges.get(clusterAddresses[i])
    if (!neighbors) continue
    for (const nb of neighbors) {
      const j = idxMap.get(nb)
      if (j !== undefined) {
        adj[i][j] = 1
        adj[j][i] = 1
      }
    }
  }

  // Check for disconnected components
  const components = countComponents(n, adj)
  if (components > 1) {
    // Disconnected — skip eigendecomposition, use BFS components
    const labels = bfsLabels(n, adj)
    return {
      algebraicConnectivity: 0,
      subClusters: new Map(clusterAddresses.map((a, i) => [a, labels[i]])),
      numSubClusters: components,
      bridgeAddresses: [],
      anomalyScores: new Map(clusterAddresses.map(a => [a, 0])),
      clusterEntropy: computeClusterEntropy(labels, n),
    }
  }

  // Build normalized Laplacian: L = I - D^{-1/2} A D^{-1/2}
  const degree = new Float64Array(n)
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) degree[i] += adj[i][j]
  }

  const L: number[][] = Array.from({ length: n }, () => new Array(n).fill(0))
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      if (i === j) {
        L[i][j] = degree[i] > 0 ? 1 : 0
      } else if (adj[i][j] > 0) {
        L[i][j] = -1 / (Math.sqrt(degree[i]) * Math.sqrt(degree[j]))
      }
    }
  }

  // Find smallest eigenvalues via power iteration on shifted matrix
  const numEigen = Math.min(maxSubClusters + 1, n)
  const { eigenvalues, eigenvectors } = smallestEigenpairs(L, n, numEigen)

  const lambda2 = eigenvalues.length >= 2 ? eigenvalues[1] : 0

  // Estimate k via eigengap heuristic
  let bestGap = 0
  let k = 1
  for (let i = 0; i < Math.min(eigenvalues.length - 1, maxSubClusters); i++) {
    const gap = eigenvalues[i + 1] - eigenvalues[i]
    if (gap > bestGap) { bestGap = gap; k = i + 1 }
  }

  // Spectral embedding: first k eigenvectors
  const embedding: number[][] = Array.from({ length: n }, (_, i) =>
    eigenvectors.slice(0, k).map(ev => ev[i])
  )

  // k-means clustering on the embedding
  const labels = kMeans(embedding, k, n)
  const subClusters = new Map<string, number>()
  clusterAddresses.forEach((a, i) => subClusters.set(a, labels[i]))

  // Bridge addresses: top 15% by absolute Fiedler vector value
  const fiedler = eigenvectors.length >= 2 ? eigenvectors[1] : new Array(n).fill(0)
  const fiedlerAbs = fiedler.map(Math.abs)
  const sorted = [...fiedlerAbs].sort((a, b) => a - b)
  const threshold = sorted[Math.floor(0.85 * (sorted.length - 1))]
  const bridgeAddresses = clusterAddresses.filter((_, i) => fiedlerAbs[i] >= threshold)

  // Anomaly scores: distance from sub-cluster center in spectral space
  const anomalyScores = computeAnomalyScores(embedding, labels, n, clusterAddresses)

  const clusterEntropy = computeClusterEntropy(labels, n)

  return {
    algebraicConnectivity: lambda2,
    subClusters,
    numSubClusters: k,
    bridgeAddresses,
    anomalyScores,
    clusterEntropy,
  }
}

// --- Linear algebra primitives ---

function smallestEigenpairs(M: number[][], n: number, k: number) {
  // Find λ_max via power iteration
  const { eigenvalue: lambdaMax } = powerIteration(M, n)

  // B = λ_max·I - M (flips spectrum)
  const B: number[][] = Array.from({ length: n }, (_, i) =>
    Array.from({ length: n }, (_, j) => (i === j ? lambdaMax : 0) - M[i][j])
  )

  const eigenvalues: number[] = []
  const eigenvectors: number[][] = []
  let current = B.map(row => [...row])

  for (let t = 0; t < k && t < n; t++) {
    const { eigenvalue, eigenvector } = powerIteration(current, n)
    eigenvalues.push(lambdaMax - eigenvalue)
    eigenvectors.push(eigenvector)

    // Deflation: B' = B - λ·v·vᵀ
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) {
        current[i][j] -= eigenvalue * eigenvector[i] * eigenvector[j]
      }
    }
  }

  return { eigenvalues, eigenvectors }
}

function powerIteration(M: number[][], n: number, maxIter = 200, tol = 1e-10) {
  let v = new Array(n)
  for (let i = 0; i < n; i++) v[i] = Math.sin(i * 7.13 + 1.37)
  v = normalize(v)

  let lambda = 0
  for (let iter = 0; iter < maxIter; iter++) {
    const w = matVec(M, v, n)
    const newLambda = dot(v, w, n)
    if (Math.abs(newLambda - lambda) < tol) {
      return { eigenvalue: newLambda, eigenvector: normalize(w) }
    }
    lambda = newLambda
    v = normalize(w)
  }
  return { eigenvalue: lambda, eigenvector: v }
}

function dot(a: number[], b: number[], n: number): number {
  let s = 0; for (let i = 0; i < n; i++) s += a[i] * b[i]; return s
}

function normalize(v: number[]): number[] {
  let norm = 0; for (const x of v) norm += x * x; norm = Math.sqrt(norm)
  return norm === 0 ? v : v.map(x => x / norm)
}

function matVec(M: number[][], v: number[], n: number): number[] {
  const r = new Array(n).fill(0)
  for (let i = 0; i < n; i++) for (let j = 0; j < n; j++) r[i] += M[i][j] * v[j]
  return r
}

// --- Clustering ---

function kMeans(vectors: number[][], k: number, n: number, maxIter = 50): number[] {
  if (n === 0 || k <= 1) return new Array(n).fill(0)
  const d = vectors[0].length

  // Init: pick first centroid, then farthest point for each subsequent
  const centroids: number[][] = [[...vectors[0]]]
  for (let c = 1; c < k; c++) {
    let maxDist = -1, maxIdx = 0
    for (let i = 0; i < n; i++) {
      let minDist = Infinity
      for (const cent of centroids) {
        let dist = 0; for (let j = 0; j < d; j++) dist += (vectors[i][j] - cent[j]) ** 2
        minDist = Math.min(minDist, dist)
      }
      if (minDist > maxDist) { maxDist = minDist; maxIdx = i }
    }
    centroids.push([...vectors[maxIdx]])
  }

  let assignments = new Array(n).fill(0)
  for (let iter = 0; iter < maxIter; iter++) {
    const newAssign = new Array(n)
    for (let i = 0; i < n; i++) {
      let bestC = 0, bestDist = Infinity
      for (let c = 0; c < centroids.length; c++) {
        let dist = 0; for (let j = 0; j < d; j++) dist += (vectors[i][j] - centroids[c][j]) ** 2
        if (dist < bestDist) { bestDist = dist; bestC = c }
      }
      newAssign[i] = bestC
    }

    let changed = false
    for (let i = 0; i < n; i++) if (newAssign[i] !== assignments[i]) { changed = true; break }
    assignments = newAssign
    if (!changed) break

    for (let c = 0; c < centroids.length; c++) {
      const members = assignments.filter(a => a === c).length
      if (members === 0) continue
      for (let j = 0; j < d; j++) {
        centroids[c][j] = 0
        for (let i = 0; i < n; i++) if (assignments[i] === c) centroids[c][j] += vectors[i][j]
        centroids[c][j] /= members
      }
    }
  }
  return assignments
}

function countComponents(n: number, adj: number[][]): number {
  const visited = new Array(n).fill(false)
  let components = 0
  for (let start = 0; start < n; start++) {
    if (visited[start]) continue
    components++
    const stack = [start]
    while (stack.length > 0) {
      const node = stack.pop()!
      if (visited[node]) continue
      visited[node] = true
      for (let j = 0; j < n; j++) if (adj[node][j] > 0 && !visited[j]) stack.push(j)
    }
  }
  return components
}

function bfsLabels(n: number, adj: number[][]): number[] {
  const labels = new Array(n).fill(-1)
  let label = 0
  for (let start = 0; start < n; start++) {
    if (labels[start] >= 0) continue
    const queue = [start]
    labels[start] = label
    while (queue.length > 0) {
      const node = queue.shift()!
      for (let j = 0; j < n; j++) {
        if (adj[node][j] > 0 && labels[j] < 0) { labels[j] = label; queue.push(j) }
      }
    }
    label++
  }
  return labels
}

function computeAnomalyScores(
  embedding: number[][], labels: number[], n: number, addresses: string[]
): Map<string, number> {
  const k = Math.max(...labels) + 1
  const d = embedding[0]?.length ?? 0
  const centers: number[][] = Array.from({ length: k }, () => new Array(d).fill(0))
  const counts = new Array(k).fill(0)

  for (let i = 0; i < n; i++) {
    const c = labels[i]
    counts[c]++
    for (let j = 0; j < d; j++) centers[c][j] += embedding[i][j]
  }
  for (let c = 0; c < k; c++) {
    if (counts[c] > 0) for (let j = 0; j < d; j++) centers[c][j] /= counts[c]
  }

  const scores = new Map<string, number>()
  for (let i = 0; i < n; i++) {
    let dist = 0
    const center = centers[labels[i]]
    for (let j = 0; j < d; j++) dist += (embedding[i][j] - center[j]) ** 2
    scores.set(addresses[i], Math.sqrt(dist))
  }
  return scores
}

function computeClusterEntropy(labels: number[], n: number): number {
  const counts = new Map<number, number>()
  for (const l of labels) counts.set(l, (counts.get(l) ?? 0) + 1)
  const probs = [...counts.values()].map(c => c / n)
  return shannonEntropy(probs)
}
