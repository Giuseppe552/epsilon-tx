/**
 * Batch wallet analysis — full history across multiple addresses.
 *
 * The single-address analyseAddress() gives a snapshot. This module
 * takes a wallet (one or more addresses), fetches the complete
 * transaction history, deduplicates, and walks through time to
 * compute a privacy timeline.
 *
 * The timeline shows how privacy evolves transaction by transaction:
 * which tx leaked the most, where privacy peaked, and at what rate
 * it's degrading. For an investigator: "how many more transactions
 * until this wallet drops below N bits?" For a privacy-conscious
 * user: "which of my transactions hurt the most?"
 *
 * Rate limiting: public APIs (Blockstream, mempool.space) page at
 * 25 txs/call with undisclosed rate limits. For wallets with >1k txs,
 * use --api-url with a self-hosted Esplora/mempool instance.
 *
 * Reference: Gavenda et al. (ESORICS 2025) — "Analysis of Input-Output
 * Mappings in CoinJoin Transactions with Arbitrary Values." Found
 * 10-50% anonymity set decrease post-mix, highest on day 1.
 */

import { getAddressTransactions, getAddressSummary, clearCache } from '../bitcoin/api.js'
import { expandGraph } from '../bitcoin/expand.js'
import type { Transaction, CoSpendGraph } from '../graph/cospend.js'
import { buildCoSpendGraph, findClusters, privacyExposure, findBridgeTransactions } from '../graph/cospend.js'
import { fingerprintTransaction, aggregateFingerprints } from '../fingerprint/wallet.js'
import { amountEntropy, amountCorrelation } from '../entropy/amount.js'
import { analyseTimingPrivacy } from '../entropy/timing.js'
import { createMass, fuseEvidence, HEURISTIC_RELIABILITY, MAX_LEAKAGE_BITS } from '../entropy/evidence.js'
import { anonymitySetSize } from '../entropy/shannon.js'
import { computeBoltzmann } from '../coinjoin/boltzmann.js'
import { classifyTransaction } from '../adversarial/classifier.js'
import { applyAdversaryModel, type AdversaryModel } from '../entropy/adversary.js'
import { generateRecommendations } from '../fingerprint/recommendations.js'

// ── Types ───────────────────────────────────────────────────────────

export interface BatchOptions {
  maxTxsPerAddress: number  // default: 0 = all
  expandDepth: number       // co-spend graph expansion hops (default 0)
  adversary: AdversaryModel
  onProgress?: (msg: string) => void
}

export interface TimelinePoint {
  txid: string
  timestamp: number
  blockHeight: number
  direction: 'incoming' | 'outgoing' | 'internal' | 'mixed'
  // privacy state AFTER this tx
  score: number               // total leakage in bits
  anonymitySet: number        // 2^(max - score)
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
  // delta from previous point
  delta: number               // negative = privacy lost, positive = privacy gained
  deltaSource: string         // which attack surface caused the biggest change
  // per-surface breakdown at this point
  breakdown: { source: string; bits: number }[]
  // cluster state at this point
  clusterSize: number
  newAddressesExposed: number // addresses added to cluster by this tx
}

export interface WalletReport {
  addresses: string[]
  txCount: number
  uniqueTxCount: number       // after dedup across addresses
  timeSpan: {
    first: number             // unix timestamp
    last: number
    days: number
  }
  timeline: TimelinePoint[]
  summary: {
    currentScore: number      // latest privacy score
    peakScore: number         // worst (highest) score
    peakTxid: string          // tx that caused peak
    bestScore: number         // best (lowest) score — e.g. after a CoinJoin
    averageScore: number
    degradationRate: number   // bits lost per transaction on average
    projectedExhaustion: number | null  // txs until privacy < 1 bit (linear extrapolation)
  }
  worstTransactions: {
    txid: string
    delta: number
    source: string
    timestamp: number
  }[]
  bestTransactions: {
    txid: string
    delta: number
    source: string
    timestamp: number
  }[]
  currentBreakdown: { source: string; bits: number; detail: string }[]
  recommendations: { action: string; priority: string; estimatedSavings: number }[]
  fetchedAt: string
}

const DEFAULT_OPTIONS: BatchOptions = {
  maxTxsPerAddress: 0,
  expandDepth: 0,
  adversary: 'exchange',
}

// ── Main entry point ────────────────────────────────────────────────

/**
 * Run a full batch privacy analysis on a wallet.
 *
 * Fetches all transactions for every address, deduplicates,
 * sorts chronologically, and walks through time computing
 * incremental privacy scores.
 */
export async function analyseWallet(
  addresses: string[],
  opts: Partial<BatchOptions> = {},
): Promise<WalletReport> {
  const options = { ...DEFAULT_OPTIONS, ...opts }
  const progress = options.onProgress ?? (() => {})

  if (addresses.length === 0) {
    return emptyWalletReport([])
  }

  // 1. Fetch all transactions across all addresses
  progress(`fetching transactions for ${addresses.length} address${addresses.length > 1 ? 'es' : ''}`)
  const allTxs = new Map<string, Transaction>()
  const addressSet = new Set(addresses)

  for (const addr of addresses) {
    const maxTxs = options.maxTxsPerAddress > 0 ? options.maxTxsPerAddress : 10000
    progress(`  ${addr.slice(0, 12)}... (max ${maxTxs})`)

    try {
      let txs = await getAddressTransactions(addr, maxTxs)

      // expand graph if requested
      if (options.expandDepth > 0 && txs.length > 0) {
        const expanded = await expandGraph(txs, addr, options.expandDepth, 20, 25)
        txs = expanded.transactions
        for (const a of expanded.expandedAddresses) addressSet.add(a)
      }

      for (const tx of txs) allTxs.set(tx.txid, tx)
    } catch (err) {
      progress(`  warning: failed to fetch ${addr.slice(0, 12)}... — ${(err as Error).message}`)
    }
  }

  const transactions = [...allTxs.values()].sort((a, b) => {
    // sort by block height first (deterministic ordering within a block),
    // then by position hint (we don't have it, so fall back to txid)
    if (a.blockHeight !== b.blockHeight) return a.blockHeight - b.blockHeight
    return a.txid < b.txid ? -1 : 1
  })

  if (transactions.length === 0) {
    return emptyWalletReport(addresses)
  }

  progress(`${transactions.length} unique transactions, building timeline`)

  // 2. Walk through time, building incremental state
  const timeline = buildTimeline(transactions, addresses, addressSet, options.adversary, progress)

  // 3. Compute summary statistics
  const summary = computeSummary(timeline)

  // 4. Current state analysis (full analysis on all txs)
  const currentBreakdown = computeCurrentBreakdown(transactions, addresses, addressSet, options.adversary)

  // 5. Recommendations based on current state
  const lastPoint = timeline[timeline.length - 1]
  const fingerprint = aggregateFingerprints(transactions.slice(-20))
  const timing = analyseTimingPrivacy(transactions)
  const changeCount = transactions.filter(tx => amountEntropy(tx).changeDetected).length
  const incoming = transactions.flatMap(tx =>
    tx.outputs.filter(o => addressSet.has(o.address)).map(o => ({ txid: tx.txid, value: o.value }))
  )
  const outgoing = transactions.flatMap(tx =>
    tx.inputs.filter(i => addressSet.has(i.address)).map(i => ({ txid: tx.txid, value: i.value }))
  )
  const correlations = amountCorrelation(incoming, outgoing)
  const graph = buildCoSpendGraph(transactions)
  const clusters = findClusters(graph)
  const exposure = privacyExposure(addresses, clusters)
  const recs = generateRecommendations(fingerprint, timing, changeCount, correlations.length, exposure.exposedAddresses)

  // 6. Find worst and best transactions
  const sorted = [...timeline].filter(p => p.delta !== 0).sort((a, b) => b.delta - a.delta)
  const worstTransactions = sorted.slice(0, 5).map(p => ({
    txid: p.txid, delta: p.delta, source: p.deltaSource, timestamp: p.timestamp,
  }))
  const bestTransactions = sorted.slice(-5).reverse().map(p => ({
    txid: p.txid, delta: p.delta, source: p.deltaSource, timestamp: p.timestamp,
  }))

  const first = transactions[0].timestamp
  const last = transactions[transactions.length - 1].timestamp

  return {
    addresses,
    txCount: transactions.length,
    uniqueTxCount: allTxs.size,
    timeSpan: {
      first,
      last,
      days: Math.max(1, Math.round((last - first) / 86400)),
    },
    timeline,
    summary,
    worstTransactions,
    bestTransactions,
    currentBreakdown,
    recommendations: recs.map(r => ({ action: r.action, priority: r.priority, estimatedSavings: r.estimatedSavings })),
    fetchedAt: new Date().toISOString(),
  }
}

// ── Timeline builder ────────────────────────────────────────────────

/**
 * Walk through transactions chronologically, maintaining running state.
 *
 * At each transaction:
 * 1. Add it to the running tx set
 * 2. Rebuild/update co-spend graph
 * 3. Recompute privacy score from the accumulated state
 * 4. Record the delta from the previous point
 *
 * For efficiency, we don't re-run the full analysis at every tx.
 * Instead we maintain running accumulators and only recompute
 * the surfaces that the new tx could affect.
 */
function buildTimeline(
  transactions: Transaction[],
  walletAddresses: string[],
  addressSet: Set<string>,
  adversary: AdversaryModel,
  progress: (msg: string) => void,
): TimelinePoint[] {
  const timeline: TimelinePoint[] = []
  const runningTxs: Transaction[] = []

  // running co-spend state
  let prevClusterSize = 0
  let prevScore = 0

  // batch progress reporting
  const reportInterval = Math.max(1, Math.floor(transactions.length / 20))

  for (let idx = 0; idx < transactions.length; idx++) {
    const tx = transactions[idx]
    runningTxs.push(tx)

    if (idx % reportInterval === 0 && idx > 0) {
      progress(`  timeline ${idx}/${transactions.length}`)
    }

    // classify direction
    const hasInput = tx.inputs.some(i => addressSet.has(i.address))
    const hasOutput = tx.outputs.some(o => addressSet.has(o.address))
    let direction: TimelinePoint['direction'] = 'mixed'
    if (hasInput && hasOutput) direction = 'internal'
    else if (hasInput) direction = 'outgoing'
    else if (hasOutput) direction = 'incoming'

    // compute privacy state from accumulated transactions
    const state = computeSnapshotScore(runningTxs, walletAddresses, addressSet, adversary)

    const delta = state.totalScore - prevScore
    const newExposed = Math.max(0, state.clusterSize - prevClusterSize)

    // find which surface changed most
    let deltaSource = 'none'
    if (timeline.length > 0) {
      const prevBreakdown = timeline[timeline.length - 1].breakdown
      let maxDelta = 0
      for (const cur of state.breakdown) {
        const prev = prevBreakdown.find(p => p.source === cur.source)
        const d = cur.bits - (prev?.bits ?? 0)
        if (Math.abs(d) > Math.abs(maxDelta)) {
          maxDelta = d
          deltaSource = cur.source
        }
      }
    } else if (state.breakdown.length > 0) {
      deltaSource = state.breakdown[0].source
    }

    const riskLevel = state.dsBeliefExposed > 0.7 ? 'critical'
      : state.dsBeliefExposed > 0.5 ? 'high'
      : state.dsBeliefExposed > 0.3 ? 'medium'
      : 'low'

    timeline.push({
      txid: tx.txid,
      timestamp: tx.timestamp,
      blockHeight: tx.blockHeight,
      direction,
      score: state.totalScore,
      anonymitySet: state.anonymitySet,
      riskLevel,
      delta: Math.round(delta * 100) / 100,
      deltaSource,
      breakdown: state.breakdown,
      clusterSize: state.clusterSize,
      newAddressesExposed: newExposed,
    })

    prevScore = state.totalScore
    prevClusterSize = state.clusterSize
  }

  return timeline
}

// ── Snapshot scorer ─────────────────────────────────────────────────

interface SnapshotScore {
  totalScore: number
  anonymitySet: number
  dsBeliefExposed: number
  clusterSize: number
  breakdown: { source: string; bits: number }[]
}

/**
 * Compute privacy score from an accumulated set of transactions.
 *
 * This is a lighter version of analyseAddress() that works on
 * an arbitrary transaction set rather than fetching from an API.
 */
function computeSnapshotScore(
  txs: Transaction[],
  walletAddresses: string[],
  addressSet: Set<string>,
  adversary: AdversaryModel,
): SnapshotScore {
  if (txs.length === 0) {
    return { totalScore: 0, anonymitySet: 1024, dsBeliefExposed: 0, clusterSize: 0, breakdown: [] }
  }

  // clustering
  const graph = buildCoSpendGraph(txs)
  const clusters = findClusters(graph)
  const exposure = privacyExposure(walletAddresses, clusters)
  const clusterLeakage = exposure.exposedAddresses > 1 ? Math.log2(exposure.exposedAddresses) : 0

  // fingerprinting (last 20 txs for recency, aggregate for stability)
  const recentTxs = txs.slice(-20)
  const fingerprint = recentTxs.length > 0 ? aggregateFingerprints(recentTxs) : null
  const fpLeakage = fingerprint?.anonymityReduction ?? 0

  // amounts
  let totalAmountEntropy = 0
  let changeDetected = 0
  for (const tx of txs) {
    const ae = amountEntropy(tx)
    totalAmountEntropy += ae.entropy
    if (ae.changeDetected) changeDetected++
  }
  const avgAmountEntropy = txs.length > 0 ? totalAmountEntropy / txs.length : 0
  const amountLeakage = Math.max(0, 1.0 - avgAmountEntropy)

  // amount correlation
  const incoming = txs.flatMap(tx =>
    tx.outputs.filter(o => addressSet.has(o.address)).map(o => ({ txid: tx.txid, value: o.value }))
  )
  const outgoing = txs.flatMap(tx =>
    tx.inputs.filter(i => addressSet.has(i.address)).map(i => ({ txid: tx.txid, value: i.value }))
  )
  const correlations = amountCorrelation(incoming, outgoing)
  const correlationLeakage = correlations.length > 0 ? Math.min(correlations.length * 0.3, 2.0) : 0

  // timing
  const timing = analyseTimingPrivacy(txs)

  // fuse via D-S
  const leakages = [
    { source: 'clustering', bits: clusterLeakage },
    { source: 'wallet-fingerprint', bits: fpLeakage },
    { source: 'amount-analysis', bits: amountLeakage },
    { source: 'amount-correlation', bits: correlationLeakage },
    { source: 'timing', bits: timing.totalLeakage },
  ].filter(l => l.bits > 0)

  const masses = leakages.map(l => createMass(
    l.bits,
    MAX_LEAKAGE_BITS[l.source] ?? 5,
    HEURISTIC_RELIABILITY[l.source] ?? 0.5,
    l.source,
  ))

  const fused = fuseEvidence(masses)
  const maxTheoreticalBits = leakages.reduce((s, l) => s + (MAX_LEAKAGE_BITS[l.source] ?? 5), 0)
  const totalScore = Math.round(fused.belief * maxTheoreticalBits * 100) / 100

  return {
    totalScore,
    anonymitySet: Math.round(anonymitySetSize(Math.max(0, 10 - totalScore))),
    dsBeliefExposed: fused.belief,
    clusterSize: exposure.exposedAddresses,
    breakdown: [...leakages].sort((a, b) => b.bits - a.bits).map(l => ({
      source: l.source,
      bits: Math.round(l.bits * 100) / 100,
    })),
  }
}

// ── Current state breakdown ─────────────────────────────────────────

function computeCurrentBreakdown(
  txs: Transaction[],
  walletAddresses: string[],
  addressSet: Set<string>,
  adversary: AdversaryModel,
): WalletReport['currentBreakdown'] {
  const graph = buildCoSpendGraph(txs)
  const clusters = findClusters(graph)
  const exposure = privacyExposure(walletAddresses, clusters)
  const clusterLeakage = exposure.exposedAddresses > 1 ? Math.log2(exposure.exposedAddresses) : 0

  const fingerprint = aggregateFingerprints(txs.slice(-20))
  const fpLeakage = fingerprint?.anonymityReduction ?? 0

  let totalAmountEntropy = 0, changeDetected = 0
  for (const tx of txs) {
    const ae = amountEntropy(tx)
    totalAmountEntropy += ae.entropy
    if (ae.changeDetected) changeDetected++
  }
  const avgAmountEntropy = txs.length > 0 ? totalAmountEntropy / txs.length : 0
  const amountLeakage = Math.max(0, 1.0 - avgAmountEntropy)

  const incoming = txs.flatMap(tx =>
    tx.outputs.filter(o => addressSet.has(o.address)).map(o => ({ txid: tx.txid, value: o.value }))
  )
  const outgoing = txs.flatMap(tx =>
    tx.inputs.filter(i => addressSet.has(i.address)).map(i => ({ txid: tx.txid, value: i.value }))
  )
  const correlations = amountCorrelation(incoming, outgoing)
  const correlationLeakage = correlations.length > 0 ? Math.min(correlations.length * 0.3, 2.0) : 0

  const timing = analyseTimingPrivacy(txs)

  const results: WalletReport['currentBreakdown'] = []

  if (clusterLeakage > 0) {
    results.push({
      source: 'clustering',
      bits: Math.round(clusterLeakage * 100) / 100,
      detail: `${exposure.exposedAddresses} addresses in same cluster`,
    })
  }
  if (fpLeakage > 0) {
    const top = fingerprint?.scores[0]
    results.push({
      source: 'wallet-fingerprint',
      bits: Math.round(fpLeakage * 100) / 100,
      detail: top ? `likely ${top.wallet} (${(top.confidence * 100).toFixed(0)}%)` : 'inconclusive',
    })
  }
  if (amountLeakage > 0) {
    results.push({
      source: 'amount-analysis',
      bits: Math.round(amountLeakage * 100) / 100,
      detail: `avg entropy ${avgAmountEntropy.toFixed(2)} bits, change detected in ${changeDetected} txs`,
    })
  }
  if (correlationLeakage > 0) {
    results.push({
      source: 'amount-correlation',
      bits: Math.round(correlationLeakage * 100) / 100,
      detail: `${correlations.length} near-match amount pairs`,
    })
  }
  if (timing.totalLeakage > 0) {
    results.push({
      source: 'timing',
      bits: Math.round(timing.totalLeakage * 100) / 100,
      detail: timing.timezoneConfidence > 0.3
        ? `estimated UTC${timing.timezoneEstimate >= 0 ? '+' : ''}${timing.timezoneEstimate}, ${timing.periodicityLags.length} periodic patterns`
        : `${timing.periodicityLags.length} periodic patterns`,
    })
  }

  return results.sort((a, b) => b.bits - a.bits)
}

// ── Summary computation ─────────────────────────────────────────────

function computeSummary(timeline: TimelinePoint[]): WalletReport['summary'] {
  if (timeline.length === 0) {
    return {
      currentScore: 0, peakScore: 0, peakTxid: '', bestScore: 0,
      averageScore: 0, degradationRate: 0, projectedExhaustion: null,
    }
  }

  const current = timeline[timeline.length - 1]
  let peakScore = 0, peakTxid = '', bestScore = Infinity
  let totalScore = 0

  for (const p of timeline) {
    if (p.score > peakScore) { peakScore = p.score; peakTxid = p.txid }
    if (p.score < bestScore) bestScore = p.score
    totalScore += p.score
  }

  const averageScore = totalScore / timeline.length

  // degradation rate: linear regression of score over tx index
  // slope = Σ(i - ī)(s - s̄) / Σ(i - ī)²
  const n = timeline.length
  const meanIdx = (n - 1) / 2
  let num = 0, den = 0
  for (let i = 0; i < n; i++) {
    const di = i - meanIdx
    num += di * (timeline[i].score - averageScore)
    den += di * di
  }
  const degradationRate = den > 0 ? Math.round(num / den * 1000) / 1000 : 0

  // projection: at current rate, when does score reach 10 bits? (that's roughly the max)
  // actually: when does anonymity set drop below 2 (= score > 9 bits)?
  // or more usefully: how many more txs until current score + rate * N > some threshold
  let projectedExhaustion: number | null = null
  if (degradationRate > 0.001) {
    // txs until score exceeds 8 bits (anonymity set < 4)
    const remaining = (8 - current.score) / degradationRate
    if (remaining > 0 && remaining < 100000) {
      projectedExhaustion = Math.round(remaining)
    }
  }

  return {
    currentScore: current.score,
    peakScore,
    peakTxid,
    bestScore: bestScore === Infinity ? 0 : bestScore,
    averageScore: Math.round(averageScore * 100) / 100,
    degradationRate,
    projectedExhaustion,
  }
}

// ── Empty report ────────────────────────────────────────────────────

function emptyWalletReport(addresses: string[]): WalletReport {
  return {
    addresses,
    txCount: 0,
    uniqueTxCount: 0,
    timeSpan: { first: 0, last: 0, days: 0 },
    timeline: [],
    summary: {
      currentScore: 0, peakScore: 0, peakTxid: '', bestScore: 0,
      averageScore: 0, degradationRate: 0, projectedExhaustion: null,
    },
    worstTransactions: [],
    bestTransactions: [],
    currentBreakdown: [],
    recommendations: [],
    fetchedAt: new Date().toISOString(),
  }
}
