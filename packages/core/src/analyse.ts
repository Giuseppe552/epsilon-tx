/**
 * Unified privacy analysis — the main entry point.
 *
 * Fetches transactions for a Bitcoin address, runs all analysis
 * modules, and produces a single privacy score in bits.
 *
 * The score represents the total information an adversary with
 * full blockchain visibility can learn about the address owner.
 * Lower = more private. 0 = perfectly private (impossible in practice).
 *
 * Breakdown shows which attack surface leaks the most — this tells
 * the user where to focus their privacy improvements.
 */

import { getAddressTransactions, getAddressSummary } from './bitcoin/api.js'
import { expandGraph } from './bitcoin/expand.js'
import { buildCoSpendGraph, findClusters, clusterStats, privacyExposure, findBridgeTransactions } from './graph/cospend.js'
import { analyseClusterSpectrum } from './graph/spectral.js'
import { fingerprintTransaction, aggregateFingerprints } from './fingerprint/wallet.js'
import { generateRecommendations, type Recommendation } from './fingerprint/recommendations.js'
import { amountEntropy, amountCorrelation } from './entropy/amount.js'
import { analyseTimingPrivacy } from './entropy/timing.js'
import { createMass, fuseEvidence, HEURISTIC_RELIABILITY, MAX_LEAKAGE_BITS } from './entropy/evidence.js'
import { anonymitySetSize } from './entropy/shannon.js'
import { computeBoltzmann } from './coinjoin/boltzmann.js'
import { classifyTransaction } from './adversarial/classifier.js'
import { applyAdversaryModel, type AdversaryModel } from './entropy/adversary.js'
import type { Transaction } from './graph/cospend.js'
import type { WalletFingerprint } from './fingerprint/wallet.js'
import type { TimingAnalysis } from './entropy/timing.js'

export interface PrivacyReport {
  address: string
  summary: {
    totalScore: number          // bits — total information leakage
    anonymitySet: number        // effective anonymity set (2^(maxH - score))
    riskLevel: 'low' | 'medium' | 'high' | 'critical'
    dsBeliefExposed: number     // Dempster-Shafer Bel(EXPOSED) — fused evidence
    dsConflict: number          // conflict mass K between heuristics
  }
  breakdown: {
    source: string
    bits: number
    detail: string
  }[]
  clustering: {
    clusterSize: number
    totalClusters: number
    bridges: { address1: string; address2: string; txids: string[] }[]
  }
  fingerprint: WalletFingerprint | null
  timing: TimingAnalysis | null
  amountAnalysis: {
    avgEntropy: number
    changeDetectedCount: number
    correlations: number
  }
  coinjoinDetected: boolean
  coinjoinEntropy: number | null
  classification: { label: string; confidence: number; suspiciousness: number } | null
  adversaryModel: {
    model: string
    totalEffective: number
    topThreats: { source: string; effective: number }[]
  } | null
  recommendations: Recommendation[]
  expandedAddresses: number
  txCount: number
  fetchedAt: string
}

/**
 * Run a full privacy analysis on a Bitcoin address.
 *
 * @param address - Bitcoin address (any format)
 * @param maxTxs - Maximum transactions to fetch (default 100)
 */
export async function analyseAddress(
  address: string,
  maxTxs: number = 100,
  expandDepth: number = 0,
  adversary: AdversaryModel = 'exchange',
): Promise<PrivacyReport> {
  // Fetch transaction history
  let transactions = await getAddressTransactions(address, maxTxs)
  const summary = await getAddressSummary(address)
  let expandedCount = 0

  // Recursive expansion: follow co-spend addresses outward
  if (expandDepth > 0 && transactions.length > 0) {
    const expanded = await expandGraph(transactions, address, expandDepth, 20, 25)
    transactions = expanded.transactions
    expandedCount = expanded.expandedAddresses.length
  }

  if (transactions.length === 0) {
    return emptyReport(address)
  }

  // 1. UTXO clustering
  const graph = buildCoSpendGraph(transactions)
  const clusters = findClusters(graph)
  const stats = clusterStats(clusters, graph)
  const exposure = privacyExposure([address], clusters)

  let clusterLeakage = 0
  let clusterDetail = 'address not in co-spend graph (single-input txs only)'
  let bridges: { address1: string; address2: string; txids: string[] }[] = []

  if (exposure.exposedAddresses > 1) {
    // Leakage = log₂(cluster_size) — knowing the cluster narrows the search
    clusterLeakage = Math.log2(exposure.exposedAddresses)
    clusterDetail = `${exposure.exposedAddresses} addresses in same cluster (${exposure.clusterIds.size} cluster${exposure.clusterIds.size > 1 ? 's' : ''})`

    // Find bridge transactions
    const clusterAddrs = [...clusters.entries()]
      .filter(([, cid]) => exposure.clusterIds.has(cid))
      .map(([addr]) => addr)
    bridges = findBridgeTransactions(graph, clusterAddrs)
  }

  // 1b. Spectral analysis on largest cluster
  let spectral = null
  if (exposure.exposedAddresses >= 4) {
    const clusterAddrs = [...clusters.entries()]
      .filter(([, cid]) => exposure.clusterIds.has(cid))
      .map(([addr]) => addr)
    spectral = analyseClusterSpectrum(graph, clusterAddrs)
  }

  // 2. Wallet fingerprinting (aggregate across multiple txs for stronger signal)
  const fingerprint = transactions.length > 0 ? aggregateFingerprints(transactions) : null
  const fpLeakage = fingerprint?.anonymityReduction ?? 0

  // 3. Amount analysis (average across all transactions)
  let totalAmountEntropy = 0
  let changeDetected = 0
  for (const tx of transactions) {
    const ae = amountEntropy(tx)
    totalAmountEntropy += ae.entropy
    if (ae.changeDetected) changeDetected++
  }
  const avgAmountEntropy = transactions.length > 0 ? totalAmountEntropy / transactions.length : 0
  // Amount leakage = max possible (1 bit per 2-output tx) minus actual entropy
  const amountLeakage = Math.max(0, 1.0 - avgAmountEntropy)

  // 4. Amount correlation
  const incoming = transactions.flatMap(tx =>
    tx.outputs.filter(o => o.address === address).map(o => ({ txid: tx.txid, value: o.value }))
  )
  const outgoing = transactions.flatMap(tx =>
    tx.inputs.filter(i => i.address === address).map(i => ({ txid: tx.txid, value: i.value }))
  )
  const correlations = amountCorrelation(incoming, outgoing)
  const correlationLeakage = correlations.length > 0 ? Math.min(correlations.length * 0.3, 2.0) : 0

  // 5. Timing analysis
  const timing = analyseTimingPrivacy(transactions)

  // 6. CoinJoin detection on the most CoinJoin-like transaction
  let coinjoinDetected = false
  let coinjoinEntropy: number | null = null
  const likelyCj = transactions.find(tx => tx.inputs.length >= 3 && tx.outputs.length >= 3)
  if (likelyCj) {
    const boltzmann = computeBoltzmann(likelyCj)
    if (boltzmann.isLikelyCoinJoin) {
      coinjoinDetected = true
      coinjoinEntropy = boltzmann.entropy
    }
  }

  // 7. Adversarial classification on most recent transaction
  let classification: PrivacyReport['classification'] = null
  if (transactions.length > 0) {
    const classResult = classifyTransaction(transactions[0])
    classification = {
      label: classResult.classification,
      confidence: classResult.confidence,
      suspiciousness: classResult.suspiciousnessScore,
    }
  }

  // Compose via Dempster-Shafer evidence fusion
  // Each heuristic produces a mass function; Dempster's rule fuses them.
  // This handles conflicting evidence properly — if clustering says "exposed"
  // but timing says "private", basic addition would sum both leakages.
  // Dempster-Shafer detects the conflict and adjusts.
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

  // Convert Bel(EXPOSED) to bits: score = Bel * max_theoretical_leakage
  // max_theoretical = sum of all max leakages
  const maxTheoreticalBits = leakages.reduce((s, l) => s + (MAX_LEAKAGE_BITS[l.source] ?? 5), 0)
  const totalScore = fused.belief * maxTheoreticalBits

  // Also keep the raw leakage breakdown for display
  const sortedLeakages = [...leakages].sort((a, b) => b.bits - a.bits)

  // Risk level (calibrated to Dempster-Shafer output)
  // Apply adversary model
  const rawLeakageMap: Record<string, number> = {}
  for (const l of leakages) rawLeakageMap[l.source] = l.bits
  const adversaryResult = applyAdversaryModel(rawLeakageMap, adversary)

  let riskLevel: PrivacyReport['summary']['riskLevel'] = 'low'
  if (fused.belief > 0.7) riskLevel = 'critical'
  else if (fused.belief > 0.5) riskLevel = 'high'
  else if (fused.belief > 0.3) riskLevel = 'medium'

  return {
    address,
    summary: {
      totalScore: Math.round(totalScore * 100) / 100,
      anonymitySet: Math.round(anonymitySetSize(Math.max(0, 10 - totalScore))),
      riskLevel,
      dsBeliefExposed: Math.round(fused.belief * 1000) / 1000,
      dsConflict: Math.round(fused.conflict * 1000) / 1000,
    },
    breakdown: sortedLeakages.map(b => ({
      source: b.source,
      bits: Math.round(b.bits * 100) / 100,
      detail: detailForSource(b.source, {
        clusterDetail,
        fingerprint,
        avgAmountEntropy,
        changeDetected,
        correlations: correlations.length,
        timing,
      }),
    })),
    clustering: {
      clusterSize: exposure.exposedAddresses,
      totalClusters: stats.size,
      bridges,
    },
    fingerprint,
    timing,
    amountAnalysis: {
      avgEntropy: Math.round(avgAmountEntropy * 100) / 100,
      changeDetectedCount: changeDetected,
      correlations: correlations.length,
    },
    coinjoinDetected,
    coinjoinEntropy,
    classification,
    adversaryModel: {
      model: adversary,
      totalEffective: adversaryResult.totalEffective,
      topThreats: adversaryResult.weighted.slice(0, 3).map(w => ({ source: w.source, effective: w.effective })),
    },
    recommendations: generateRecommendations(
      fingerprint, timing, changeDetected, correlations.length, exposure.exposedAddresses,
    ),
    expandedAddresses: expandedCount,
    txCount: transactions.length,
    fetchedAt: new Date().toISOString(),
  }
}

function emptyReport(address: string): PrivacyReport {
  return {
    address,
    summary: { totalScore: 0, anonymitySet: 1024, riskLevel: 'low', dsBeliefExposed: 0, dsConflict: 0 },
    breakdown: [],
    clustering: { clusterSize: 0, totalClusters: 0, bridges: [] },
    fingerprint: null,
    timing: null,
    amountAnalysis: { avgEntropy: 0, changeDetectedCount: 0, correlations: 0 },
    coinjoinDetected: false,
    coinjoinEntropy: null,
    classification: null,
    adversaryModel: null,
    recommendations: [],
    expandedAddresses: 0,
    txCount: 0,
    fetchedAt: new Date().toISOString(),
  }
}

function detailForSource(source: string, ctx: {
  clusterDetail: string
  fingerprint: WalletFingerprint | null
  avgAmountEntropy: number
  changeDetected: number
  correlations: number
  timing: TimingAnalysis
}): string {
  switch (source) {
    case 'clustering':
      return ctx.clusterDetail
    case 'wallet-fingerprint': {
      const top = ctx.fingerprint?.scores[0]
      return top ? `likely ${top.wallet} (${(top.confidence * 100).toFixed(0)}% confidence)` : 'inconclusive'
    }
    case 'amount-analysis':
      return `avg entropy ${ctx.avgAmountEntropy.toFixed(2)} bits, change detected in ${ctx.changeDetected} txs`
    case 'amount-correlation':
      return `${ctx.correlations} near-match amount pairs found`
    case 'timing':
      return ctx.timing.timezoneConfidence > 0.3
        ? `estimated UTC${ctx.timing.timezoneEstimate >= 0 ? '+' : ''}${ctx.timing.timezoneEstimate}, ${ctx.timing.periodicityLags.length} periodic patterns`
        : `${ctx.timing.periodicityLags.length} periodic patterns detected`
    default:
      return ''
  }
}
