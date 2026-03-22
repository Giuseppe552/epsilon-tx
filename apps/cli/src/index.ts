#!/usr/bin/env node
/**
 * ε-tx CLI — privacy analysis for cryptocurrency transactions.
 *
 * Every command outputs JSON to stdout (pipeable). Human-readable
 * reports go to stderr (visible in terminal, invisible to pipes).
 *
 * No API keys needed for basic analysis. All data from public APIs.
 */

import {
  analyseAddress,
  analyseWallet,
  computeBoltzmann,
  analysePostMix,
  analyseRing,
  constructOptimalRing,
  analyseRoutePrivacy,
  getNode,
  getNodeChannels,
  buildRouteHop,
  getTopNodes,
  analyseCrossChain,
  searchAllBridgeTransfers,
  analyseNetworkPrivacy,
  classifyTransaction,
  getTransaction,
  getTransactionRings,
  type PrivacyReport,
  type WalletReport,
  type NetworkPrivacyInput,
} from '@etx/core'

// --- Arg parsing ---

const args = process.argv.slice(2)
const command = args[0]
const subcommand = args[1]
const target = args[1]

function flag(name: string): boolean { return args.includes(`--${name}`) }
function param(name: string, fallback: number): number {
  const idx = args.indexOf(`--${name}`)
  return idx >= 0 ? parseInt(args[idx + 1], 10) || fallback : fallback
}
function strParam(name: string): string | undefined {
  const idx = args.indexOf(`--${name}`)
  return idx >= 0 ? args[idx + 1] : undefined
}

const jsonFlag = flag('json')

// --- Validation ---

function validateBtcAddress(addr: string): boolean {
  return /^(1|3|bc1q|bc1p)[a-zA-HJ-NP-Z0-9]{25,62}$/.test(addr)
}

function validateTxid(txid: string): boolean {
  return /^[a-fA-F0-9]{64}$/.test(txid)
}

function validateMoneroHash(hash: string): boolean {
  return /^[a-fA-F0-9]{64}$/.test(hash)
}

function validateLnPubkey(pk: string): boolean {
  return /^[a-fA-F0-9]{66}$/.test(pk)
}

// --- Output helpers ---

const w = process.stderr.write.bind(process.stderr)
const out = (data: unknown) => process.stdout.write(JSON.stringify(data, null, 2) + '\n')

function die(msg: string): never {
  w(`\x1b[31merror:\x1b[0m ${msg}\n`)
  process.exit(1)
}

function progress(msg: string) {
  if (!jsonFlag) w(`\x1b[2m[*]\x1b[0m ${msg}\n`)
}

function bar(bits: number, color: string): string {
  return `${color}${'█'.repeat(Math.round(bits * 3))}\x1b[0m`
}

// --- Commands ---

async function cmdAnalyse() {
  const addr = target
  if (!addr) die('address required. usage: etx analyse <bitcoin-address>')
  if (!validateBtcAddress(addr)) die(`invalid Bitcoin address: ${addr}`)

  const maxTxs = param('max', 100)
  const expandDepth = param('expand', 0)
  const adversary = (strParam('adversary') ?? 'exchange') as 'casual' | 'exchange' | 'law-enforcement' | 'nation-state'

  progress(`analysing ${addr} (max ${maxTxs} txs, adversary=${adversary}${expandDepth > 0 ? `, expand ${expandDepth}` : ''})`)

  const report = await analyseAddress(addr, maxTxs, expandDepth, adversary)

  if (jsonFlag) { out(report); return }

  printAnalysisReport(report)
  out(report)
}

async function cmdCoinjoin() {
  const txid = subcommand
  if (!txid) die('txid required. usage: etx coinjoin <txid>')
  if (!validateTxid(txid)) die(`invalid txid: ${txid}`)

  progress(`fetching transaction ${txid.slice(0, 12)}...`)
  const tx = await getTransaction(txid)

  progress('computing Boltzmann entropy...')
  const boltzmann = computeBoltzmann(tx)

  if (jsonFlag) { out(boltzmann); return }

  w('\n')
  w(`  CoinJoin analysis — ${txid.slice(0, 16)}...\n`)
  w(`  ${'—'.repeat(50)}\n`)
  w(`  inputs:          ${tx.inputs.length}\n`)
  w(`  outputs:         ${tx.outputs.length}\n`)
  w(`  entropy:         \x1b[36m${boltzmann.entropy.toFixed(2)} bits\x1b[0m\n`)
  w(`  max entropy:     ${boltzmann.maxEntropy.toFixed(2)} bits\n`)
  w(`  efficiency:      ${(boltzmann.efficiency * 100).toFixed(1)}%\n`)
  w(`  interpretations: ${boltzmann.interpretations}\n`)
  w(`  is CoinJoin:     ${boltzmann.isLikelyCoinJoin ? '\x1b[32myes\x1b[0m' : '\x1b[33mno\x1b[0m'}\n`)
  w('\n')

  if (boltzmann.linkProbabilities.matrix.length > 0 && boltzmann.linkProbabilities.matrix.length <= 10) {
    w(`  link probability matrix (P[input → output]):\n`)
    const m = boltzmann.linkProbabilities
    for (let i = 0; i < m.inputs.length; i++) {
      const row = m.matrix[i].map(p => p.toFixed(2).padStart(5)).join(' ')
      w(`    ${m.inputs[i].slice(0, 8)}..  ${row}\n`)
    }
    w('\n')
  }

  out(boltzmann)
}

async function cmdRing() {
  const hash = subcommand
  if (!hash) die('tx hash required. usage: etx ring <monero-tx-hash> [--optimise]')
  if (!validateMoneroHash(hash)) die(`invalid Monero tx hash: ${hash}`)

  const optimise = flag('optimise') || flag('optimize')

  progress(`fetching Monero transaction rings...`)
  const rings = await getTransactionRings(hash)

  if (rings.length === 0) die('no ring inputs found in transaction')

  progress(`analysing ${rings.length} ring(s)...`)
  const results = rings.map(members => analyseRing(members))

  if (optimise && rings.length > 0) {
    progress('constructing optimal decoy ring (inverse-OSPEAD)...')
    const realAge = rings[0][0]?.age ?? 3600
    const optimal = constructOptimalRing(realAge)

    if (jsonFlag) { out({ rings: results, optimal }); return }

    for (let i = 0; i < results.length; i++) {
      const r = results[i]
      w('\n')
      w(`  ring ${i} — ${r.ringSize} members\n`)
      w(`  ${'—'.repeat(40)}\n`)
      w(`  entropy:            \x1b[36m${r.entropy} bits\x1b[0m (theoretical: ${r.theoreticalEntropy})\n`)
      w(`  entropy loss:       ${r.entropyLoss} bits\n`)
      w(`  anonymity set:      ${r.effectiveAnonymitySet}\n`)
      w(`  most likely real:   member ${r.mostLikelyReal} (${(r.mostLikelyRealProbability * 100).toFixed(1)}%)\n`)
    }

    w('\n')
    w(`  optimal ring (inverse-OSPEAD):\n`)
    w(`  ${'—'.repeat(40)}\n`)
    w(`  expected entropy:   \x1b[32m${optimal.expectedEntropy} bits\x1b[0m\n`)
    w(`  improvement:        +${optimal.improvementOverDefault} bits over default\n`)
    w(`  decoy ages:         ${optimal.selectedDecoyAges.slice(0, 5).map(a => formatAge(a)).join(', ')}...\n`)
    w('\n')

    out({ rings: results, optimal })
    return
  }

  if (jsonFlag) { out(results); return }

  for (let i = 0; i < results.length; i++) {
    const r = results[i]
    w('\n')
    w(`  ring ${i} — ${r.ringSize} members\n`)
    w(`  ${'—'.repeat(40)}\n`)
    w(`  entropy:          \x1b[36m${r.entropy} bits\x1b[0m (theoretical: ${r.theoreticalEntropy})\n`)
    w(`  entropy loss:     ${r.entropyLoss} bits\n`)
    w(`  anonymity set:    ${r.effectiveAnonymitySet}\n`)
    w(`  most likely real: member ${r.mostLikelyReal} (${(r.mostLikelyRealProbability * 100).toFixed(1)}%)\n`)
  }
  w('\n')

  out(results)
}

async function cmdRoute() {
  const from = subcommand
  const to = args[2]
  if (!from || !to) die('two node pubkeys required. usage: etx route <from-pubkey> <to-pubkey>')
  if (!validateLnPubkey(from)) die(`invalid Lightning pubkey: ${from}`)
  if (!validateLnPubkey(to)) die(`invalid Lightning pubkey: ${to}`)

  const amount = param('amount', 100000) // default 100k sats

  progress(`fetching node data for ${from.slice(0, 12)}...`)
  const fromNode = await getNode(from)
  const fromChannels = await getNodeChannels(from)

  progress(`fetching node data for ${to.slice(0, 12)}...`)
  const toNode = await getNode(to)

  // Build candidate routes (1-hop for now — direct channels)
  const nodeCounts = new Map<string, number>()
  nodeCounts.set(from, fromNode.channels)
  nodeCounts.set(to, toNode.channels)

  const channelCaps = new Map<string, number>()
  const directChannels = fromChannels.filter(ch => ch.node1 === to || ch.node2 === to)

  const routes = directChannels.map(ch => {
    const isNode1 = ch.node1 === from
    channelCaps.set(ch.id, ch.capacity)
    const hop = buildRouteHop(to, ch, amount, isNode1)
    return analyseRoutePrivacy([hop], nodeCounts, channelCaps)
  })

  if (jsonFlag) { out({ from: fromNode, to: toNode, routes }); return }

  w('\n')
  w(`  Lightning route privacy\n`)
  w(`  ${'—'.repeat(50)}\n`)
  w(`  from: ${fromNode.alias || from.slice(0, 16)} (${fromNode.channels} channels)\n`)
  w(`  to:   ${toNode.alias || to.slice(0, 16)} (${toNode.channels} channels)\n`)
  w(`  amount: ${amount} sats\n`)
  w(`  direct channels: ${directChannels.length}\n`)
  w('\n')

  if (routes.length === 0) {
    w(`  no direct channels found. multi-hop routing not yet implemented.\n\n`)
  } else {
    for (const r of routes) {
      w(`  route (${r.hops} hop): ${r.totalFee} sats fee, ${r.totalPrivacy.toFixed(2)} bits privacy\n`)
      w(`    sender anonymity:    ${r.senderAnonymity} bits\n`)
      w(`    timing leakage:      ${r.timingLeakage} bits\n`)
      w(`    balance resistance:  ${r.balanceProbeResistance} bits\n`)
    }
    w('\n')
  }

  out({ from: fromNode, to: toNode, routes })
}

async function cmdCrosschain() {
  const addr = target
  if (!addr) die('address required. usage: etx crosschain <ethereum-address>')

  progress(`searching bridge explorers for ${addr.slice(0, 12)}...`)
  const hops = await searchAllBridgeTransfers(addr)

  if (hops.length === 0) {
    if (jsonFlag) { out({ hops: [], analysis: null }); return }
    w('\n  no bridge transfers found for this address.\n\n')
    out({ hops: [], analysis: null })
    return
  }

  progress(`analysing ${hops.length} cross-chain hops...`)
  const analysis = analyseCrossChain(hops)

  if (jsonFlag) { out(analysis); return }

  w('\n')
  w(`  cross-chain privacy analysis\n`)
  w(`  ${'—'.repeat(50)}\n`)
  w(`  hops:              ${hops.length}\n`)
  w(`  chains:            ${[...new Set(hops.map(h => h.chain))].join(' → ')}\n`)
  w(`  basic composition: ${analysis.basicComposition} bits (Σ ε_i)\n`)
  w(`  advanced:          ${analysis.advancedComposition} bits (√(2k·ln(1/δ))·ε + k·ε²)\n`)
  w(`  HTLC link risk:    ${analysis.htlcLinkRisk} bits\n`)
  w(`  timing correlation:${analysis.timingCorrelation} bits\n`)
  w(`  amount correlation:${analysis.amountCorrelation} bits\n`)
  w(`  total leakage:     \x1b[33m${analysis.totalLeakage} bits\x1b[0m\n`)
  w(`  anonymity set:     ~${analysis.anonymitySet}\n`)
  w('\n')

  out(analysis)
}

async function cmdNetwork() {
  const nodeType = strParam('node-type') ?? 'unknown'
  const broadcast = strParam('broadcast') ?? 'unknown'
  const connections = param('connections', 8)
  const usesTor = flag('tor')
  const usesRpc = flag('rpc')
  const rpcName = strParam('rpc-name')

  const input: NetworkPrivacyInput = {
    nodeType: nodeType as NetworkPrivacyInput['nodeType'],
    broadcastMethod: broadcast as NetworkPrivacyInput['broadcastMethod'],
    connectionCount: connections,
    usesTor,
    usesRpcProvider: usesRpc,
    rpcProviderName: rpcName,
  }

  const result = analyseNetworkPrivacy(input)

  if (jsonFlag) { out(result); return }

  w('\n')
  w(`  network privacy assessment\n`)
  w(`  ${'—'.repeat(50)}\n`)
  w(`  node type:         ${nodeType}\n`)
  w(`  broadcast:         ${broadcast}\n`)
  w(`  connections:       ${connections}\n`)
  w(`  uses Tor:          ${usesTor}\n`)
  w('\n')
  w(`  IP leakage:        ${result.ipLeakageRisk} bits  ${bar(result.ipLeakageRisk, '\x1b[31m')}\n`)
  w(`  node type leak:    ${result.nodeTypeLeakage} bits  ${bar(result.nodeTypeLeakage, '\x1b[33m')}\n`)
  w(`  RPC correlation:   ${result.rpcCorrelation} bits  ${bar(result.rpcCorrelation, '\x1b[33m')}\n`)
  w(`  total:             \x1b[31m${result.totalLeakage} bits\x1b[0m\n`)
  w('\n')

  if (result.recommendations.length > 0) {
    w(`  recommendations:\n`)
    for (const rec of result.recommendations) {
      w(`    \x1b[33m→\x1b[0m ${rec}\n`)
    }
    w('\n')
  }

  out(result)
}

async function cmdClassify() {
  const txid = subcommand
  if (!txid) die('txid required. usage: etx classify <txid>')
  if (!validateTxid(txid)) die(`invalid txid: ${txid}`)

  progress(`fetching transaction ${txid.slice(0, 12)}...`)
  const tx = await getTransaction(txid)

  progress('classifying...')
  const result = classifyTransaction(tx)

  if (jsonFlag) { out(result); return }

  w('\n')
  w(`  adversarial classification\n`)
  w(`  ${'—'.repeat(50)}\n`)
  w(`  classification:    \x1b[36m${result.classification}\x1b[0m (${(result.confidence * 100).toFixed(1)}%)\n`)
  w(`  suspiciousness:    ${(result.suspiciousnessScore * 100).toFixed(1)}%\n`)
  w('\n')

  w(`  scores:\n`)
  for (const s of result.scores.filter(s => s.score > 0.05)) {
    w(`    ${s.label.padEnd(20)} ${(s.score * 100).toFixed(1)}%\n`)
  }
  w('\n')

  if (result.featureImportance.length > 0) {
    w(`  feature importance:\n`)
    for (const f of result.featureImportance) {
      const dir = f.direction === 'increases' ? '\x1b[31m↑\x1b[0m' : '\x1b[32m↓\x1b[0m'
      w(`    ${dir} ${f.feature.padEnd(22)} ${(f.contribution * 100).toFixed(0)}% ${f.direction}\n`)
    }
    w('\n')
  }

  if (result.perturbations.length > 0) {
    w(`  evasion suggestions:\n`)
    for (const p of result.perturbations) {
      w(`    [${p.feasibility}] ${p.action}\n`)
      w(`      → ${p.expectedClassification} (${(p.expectedConfidence * 100).toFixed(0)}%)\n`)
    }
    w('\n')
  }

  out(result)
}

async function cmdBatch() {
  // Collect all addresses from args (everything after 'batch' that looks like an address)
  const addrs: string[] = []
  for (let i = 1; i < args.length; i++) {
    if (args[i].startsWith('--')) { i++; continue } // skip flags and their values
    if (validateBtcAddress(args[i])) addrs.push(args[i])
  }

  if (addrs.length === 0) die('at least one address required. usage: etx batch <addr1> [addr2] ...')

  const maxTxs = param('max', 0)
  const expandDepth = param('expand', 0)
  const adversary = (strParam('adversary') ?? 'exchange') as 'casual' | 'exchange' | 'law-enforcement' | 'nation-state'
  const csvMode = flag('csv')
  const timelineMode = flag('timeline') || csvMode

  progress(`batch analysis: ${addrs.length} address${addrs.length > 1 ? 'es' : ''}, adversary=${adversary}`)

  const report = await analyseWallet(addrs, {
    maxTxsPerAddress: maxTxs,
    expandDepth,
    adversary,
    onProgress: (msg) => progress(msg),
  })

  if (csvMode) {
    // CSV timeline for plotting
    process.stdout.write('txid,timestamp,block_height,direction,score,anonymity_set,delta,delta_source,cluster_size\n')
    for (const p of report.timeline) {
      process.stdout.write(`${p.txid},${p.timestamp},${p.blockHeight},${p.direction},${p.score},${p.anonymitySet},${p.delta},${p.deltaSource},${p.clusterSize}\n`)
    }
    return
  }

  if (jsonFlag) { out(report); return }

  printBatchReport(report, timelineMode)
  out(report)
}

function printBatchReport(r: WalletReport, showTimeline: boolean) {
  w('\n')
  w(`  ε-tx batch privacy analysis\n`)
  w(`  ${'—'.repeat(50)}\n`)
  w(`  addresses:     ${r.addresses.length}\n`)
  w(`  transactions:  ${r.uniqueTxCount}\n`)
  w(`  time span:     ${r.timeSpan.days} days\n`)
  w('\n')

  const color = r.summary.currentScore > 6 ? '\x1b[31m'
    : r.summary.currentScore > 4 ? '\x1b[33m'
    : '\x1b[32m'

  w(`  current score: ${color}${r.summary.currentScore} bits\x1b[0m\n`)
  w(`  peak score:    ${r.summary.peakScore} bits (${r.summary.peakTxid.slice(0, 12)}...)\n`)
  w(`  best score:    ${r.summary.bestScore} bits\n`)
  w(`  avg score:     ${r.summary.averageScore} bits\n`)
  w(`  degradation:   ${r.summary.degradationRate > 0 ? '+' : ''}${r.summary.degradationRate} bits/tx\n`)

  if (r.summary.projectedExhaustion !== null) {
    w(`  projection:    \x1b[33m~${r.summary.projectedExhaustion} txs until anonymity set < 4\x1b[0m\n`)
  }
  w('\n')

  if (r.currentBreakdown.length > 0) {
    w(`  current breakdown:\n`)
    for (const b of r.currentBreakdown) {
      w(`    ${b.source.padEnd(22)} ${b.bits.toFixed(2).padStart(5)} bits  ${b.detail}\n`)
    }
    w('\n')
  }

  if (r.worstTransactions.length > 0) {
    w(`  worst transactions (privacy lost):\n`)
    for (const t of r.worstTransactions) {
      if (t.delta <= 0) continue
      const date = new Date(t.timestamp * 1000).toISOString().slice(0, 10)
      w(`    \x1b[31m+${t.delta.toFixed(2)}b\x1b[0m  ${t.txid.slice(0, 16)}...  ${date}  ${t.source}\n`)
    }
    w('\n')
  }

  if (r.bestTransactions.length > 0) {
    const improving = r.bestTransactions.filter(t => t.delta < 0)
    if (improving.length > 0) {
      w(`  best transactions (privacy gained):\n`)
      for (const t of improving) {
        const date = new Date(t.timestamp * 1000).toISOString().slice(0, 10)
        w(`    \x1b[32m${t.delta.toFixed(2)}b\x1b[0m  ${t.txid.slice(0, 16)}...  ${date}  ${t.source}\n`)
      }
      w('\n')
    }
  }

  if (showTimeline && r.timeline.length > 0) {
    w(`  timeline (${r.timeline.length} points):\n`)
    w(`    ${'txid'.padEnd(16)}  ${'date'.padEnd(10)}  ${'score'.padStart(6)}  ${'delta'.padStart(7)}  ${'cluster'.padStart(7)}  source\n`)
    w(`    ${'—'.repeat(70)}\n`)

    // show all points if <50, otherwise sample
    const points = r.timeline.length <= 50
      ? r.timeline
      : sampleTimeline(r.timeline, 50)

    for (const p of points) {
      const date = p.timestamp > 0 ? new Date(p.timestamp * 1000).toISOString().slice(0, 10) : 'unconfirmed'
      const deltaStr = p.delta === 0 ? '  0.00'
        : p.delta > 0 ? `\x1b[31m+${p.delta.toFixed(2)}\x1b[0m`
        : `\x1b[32m${p.delta.toFixed(2)}\x1b[0m`
      w(`    ${p.txid.slice(0, 16)}  ${date}  ${p.score.toFixed(2).padStart(6)}  ${deltaStr.padStart(7)}  ${String(p.clusterSize).padStart(7)}  ${p.deltaSource}\n`)
    }
    w('\n')
  }

  if (r.recommendations.length > 0) {
    w(`  recommendations:\n`)
    for (const rec of r.recommendations) {
      const icon = rec.priority === 'high' ? '\x1b[31m!\x1b[0m' : rec.priority === 'medium' ? '\x1b[33m~\x1b[0m' : '\x1b[36m·\x1b[0m'
      w(`    ${icon} ${rec.action} \x1b[2m(−${rec.estimatedSavings.toFixed(1)}b)\x1b[0m\n`)
    }
    w('\n')
  }
}

/**
 * Sample a timeline evenly to show at most N points.
 * Always includes first, last, peak, and biggest deltas.
 */
function sampleTimeline(timeline: readonly WalletReport['timeline'][number][], maxPoints: number): WalletReport['timeline'] {
  if (timeline.length <= maxPoints) return [...timeline]

  const result = new Map<number, typeof timeline[number]>()

  // always include first and last
  result.set(0, timeline[0])
  result.set(timeline.length - 1, timeline[timeline.length - 1])

  // include peak score
  let peakIdx = 0
  for (let i = 1; i < timeline.length; i++) {
    if (timeline[i].score > timeline[peakIdx].score) peakIdx = i
  }
  result.set(peakIdx, timeline[peakIdx])

  // include top 5 biggest deltas
  const byDelta = timeline.map((p, i) => ({ i, absDelta: Math.abs(p.delta) }))
    .sort((a, b) => b.absDelta - a.absDelta)
    .slice(0, 5)
  for (const { i } of byDelta) result.set(i, timeline[i])

  // fill remaining with even spacing
  const remaining = maxPoints - result.size
  const step = timeline.length / (remaining + 1)
  for (let s = 1; s <= remaining; s++) {
    const idx = Math.round(s * step)
    if (idx < timeline.length && !result.has(idx)) {
      result.set(idx, timeline[idx])
    }
  }

  // return sorted by index
  return [...result.entries()].sort((a, b) => a[0] - b[0]).map(([, p]) => p)
}

// --- Report printer ---

function printAnalysisReport(r: PrivacyReport) {
  const color = r.summary.riskLevel === 'critical' ? '\x1b[31m'
    : r.summary.riskLevel === 'high' ? '\x1b[33m'
    : r.summary.riskLevel === 'medium' ? '\x1b[33m'
    : '\x1b[32m'

  w('\n')
  w(`  ε-tx privacy analysis\n`)
  w(`  ${'—'.repeat(50)}\n`)
  w(`  address:       ${r.address}\n`)
  w(`  transactions:  ${r.txCount}\n`)
  if (r.expandedAddresses > 0) w(`  expanded:      ${r.expandedAddresses} co-spend addresses followed\n`)
  w('\n')

  w(`  privacy score: ${color}${r.summary.totalScore} bits\x1b[0m (${r.summary.riskLevel})\n`)
  w(`  anonymity set: ~${r.summary.anonymitySet}\n`)
  w(`  evidence:      Bel(exposed)=${r.summary.dsBeliefExposed}, conflict K=${r.summary.dsConflict}\n`)
  w('\n')

  if (r.breakdown.length > 0) {
    w(`  breakdown:\n`)
    for (const b of r.breakdown) {
      w(`    ${b.source.padEnd(22)} ${b.bits.toFixed(2).padStart(5)} bits  ${bar(b.bits, color)}  ${b.detail}\n`)
    }
    w('\n')
  }

  if (r.clustering.clusterSize > 1) {
    w(`  clustering:\n`)
    w(`    cluster size:  ${r.clustering.clusterSize} addresses\n`)
    if (r.clustering.bridges.length > 0) {
      w(`    bridges:       ${r.clustering.bridges.length} weakest links\n`)
      for (const b of r.clustering.bridges.slice(0, 3)) {
        w(`      ${b.address1.slice(0, 12)}... ↔ ${b.address2.slice(0, 12)}...\n`)
      }
    }
    w('\n')
  }

  if (r.fingerprint) {
    const top = r.fingerprint.scores[0]
    if (top && top.confidence > 0.2) {
      w(`  wallet: ${top.wallet} (${(top.confidence * 100).toFixed(0)}%) · ${r.fingerprint.features.scriptTypes.join('+')} · ${r.fingerprint.features.inputOrdering}/${r.fingerprint.features.outputOrdering} · ${r.fingerprint.anonymityReduction.toFixed(2)} bits leaked\n\n`)
    }
  }

  if (r.timing && r.timing.totalLeakage > 0.5) {
    w(`  timing: H=${r.timing.hourlyEntropy.toFixed(2)} bits`)
    if (r.timing.timezoneConfidence > 0.2) w(` · UTC${r.timing.timezoneEstimate >= 0 ? '+' : ''}${r.timing.timezoneEstimate}`)
    w(` · ${r.timing.activityWindow.startHour}:00-${r.timing.activityWindow.endHour}:00`)
    if (r.timing.isScheduled) w(` · \x1b[33mscheduled\x1b[0m`)
    if (r.timing.periodicityLags.length > 0) w(` · ${r.timing.periodicityLags.map(l => l.label).join(', ')}`)
    w('\n\n')
  }

  if (r.classification) {
    w(`  classification: ${r.classification.label} (${(r.classification.confidence * 100).toFixed(0)}%)`)
    if (r.classification.suspiciousness > 0.1) w(` · suspiciousness ${(r.classification.suspiciousness * 100).toFixed(0)}%`)
    w('\n')
  }

  if (r.coinjoinDetected) {
    w(`  coinjoin: \x1b[32mdetected\x1b[0m · entropy ${r.coinjoinEntropy?.toFixed(2)} bits\n`)
  }

  if (r.adversaryModel) {
    w(`  adversary: ${r.adversaryModel.model} · effective leakage ${r.adversaryModel.totalEffective} bits\n`)
    if (r.adversaryModel.topThreats.length > 0) {
      w(`    top threats: ${r.adversaryModel.topThreats.map(t => `${t.source} (${t.effective.toFixed(1)}b)`).join(', ')}\n`)
    }
  }

  w('\n')

  if (r.recommendations.length > 0) {
    w(`  fix:\n`)
    for (const rec of r.recommendations) {
      const icon = rec.priority === 'high' ? '\x1b[31m!\x1b[0m' : rec.priority === 'medium' ? '\x1b[33m~\x1b[0m' : '\x1b[36m·\x1b[0m'
      w(`    ${icon} ${rec.action} \x1b[2m(−${rec.estimatedSavings.toFixed(1)}b)\x1b[0m\n`)
    }
    w('\n')
  }
}

function formatAge(seconds: number): string {
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`
  if (seconds < 2592000) return `${Math.round(seconds / 86400)}d`
  return `${Math.round(seconds / 2592000)}mo`
}

// --- Main ---

const HELP = `ε-tx — privacy analysis for cryptocurrency transactions

  analyse <address>           Bitcoin address privacy score
    --max <n>                 max transactions (default 100)
    --expand <n>              follow co-spend graph N hops
    --adversary <model>       casual|exchange|law-enforcement|nation-state
    --json                    raw JSON only

  coinjoin <txid>             Boltzmann entropy of a transaction
  classify <txid>             how chain analysis would classify a tx
  ring <monero-hash>          Monero ring signature privacy
    --optimise                construct optimal decoy ring
  batch <addr1> [addr2] ...   full wallet history privacy timeline
    --max <n>                 max txs per address (default: all)
    --expand <n>              follow co-spend graph N hops
    --adversary <model>       casual|exchange|law-enforcement|nation-state
    --timeline                show per-transaction timeline
    --csv                     output timeline as CSV (for plotting)
  route <pubkey> <pubkey>     Lightning route privacy analysis
    --amount <sats>           payment amount (default 100000)
  crosschain <address>        cross-chain bridge linking analysis
  network                     network-level privacy assessment
    --node-type <type>        full-node|electrum|spv|light-client
    --broadcast <method>      direct|tor|vpn|rpc-provider
    --connections <n>         peer count
    --tor                     using Tor
    --rpc                     using RPC provider

examples:
  etx analyse bc1q...
  etx batch bc1q... bc1p... --timeline
  etx batch bc1q... --csv > privacy.csv
  etx coinjoin abc123...def --json | jq .efficiency
  etx ring abc123...def --optimise
  etx classify abc123...def
  etx route 02abc... 03def... --amount 50000
  etx crosschain 0xabc...
  etx network --node-type electrum --broadcast direct --rpc
`

async function main() {
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    process.stdout.write(HELP)
    return
  }

  try {
    switch (command) {
      case 'analyse': case 'analyze': await cmdAnalyse(); break
      case 'batch': case 'wallet': await cmdBatch(); break
      case 'coinjoin': case 'cj': await cmdCoinjoin(); break
      case 'ring': await cmdRing(); break
      case 'route': await cmdRoute(); break
      case 'crosschain': case 'xchain': await cmdCrosschain(); break
      case 'network': case 'net': await cmdNetwork(); break
      case 'classify': await cmdClassify(); break
      default:
        w(`unknown command: ${command}\n`)
        process.stdout.write(HELP)
    }
  } catch (err) {
    const msg = (err as Error).message
    if (msg.includes('API 4')) die(`rate limited by API — wait a moment and retry`)
    if (msg.includes('fetch failed') || msg.includes('ENOTFOUND')) die(`network error — check your connection`)
    if (msg.includes('not found')) die(msg)
    die(msg)
  }
}

main().catch(err => die(err.message))
