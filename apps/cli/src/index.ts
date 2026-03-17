#!/usr/bin/env node
/**
 * ε-tx CLI — privacy analysis for Bitcoin addresses.
 *
 * Usage:
 *   etx analyse <address>              analyse a Bitcoin address
 *   etx analyse <address> --json       output raw JSON
 *   etx analyse <address> --max 200    fetch up to 200 transactions
 */

import { analyseAddress } from '@etx/core'
import type { PrivacyReport } from '@etx/core'

const args = process.argv.slice(2)
const command = args[0]
const target = args[1]
const jsonFlag = args.includes('--json')
const expandIdx = args.indexOf('--expand')
const expandDepth = expandIdx >= 0 ? parseInt(args[expandIdx + 1], 10) || 1 : 0
const maxIdx = args.indexOf('--max')
const maxTxs = maxIdx >= 0 ? parseInt(args[maxIdx + 1], 10) || 100 : 100

const HELP = `ε-tx — privacy analysis for cryptocurrency transactions

usage:
  etx analyse <address>                analyse a Bitcoin address
  etx analyse <address> --json         raw JSON output
  etx analyse <address> --max 200      fetch up to 200 transactions
  etx analyse <address> --expand 1     follow co-spend addresses 1 hop out

example:
  etx analyse bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
  etx analyse 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa --expand 1 --json | jq .recommendations
`

async function main() {
  if (!command || command === 'help' || command === '--help') {
    process.stdout.write(HELP)
    return
  }

  if (command === 'analyse' || command === 'analyze') {
    if (!target) {
      process.stderr.write('error: address required\n')
      process.exit(1)
    }

    process.stderr.write(`[*] analysing ${target} (max ${maxTxs} txs${expandDepth > 0 ? `, expand depth ${expandDepth}` : ''})\n`)

    try {
      const report = await analyseAddress(target, maxTxs, expandDepth)

      if (jsonFlag) {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n')
      } else {
        printReport(report)
      }
    } catch (err) {
      process.stderr.write(`error: ${(err as Error).message}\n`)
      process.exit(1)
    }

    return
  }

  process.stdout.write(HELP)
}

function printReport(r: PrivacyReport) {
  const w = process.stderr.write.bind(process.stderr)

  w('\n')
  w(`  ε-tx privacy analysis\n`)
  w(`  ${'—'.repeat(50)}\n`)
  w(`  address:       ${r.address}\n`)
  w(`  transactions:  ${r.txCount}\n`)
  w(`  fetched:       ${r.fetchedAt}\n`)
  w('\n')

  // Score
  const color = r.summary.riskLevel === 'critical' ? '\x1b[31m'
    : r.summary.riskLevel === 'high' ? '\x1b[33m'
    : r.summary.riskLevel === 'medium' ? '\x1b[33m'
    : '\x1b[32m'
  const reset = '\x1b[0m'

  w(`  privacy score: ${color}${r.summary.totalScore} bits${reset} (${r.summary.riskLevel})\n`)
  w(`  anonymity set: ~${r.summary.anonymitySet}\n`)
  w(`  evidence:      Bel(exposed)=${r.summary.dsBeliefExposed}, conflict K=${r.summary.dsConflict}\n`)
  w('\n')

  // Breakdown
  if (r.breakdown.length > 0) {
    w(`  breakdown:\n`)
    for (const b of r.breakdown) {
      const bar = '█'.repeat(Math.round(b.bits * 3))
      w(`    ${b.source.padEnd(22)} ${b.bits.toFixed(2).padStart(5)} bits  ${color}${bar}${reset}  ${b.detail}\n`)
    }
    w('\n')
  }

  // Clustering
  if (r.clustering.clusterSize > 1) {
    w(`  clustering:\n`)
    w(`    cluster size:  ${r.clustering.clusterSize} addresses\n`)
    if (r.clustering.bridges.length > 0) {
      w(`    bridge txs:    ${r.clustering.bridges.length} (weakest links)\n`)
      for (const b of r.clustering.bridges.slice(0, 3)) {
        w(`      ${b.address1.slice(0, 12)}... ↔ ${b.address2.slice(0, 12)}... via ${b.txids[0]?.slice(0, 12)}...\n`)
      }
    }
    w('\n')
  }

  // Fingerprint
  if (r.fingerprint) {
    const top = r.fingerprint.scores[0]
    if (top && top.confidence > 0.2) {
      w(`  wallet fingerprint:\n`)
      w(`    likely:        ${top.wallet} (${(top.confidence * 100).toFixed(0)}%)\n`)
      w(`    script types:  ${r.fingerprint.features.scriptTypes.join(', ')}\n`)
      w(`    ordering:      inputs=${r.fingerprint.features.inputOrdering}, outputs=${r.fingerprint.features.outputOrdering}\n`)
      w(`    info leaked:   ${r.fingerprint.anonymityReduction.toFixed(2)} bits\n`)
      w('\n')
    }
  }

  // Timing
  if (r.timing && r.timing.totalLeakage > 0.5) {
    w(`  timing analysis:\n`)
    w(`    hourly entropy: ${r.timing.hourlyEntropy.toFixed(2)} bits (max ${Math.log2(24).toFixed(2)})\n`)
    if (r.timing.timezoneConfidence > 0.2) {
      const tz = r.timing.timezoneEstimate
      w(`    timezone est:   UTC${tz >= 0 ? '+' : ''}${tz} (${(r.timing.timezoneConfidence * 100).toFixed(0)}% confidence)\n`)
    }
    w(`    activity:       ${r.timing.activityWindow.startHour}:00 - ${r.timing.activityWindow.endHour}:00 UTC\n`)
    if (r.timing.isScheduled) {
      w(`    scheduled:      \x1b[33myes\x1b[0m (KS test rejected random timing)\n`)
    }
    if (r.timing.periodicityLags.length > 0) {
      w(`    patterns:       ${r.timing.periodicityLags.map(l => `${l.label} (${l.strength.toFixed(1)}x)`).join(', ')}\n`)
    }
    w('\n')
  }

  // Amount
  if (r.amountAnalysis.changeDetectedCount > 0 || r.amountAnalysis.correlations > 0) {
    w(`  amounts:\n`)
    w(`    avg entropy:   ${r.amountAnalysis.avgEntropy} bits\n`)
    w(`    change found:  ${r.amountAnalysis.changeDetectedCount} transactions\n`)
    if (r.amountAnalysis.correlations > 0) {
      w(`    correlations:  ${r.amountAnalysis.correlations} near-match pairs\n`)
    }
    w('\n')
  }

  // Recommendations
  if (r.recommendations.length > 0) {
    w(`  recommendations:\n`)
    for (const rec of r.recommendations.slice(0, 5)) {
      const icon = rec.priority === 'high' ? '\x1b[31m!\x1b[0m'
        : rec.priority === 'medium' ? '\x1b[33m~\x1b[0m'
        : '\x1b[36m·\x1b[0m'
      w(`    ${icon} [${rec.source}] ${rec.action}\n`)
      w(`      saves ~${rec.estimatedSavings.toFixed(1)} bits\n`)
    }
    w('\n')
  }

  // Expansion info
  if (r.expandedAddresses > 0) {
    w(`  graph expansion: ${r.expandedAddresses} addresses followed\n\n`)
  }

  // JSON output to stdout for piping
  process.stdout.write(JSON.stringify(r, null, 2) + '\n')
}

main().catch(err => {
  process.stderr.write(`fatal: ${err.message}\n`)
  process.exit(1)
})
