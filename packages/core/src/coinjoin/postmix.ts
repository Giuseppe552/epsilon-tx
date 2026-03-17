/**
 * Post-mix degradation analysis.
 *
 * A CoinJoin provides theoretical entropy at the time of mixing.
 * But subsequent spending behaviour can destroy that privacy:
 *
 * 1. Output consolidation: spending 2+ CoinJoin outputs in the same
 *    transaction links them → common-input-ownership heuristic
 *    eliminates the ambiguity the CoinJoin created.
 *
 * 2. Toxic change: if the CoinJoin has a non-equal change output,
 *    spending it alongside a mixed output links your identity to
 *    the change (which is already linked to your pre-mix identity).
 *
 * 3. Address reuse: receiving new funds to an address that was a
 *    CoinJoin output links your post-mix activity to your mix.
 *
 * 4. Timing correlation: spending a CoinJoin output within minutes
 *    of the mix narrows the anonymity set (the adversary knows
 *    the real spender acts quickly).
 *
 * We measure the degradation as: actual_entropy = mix_entropy - Σ(degradation_i)
 *
 * Reference: Maurer et al. (2025) — arXiv 2510.17284, §5 post-mix analysis.
 * Reference: OXT Research — KYCP.org methodology.
 */

import type { Transaction } from '../graph/cospend.js'
import type { BoltzmannResult } from './boltzmann.js'

export interface PostMixAnalysis {
  mixTxid: string
  theoreticalEntropy: number   // bits at time of mix
  actualEntropy: number        // bits after degradation
  degradation: number          // bits lost
  degradationPct: number       // % of theoretical lost
  issues: PostMixIssue[]
}

export interface PostMixIssue {
  type: 'consolidation' | 'toxic-change' | 'address-reuse' | 'timing'
  severity: 'critical' | 'high' | 'medium' | 'low'
  bitsLost: number
  detail: string
  txid?: string
}

/**
 * Analyse post-mix behaviour for a CoinJoin transaction.
 *
 * @param mixResult - Boltzmann analysis of the CoinJoin transaction
 * @param mixOutputAddresses - Addresses that received mixed outputs
 * @param subsequentTxs - All transactions AFTER the mix involving these addresses
 */
export function analysePostMix(
  mixResult: BoltzmannResult,
  mixOutputAddresses: string[],
  subsequentTxs: Transaction[],
): PostMixAnalysis {
  const issues: PostMixIssue[] = []
  const mixAddrs = new Set(mixOutputAddresses)

  // Sort subsequent txs by time
  const sorted = [...subsequentTxs].sort((a, b) => a.timestamp - b.timestamp)

  // 1. Output consolidation: any tx spending 2+ mix outputs as inputs
  for (const tx of sorted) {
    const mixInputs = tx.inputs.filter(i => mixAddrs.has(i.address))
    if (mixInputs.length >= 2) {
      // Critical: these outputs are now linked
      const bitsLost = Math.log2(mixInputs.length) * 1.5
      issues.push({
        type: 'consolidation',
        severity: 'critical',
        bitsLost,
        detail: `${mixInputs.length} mixed outputs consolidated in one tx — common-input-ownership links them`,
        txid: tx.txid,
      })
    }
  }

  // 2. Toxic change: spending a mix output alongside a non-mix input
  for (const tx of sorted) {
    const hasMixInput = tx.inputs.some(i => mixAddrs.has(i.address))
    const hasNonMixInput = tx.inputs.some(i => !mixAddrs.has(i.address))

    if (hasMixInput && hasNonMixInput && tx.inputs.length >= 2) {
      issues.push({
        type: 'toxic-change',
        severity: 'high',
        bitsLost: 1.5,
        detail: 'mixed output spent alongside non-mixed input — pre-mix identity linked to post-mix',
        txid: tx.txid,
      })
    }
  }

  // 3. Address reuse: any mix output address that receives funds again
  const receivingAddresses = new Set<string>()
  for (const tx of sorted) {
    for (const out of tx.outputs) {
      if (mixAddrs.has(out.address)) receivingAddresses.add(out.address)
    }
  }
  // Subtract the mix tx itself — the address receiving in the mix is expected
  for (const addr of mixOutputAddresses) receivingAddresses.delete(addr)

  // Check if any of those addresses received NEW funds after the mix
  for (const tx of sorted) {
    if (tx.txid === mixResult.txid) continue
    for (const out of tx.outputs) {
      if (mixAddrs.has(out.address)) {
        issues.push({
          type: 'address-reuse',
          severity: 'high',
          bitsLost: 1.0,
          detail: `mix output address ${out.address.slice(0, 12)}... received new funds — links pre and post-mix activity`,
          txid: tx.txid,
        })
        break // one per tx is enough
      }
    }
  }

  // 4. Timing: spending within 1 hour of the mix
  if (sorted.length > 0 && mixResult.txid) {
    // Find the mix tx timestamp
    const mixTx = sorted.find(tx => tx.txid === mixResult.txid)
    const mixTime = mixTx?.timestamp ?? 0

    if (mixTime > 0) {
      for (const tx of sorted) {
        if (tx.txid === mixResult.txid) continue
        const hasMixInput = tx.inputs.some(i => mixAddrs.has(i.address))
        if (!hasMixInput) continue

        const timeDiffHours = (tx.timestamp - mixTime) / 3600
        if (timeDiffHours > 0 && timeDiffHours < 1) {
          issues.push({
            type: 'timing',
            severity: 'medium',
            bitsLost: 0.8,
            detail: `mixed output spent ${timeDiffHours.toFixed(1)}h after mix — narrows anonymity set to fast spenders`,
            txid: tx.txid,
          })
        } else if (timeDiffHours >= 1 && timeDiffHours < 24) {
          issues.push({
            type: 'timing',
            severity: 'low',
            bitsLost: 0.3,
            detail: `mixed output spent ${timeDiffHours.toFixed(0)}h after mix — minor timing correlation`,
            txid: tx.txid,
          })
        }
      }
    }
  }

  // Compute degradation
  const totalBitsLost = issues.reduce((s, i) => s + i.bitsLost, 0)
  const actualEntropy = Math.max(0, mixResult.entropy - totalBitsLost)
  const degradationPct = mixResult.entropy > 0 ? (totalBitsLost / mixResult.entropy) * 100 : 0

  return {
    mixTxid: mixResult.txid,
    theoreticalEntropy: mixResult.entropy,
    actualEntropy: Math.round(actualEntropy * 100) / 100,
    degradation: Math.round(totalBitsLost * 100) / 100,
    degradationPct: Math.round(degradationPct),
    issues: issues.sort((a, b) => b.bitsLost - a.bitsLost),
  }
}
