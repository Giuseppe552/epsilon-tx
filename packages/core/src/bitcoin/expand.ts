/**
 * Recursive graph expansion — follow the UTXO graph outward.
 *
 * The basic analysis only sees transactions involving the target address.
 * This misses the transitive closure: address A co-spends with B in
 * a tx we fetched, but B also co-spends with C in a tx we didn't fetch.
 * Without following B, we undercount the cluster size.
 *
 * This module fetches transactions for discovered addresses up to a
 * configurable depth. Each hop multiplies API calls by the average
 * number of new addresses per tx (~3-5), so depth should be limited.
 *
 * Reference: Meiklejohn et al. (2013) §3 — "growing the cluster"
 * by following co-spend links transitively.
 */

import { getAddressTransactions } from './api.js'
import type { Transaction } from '../graph/cospend.js'

/**
 * Expand the transaction set by fetching transactions for co-spend addresses.
 *
 * @param seedTxs - Initial transactions (from the target address)
 * @param targetAddress - The address being analysed
 * @param maxDepth - How many hops to follow (default 1)
 * @param maxAddresses - Maximum addresses to expand (default 20)
 * @param maxTxsPerAddress - Max txs to fetch per address (default 25)
 * @returns All transactions (seed + expanded)
 */
export async function expandGraph(
  seedTxs: Transaction[],
  targetAddress: string,
  maxDepth: number = 1,
  maxAddresses: number = 20,
  maxTxsPerAddress: number = 25,
): Promise<{ transactions: Transaction[]; expandedAddresses: string[] }> {
  const allTxs = new Map<string, Transaction>()
  const seen = new Set<string>([targetAddress])
  const expandedAddresses: string[] = []

  // Seed transactions
  for (const tx of seedTxs) allTxs.set(tx.txid, tx)

  let frontier = extractCoSpendAddresses(seedTxs, seen)

  for (let depth = 0; depth < maxDepth && frontier.length > 0; depth++) {
    // Limit how many addresses we expand per hop
    const toExpand = frontier.slice(0, maxAddresses - expandedAddresses.length)
    if (toExpand.length === 0) break

    const nextFrontier: string[] = []

    for (const addr of toExpand) {
      if (expandedAddresses.length >= maxAddresses) break

      try {
        const txs = await getAddressTransactions(addr, maxTxsPerAddress)
        for (const tx of txs) {
          if (!allTxs.has(tx.txid)) allTxs.set(tx.txid, tx)
        }
        expandedAddresses.push(addr)
        seen.add(addr)

        // Find new addresses for the next hop
        const newAddrs = extractCoSpendAddresses(txs, seen)
        for (const a of newAddrs) nextFrontier.push(a)
      } catch {
        // API error for this address — skip, continue with others
      }
    }

    frontier = nextFrontier
  }

  return {
    transactions: [...allTxs.values()],
    expandedAddresses,
  }
}

/**
 * Extract addresses that co-spend with existing addresses but aren't yet in the seen set.
 * Only returns addresses that appear as CO-INPUTS (same tx, multiple inputs).
 */
function extractCoSpendAddresses(txs: Transaction[], seen: Set<string>): string[] {
  const candidates = new Set<string>()

  for (const tx of txs) {
    if (tx.inputs.length < 2) continue // single-input: no co-spend info

    const inputAddrs = tx.inputs.map(i => i.address)
    const hasKnown = inputAddrs.some(a => seen.has(a))

    if (hasKnown) {
      for (const addr of inputAddrs) {
        if (!seen.has(addr)) candidates.add(addr)
      }
    }
  }

  return [...candidates]
}
