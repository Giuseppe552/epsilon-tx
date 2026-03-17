/**
 * Lightning Network routing privacy analysis.
 *
 * Lightning payments are routed through payment channels via HTLCs.
 * While the payment itself is onion-encrypted (the intermediate nodes
 * only see their hop), several side channels leak information:
 *
 * 1. Timing: HTLC resolution time reveals path length. An adversary
 *    at position i sees delay t_i. At position j: delay t_j. The
 *    difference t_j - t_i bounds the path segment between them.
 *
 * 2. Amount: each hop reduces the amount by a routing fee. The fee
 *    structure reveals the path if fee policies are public.
 *
 * 3. Balance probing: sending payments that are designed to fail
 *    reveals channel balances. Repeated probing tracks individual
 *    payments over time.
 *
 * 4. Path length inference: fewer hops = less anonymity. A direct
 *    channel between sender and receiver has zero routing privacy.
 *
 * This module computes the privacy of a proposed Lightning payment
 * BEFORE routing it, as a Pareto frontier of privacy vs cost.
 *
 * Reference: Romiti et al. (2020). "Counting Down Thunder: Timing
 *            Attacks on Privacy in Payment Channel Networks." arXiv:2006.12143.
 * Reference: Herrera-Joancomartí et al. (2019). "On the Difficulty of
 *            Hiding the Balance of Lightning Network Channels." IACR ePrint 2019/328.
 * Reference: lightningprivacy.com — routing analysis documentation.
 */

import { shannonEntropy } from '../entropy/shannon.js'

export interface LightningNode {
  id: string
  alias?: string
  channels: number
  capacity: number  // total sats
}

export interface LightningChannel {
  id: string
  node1: string
  node2: string
  capacity: number
  baseFee1: number    // msat — node1's fee to forward
  feeRate1: number    // ppm — node1's proportional fee
  baseFee2: number
  feeRate2: number
}

export interface RouteHop {
  nodeId: string
  channelId: string
  fee: number    // sats paid at this hop
  delay: number  // estimated processing time in ms
}

export interface RoutePrivacy {
  route: RouteHop[]
  hops: number
  totalFee: number                // sats
  senderAnonymity: number         // bits — how uncertain is an observer about the sender?
  receiverAnonymity: number       // bits — how uncertain about the receiver?
  timingLeakage: number           // bits — information leaked by timing patterns
  balanceProbeResistance: number  // bits — resistance to balance discovery attacks
  totalPrivacy: number            // bits — combined score
}

export interface ParetoPoint {
  route: RouteHop[]
  fee: number
  privacy: number
}

/**
 * Compute sender anonymity for a route.
 *
 * Sender anonymity = H(sender | observations at each hop).
 * A longer route through higher-degree nodes provides more anonymity
 * because each intermediate node has more possible predecessors.
 *
 * For each hop i, the anonymity contribution is log₂(degree(node_i) - 1)
 * — the number of channels the payment COULD have come from (minus
 * the one it actually came from).
 *
 * Reference: Romiti et al. (2020) §3.2 — sender anonymity metric.
 */
export function computeSenderAnonymity(
  route: RouteHop[],
  nodeChannelCounts: Map<string, number>,
): number {
  if (route.length <= 1) return 0 // direct payment = zero anonymity

  let totalH = 0
  for (let i = 1; i < route.length; i++) {
    const nodeId = route[i].nodeId
    const channels = nodeChannelCounts.get(nodeId) ?? 1
    // This node has (channels - 1) other possible sources
    const anonymityContribution = channels > 1 ? Math.log2(channels - 1) : 0
    totalH += anonymityContribution
  }

  // Normalise by path length
  return totalH / route.length
}

/**
 * Compute timing leakage for a route.
 *
 * An adversary controlling nodes at positions i and j can measure
 * the time difference. Shorter paths have less timing noise →
 * more precise inference about path length and position.
 *
 * Timing leakage = 1 / (hops * avg_processing_variance)
 * More hops and more variable processing times = less leakage.
 *
 * Reference: Romiti et al. (2020) §4 — timing attack feasibility.
 */
export function computeTimingLeakage(route: RouteHop[]): number {
  if (route.length <= 1) return 3.0 // direct = high leakage

  const delays = route.map(h => h.delay)
  const mean = delays.reduce((s, d) => s + d, 0) / delays.length
  const variance = delays.reduce((s, d) => s + (d - mean) ** 2, 0) / delays.length

  // High variance in processing time → harder to correlate
  // Normalise: leakage in [0, ~5] bits
  const varianceFactor = variance > 0 ? 1 / (1 + variance / 10000) : 1
  return varianceFactor * (5 / route.length)
}

/**
 * Compute balance probe resistance.
 *
 * A channel with balanced capacity (50/50 split) is harder to probe
 * than one that's mostly on one side. The adversary sends test payments
 * to discover the balance; a balanced channel gives fewer bits.
 *
 * Resistance ≈ H(balance_distribution) across the route's channels.
 *
 * Reference: Herrera-Joancomartí et al. (2019) — balance discovery attack.
 */
export function computeBalanceProbeResistance(
  route: RouteHop[],
  channelCapacities: Map<string, number>,
): number {
  if (route.length === 0) return 0

  let totalResistance = 0
  for (const hop of route) {
    const capacity = channelCapacities.get(hop.channelId) ?? 0
    if (capacity <= 0) continue

    // Assume uniform balance distribution for analysis
    // (actual balance is unknown without probing)
    // H(balance) = log₂(capacity / min_htlc_size)
    // Approximation: more capacity = more possible balance states
    const states = Math.max(2, Math.floor(capacity / 1000)) // 1000 sat granularity
    totalResistance += Math.log2(states)
  }

  return totalResistance / route.length
}

/**
 * Analyse privacy for a complete route.
 */
export function analyseRoutePrivacy(
  route: RouteHop[],
  nodeChannelCounts: Map<string, number>,
  channelCapacities: Map<string, number>,
): RoutePrivacy {
  const senderAnonymity = computeSenderAnonymity(route, nodeChannelCounts)
  const timingLeakage = computeTimingLeakage(route)
  const balanceResistance = computeBalanceProbeResistance(route, channelCapacities)
  const receiverAnonymity = senderAnonymity * 0.9 // slightly less (last hop knows)

  const totalFee = route.reduce((s, h) => s + h.fee, 0)
  const totalPrivacy = senderAnonymity + receiverAnonymity + balanceResistance - timingLeakage

  return {
    route,
    hops: route.length,
    totalFee,
    senderAnonymity: Math.round(senderAnonymity * 100) / 100,
    receiverAnonymity: Math.round(receiverAnonymity * 100) / 100,
    timingLeakage: Math.round(timingLeakage * 100) / 100,
    balanceProbeResistance: Math.round(balanceResistance * 100) / 100,
    totalPrivacy: Math.round(Math.max(0, totalPrivacy) * 100) / 100,
  }
}

/**
 * Compute the Pareto frontier of privacy vs cost.
 *
 * Given multiple candidate routes, find the ones where no other route
 * is both cheaper AND more private. These are the optimal tradeoffs.
 *
 * "Route A→B→C: 2.1 bits, 3 sats. Route A→D→E→C: 3.4 bits, 5 sats."
 *
 * The user picks their preferred point on the frontier.
 */
export function paretoFrontier(routes: RoutePrivacy[]): ParetoPoint[] {
  // Sort by fee ascending
  const sorted = [...routes].sort((a, b) => a.totalFee - b.totalFee)
  const frontier: ParetoPoint[] = []

  let maxPrivacy = -Infinity

  for (const r of sorted) {
    if (r.totalPrivacy > maxPrivacy) {
      frontier.push({ route: r.route, fee: r.totalFee, privacy: r.totalPrivacy })
      maxPrivacy = r.totalPrivacy
    }
  }

  return frontier
}
