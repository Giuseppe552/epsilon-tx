/**
 * Cross-chain bridge transaction API client.
 *
 * Fetches bridge transaction data from public explorer APIs to detect
 * cross-chain linking. Each bridge has its own API format — this module
 * normalises them into a common ChainHop structure.
 *
 * Supported explorers:
 * - LayerZero Scan (Stargate, other LayerZero apps): layerzeroscan.com
 * - Wormhole Explorer: wormholescan.io
 * - Generic: Etherscan-style APIs for L2 deposits/withdrawals
 *
 * Reference: LayerZero Scan API — https://layerzeroscan.com/
 * Reference: Wormhole Scan — https://wormholescan.io/
 */

import type { ChainHop } from './composition.js'

const WORMHOLE_API = 'https://api.wormholescan.io/api/v1'
const LAYERZERO_API = 'https://scan.layerzero-api.com/v1'

const cache = new Map<string, unknown>()

async function fetchJson<T>(url: string): Promise<T | null> {
  if (cache.has(url)) return cache.get(url) as T

  try {
    const res = await fetch(url)
    if (!res.ok) return null
    const data = await res.json() as T
    cache.set(url, data)
    return data
  } catch {
    return null
  }
}

/**
 * Search for Wormhole bridge transactions involving an address.
 *
 * Wormhole uses VAAs (Verifiable Action Approvals) to track
 * cross-chain messages. Each transfer creates a VAA with the
 * source chain, destination chain, amount, and timestamps.
 */
export async function searchWormholeTransfers(
  address: string,
  limit: number = 20,
): Promise<ChainHop[]> {
  const data = await fetchJson<{
    operations?: {
      sourceChain: { chainId: number; from: string; timestamp: string }
      targetChain: { chainId: number; to: string; timestamp: string }
      data: { tokenAmount: string; symbol: string }
      status: string
    }[]
  }>(`${WORMHOLE_API}/operations?address=${address}&page=0&pageSize=${limit}`)

  if (!data?.operations) return []

  const hops: ChainHop[] = []
  for (const op of data.operations) {
    if (op.status !== 'COMPLETED') continue

    const amount = parseFloat(op.data.tokenAmount) || 0

    // Source hop
    hops.push({
      chain: wormholeChainName(op.sourceChain.chainId),
      mechanism: 'bridge',
      amount: Math.round(amount * 1e8), // normalise to sats-equivalent
      timestamp: Math.floor(new Date(op.sourceChain.timestamp).getTime() / 1000),
      privacyLeakage: estimateBridgeLeakage('wormhole'),
    })

    // Destination hop
    hops.push({
      chain: wormholeChainName(op.targetChain.chainId),
      mechanism: 'bridge',
      amount: Math.round(amount * 1e8),
      timestamp: Math.floor(new Date(op.targetChain.timestamp).getTime() / 1000),
      privacyLeakage: estimateBridgeLeakage('wormhole'),
    })
  }

  return hops
}

/**
 * Search for LayerZero (Stargate) bridge transactions.
 */
export async function searchLayerZeroTransfers(
  address: string,
  limit: number = 20,
): Promise<ChainHop[]> {
  const data = await fetchJson<{
    data?: {
      srcChainId: number
      dstChainId: number
      srcUaAddress: string
      dstUaAddress: string
      srcBlockTimestamp: number
      dstBlockTimestamp: number
      status: string
    }[]
  }>(`${LAYERZERO_API}/messages?srcUaAddress=${address}&limit=${limit}`)

  if (!data?.data) return []

  const hops: ChainHop[] = []
  for (const msg of data.data) {
    hops.push({
      chain: layerZeroChainName(msg.srcChainId),
      mechanism: 'bridge',
      amount: 0, // LayerZero doesn't expose amounts in the message API
      timestamp: msg.srcBlockTimestamp,
      privacyLeakage: estimateBridgeLeakage('layerzero'),
    })

    if (msg.dstBlockTimestamp > 0) {
      hops.push({
        chain: layerZeroChainName(msg.dstChainId),
        mechanism: 'bridge',
        amount: 0,
        timestamp: msg.dstBlockTimestamp,
        privacyLeakage: estimateBridgeLeakage('layerzero'),
      })
    }
  }

  return hops
}

/**
 * Search for Ethereum L2 deposits/withdrawals.
 * Uses Etherscan-compatible APIs (Arbiscan, Optimistic Etherscan, etc.)
 *
 * @param address - Ethereum address
 * @param l2Api - Base URL of the L2 explorer API
 * @param apiKey - Explorer API key (optional, rate limited without)
 */
export async function searchL2Transfers(
  address: string,
  l2Api: string,
  apiKey?: string,
): Promise<ChainHop[]> {
  const keyParam = apiKey ? `&apikey=${apiKey}` : ''
  const data = await fetchJson<{
    result?: {
      hash: string
      from: string
      to: string
      value: string
      timeStamp: string
      isError: string
    }[]
  }>(`${l2Api}?module=account&action=txlist&address=${address}&sort=desc&page=1&offset=20${keyParam}`)

  if (!data?.result) return []

  return data.result
    .filter(tx => tx.isError === '0')
    .map(tx => ({
      chain: 'ethereum-l2',
      mechanism: 'l2-deposit' as const,
      amount: Math.round(parseFloat(tx.value) / 1e10), // wei to rough sats equivalent
      timestamp: parseInt(tx.timeStamp, 10),
      privacyLeakage: 1.5, // L2s have public state — moderate leakage
    }))
}

/**
 * Aggregate bridge transfers across multiple explorers.
 */
export async function searchAllBridgeTransfers(
  address: string,
): Promise<ChainHop[]> {
  const [wormhole, layerzero] = await Promise.allSettled([
    searchWormholeTransfers(address),
    searchLayerZeroTransfers(address),
  ])

  const hops: ChainHop[] = []
  if (wormhole.status === 'fulfilled') hops.push(...wormhole.value)
  if (layerzero.status === 'fulfilled') hops.push(...layerzero.value)

  return hops.sort((a, b) => a.timestamp - b.timestamp)
}

// --- Chain ID mappings ---

function wormholeChainName(chainId: number): string {
  const names: Record<number, string> = {
    1: 'solana', 2: 'ethereum', 4: 'bsc', 5: 'polygon',
    6: 'avalanche', 10: 'fantom', 13: 'near', 22: 'aptos',
    23: 'arbitrum', 24: 'optimism', 30: 'base', 34: 'scroll',
  }
  return names[chainId] ?? `chain-${chainId}`
}

function layerZeroChainName(chainId: number): string {
  const names: Record<number, string> = {
    101: 'ethereum', 102: 'bsc', 106: 'avalanche', 109: 'polygon',
    110: 'arbitrum', 111: 'optimism', 184: 'base',
  }
  return names[chainId] ?? `lz-${chainId}`
}

/**
 * Estimate privacy leakage for a bridge type.
 * Based on bridge volume, mechanism transparency, and linking difficulty.
 */
function estimateBridgeLeakage(bridge: string): number {
  const leakages: Record<string, number> = {
    wormhole: 2.0,    // high volume but amounts + timing are public
    layerzero: 2.5,   // message-level tracking via LayerZero Scan
    stargate: 2.0,    // built on LayerZero, similar properties
    hop: 1.8,         // AMM-based, slightly harder to link exact amounts
    across: 1.5,      // intent-based, relayers add noise
    default: 2.0,
  }
  return leakages[bridge] ?? leakages.default
}

export function clearCrossChainCache() {
  cache.clear()
}
