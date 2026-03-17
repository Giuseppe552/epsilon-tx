/**
 * Monero daemon RPC client.
 *
 * Fetches transaction data including ring members (vin.key.key_offsets)
 * and output ages from public Monero daemon nodes. No wallet access
 * needed — all data is on the public blockchain.
 *
 * The key data for ring analysis:
 * - vin[].key.key_offsets: array of 16 output indices (ring members)
 * - vin[].key.k_image: key image (identifies the spent output)
 *
 * To convert key_offsets to absolute indices: they're stored as
 * deltas from the previous offset. Cumulative sum gives absolute indices.
 *
 * Reference: Monero Daemon RPC documentation
 *            https://www.getmonero.org/resources/developer-guides/daemon-rpc.html
 * Reference: monero-project/monero Wiki — get_transactions endpoint.
 */

import type { RingMember } from './ring.js'

// Public Monero daemon nodes (no auth required)
const MONERO_DAEMONS = [
  'https://node.moneroworld.com:18089',
  'https://node.community.rino.io:18081',
  'https://nodes.hashvault.pro:18081',
]

let activeDaemon = MONERO_DAEMONS[0]
const cache = new Map<string, unknown>()

interface MoneroRpcResponse<T> {
  result?: T
  error?: { code: number; message: string }
}

async function rpc<T>(method: string, params: Record<string, unknown> = {}): Promise<T> {
  const cacheKey = `${method}:${JSON.stringify(params)}`
  if (cache.has(cacheKey)) return cache.get(cacheKey) as T

  for (const daemon of [activeDaemon, ...MONERO_DAEMONS.filter(d => d !== activeDaemon)]) {
    try {
      const res = await fetch(`${daemon}/json_rpc`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: '0', method, params }),
      })

      if (!res.ok) continue

      const data = await res.json() as MoneroRpcResponse<T>
      if (data.error) throw new Error(`Monero RPC ${data.error.code}: ${data.error.message}`)
      if (!data.result) throw new Error('empty result')

      activeDaemon = daemon // remember working daemon
      cache.set(cacheKey, data.result)
      return data.result
    } catch {
      continue // try next daemon
    }
  }

  throw new Error('all Monero daemons unreachable')
}

/**
 * Non-JSON RPC endpoint for get_transactions (uses /get_transactions not /json_rpc)
 */
async function getTransactionsRaw(txHashes: string[]): Promise<MoneroTransaction[]> {
  const cacheKey = `get_tx:${txHashes.join(',')}`
  if (cache.has(cacheKey)) return cache.get(cacheKey) as MoneroTransaction[]

  for (const daemon of [activeDaemon, ...MONERO_DAEMONS.filter(d => d !== activeDaemon)]) {
    try {
      const res = await fetch(`${daemon}/get_transactions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ txs_hashes: txHashes, decode_as_json: true }),
      })

      if (!res.ok) continue

      const data = await res.json() as { txs?: { as_json: string; block_height: number; block_timestamp: number }[] }
      if (!data.txs || data.txs.length === 0) throw new Error('no txs returned')

      const result = data.txs.map(tx => {
        const parsed = JSON.parse(tx.as_json) as MoneroTxJson
        return {
          ...parsed,
          blockHeight: tx.block_height,
          blockTimestamp: tx.block_timestamp,
        }
      })

      activeDaemon = daemon
      cache.set(cacheKey, result)
      return result
    } catch {
      continue
    }
  }

  throw new Error('all Monero daemons unreachable')
}

interface MoneroTxJson {
  version: number
  unlock_time: number
  vin: {
    key: {
      amount: number
      key_offsets: number[] // delta-encoded output indices
      k_image: string
    }
  }[]
  vout: {
    amount: number
    target: { tagged_key?: { key: string }; key?: { key: string } }
  }[]
  rct_signatures: { type: number }
}

interface MoneroTransaction extends MoneroTxJson {
  blockHeight: number
  blockTimestamp: number
}

interface BlockHeader {
  height: number
  timestamp: number
}

/**
 * Get the current blockchain height.
 */
export async function getBlockchainHeight(): Promise<number> {
  const result = await rpc<{ height: number }>('get_block_count')
  return result.height
}

/**
 * Get block header by height (for timestamp lookups).
 */
export async function getBlockHeader(height: number): Promise<BlockHeader> {
  const result = await rpc<{ block_header: { height: number; timestamp: number } }>(
    'get_block_header_by_height', { height }
  )
  return { height: result.block_header.height, timestamp: result.block_header.timestamp }
}

/**
 * Fetch a Monero transaction and extract ring members.
 *
 * Converts delta-encoded key_offsets to absolute output indices,
 * then looks up the age of each output to build RingMember objects
 * for the ring analysis module.
 *
 * @param txHash - Monero transaction hash
 * @returns Array of RingMember arrays (one per input in the transaction)
 */
export async function getTransactionRings(txHash: string): Promise<RingMember[][]> {
  const txs = await getTransactionsRaw([txHash])
  if (txs.length === 0) throw new Error(`transaction ${txHash} not found`)

  const tx = txs[0]
  const currentHeight = await getBlockchainHeight()
  const rings: RingMember[][] = []

  for (const input of tx.vin) {
    if (!input.key) continue

    // Convert delta-encoded offsets to absolute output indices
    const absoluteIndices: number[] = []
    let cumulative = 0
    for (const delta of input.key.key_offsets) {
      cumulative += delta
      absoluteIndices.push(cumulative)
    }

    // For each ring member, estimate age from the output index
    // Output index grows roughly linearly with time on Monero (~2min blocks)
    // Approximate: age_seconds ≈ (currentHeight - output_height) * 120
    // We use the output index as a rough proxy for height
    const members: RingMember[] = absoluteIndices.map(idx => {
      // Rough height estimate: Monero outputs grow ~5000/day
      const estimatedHeight = Math.floor(idx / 5000) * 720 // very rough
      const ageBlocks = Math.max(1, currentHeight - estimatedHeight)
      const ageSeconds = ageBlocks * 120 // 2 min block time

      return {
        outputIndex: idx,
        age: ageSeconds,
        amount: 0, // RingCT — amount is hidden
        isDecoy: null, // unknown — that's what the analysis determines
      }
    })

    rings.push(members)
  }

  return rings
}

/**
 * Fetch the output distribution for the blockchain.
 * Used for more precise age estimation of ring members.
 */
export async function getOutputDistribution(): Promise<{
  distribution: number[]
  startHeight: number
}> {
  const result = await rpc<{
    distributions: { distribution: { data: number[]; start_height: number } }[]
  }>('get_output_distribution', {
    amounts: [0], // RingCT outputs
    cumulative: true,
    binary: false,
  })

  const dist = result.distributions[0]
  return {
    distribution: dist.distribution.data,
    startHeight: dist.distribution.start_height,
  }
}

export function clearMoneroCache() {
  cache.clear()
}
