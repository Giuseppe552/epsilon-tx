/**
 * Bitcoin blockchain API client.
 *
 * Fetches transaction and address data from public APIs (Blockstream,
 * mempool.space). No full node required.
 *
 * Rate-limited and cached to avoid hammering public infrastructure.
 * All data is public blockchain information — no authentication needed.
 */

import type { Transaction } from '../graph/cospend.js'

const BLOCKSTREAM_API = 'https://blockstream.info/api'
const MEMPOOL_API = 'https://mempool.space/api'

interface RawTx {
  txid: string
  vin: { prevout: { scriptpubkey_address?: string; value: number } }[]
  vout: { scriptpubkey_address?: string; value: number; n: number }[]
  fee: number
  status: { block_time?: number; block_height?: number; confirmed: boolean }
}

interface RawUtxo {
  txid: string
  vout: number
  value: number
  status: { block_time?: number; block_height?: number; confirmed: boolean }
}

// Simple in-memory cache to avoid re-fetching
const cache = new Map<string, unknown>()

async function fetchJson<T>(url: string, retries = 3): Promise<T> {
  if (cache.has(url)) return cache.get(url) as T

  for (let attempt = 0; attempt < retries; attempt++) {
    const res = await fetch(url)

    if (res.status === 429 || res.status === 503) {
      // Rate limited or server busy — back off exponentially
      const delay = Math.min(1000 * Math.pow(2, attempt), 10000)
      await new Promise(r => setTimeout(r, delay))
      continue
    }

    if (!res.ok) throw new Error(`API ${res.status}: ${url}`)

    const data = await res.json() as T
    cache.set(url, data)
    return data
  }

  throw new Error(`API rate limited after ${retries} retries: ${url}`)
}

/**
 * Fetch all transactions for a Bitcoin address.
 *
 * Uses Blockstream API. Returns up to 50 transactions per call
 * (paginated via last_seen_txid). Automatically follows pagination.
 *
 * @param address - Bitcoin address (any format: P2PKH, P2SH, P2WPKH, P2TR)
 * @param maxTxs - Maximum transactions to fetch (default 200)
 */
export async function getAddressTransactions(
  address: string,
  maxTxs: number = 200,
): Promise<Transaction[]> {
  const txs: Transaction[] = []
  let lastTxid: string | undefined

  while (txs.length < maxTxs) {
    const url = lastTxid
      ? `${BLOCKSTREAM_API}/address/${address}/txs/chain/${lastTxid}`
      : `${BLOCKSTREAM_API}/address/${address}/txs`

    const raw = await fetchJson<RawTx[]>(url)
    if (raw.length === 0) break

    for (const rtx of raw) {
      txs.push(parseRawTx(rtx))
    }

    if (raw.length < 25) break // last page
    lastTxid = raw[raw.length - 1].txid
  }

  return txs.slice(0, maxTxs)
}

/**
 * Fetch a single transaction by txid.
 */
export async function getTransaction(txid: string): Promise<Transaction> {
  const raw = await fetchJson<RawTx>(`${BLOCKSTREAM_API}/tx/${txid}`)
  return parseRawTx(raw)
}

/**
 * Fetch UTXOs (unspent outputs) for an address.
 */
export async function getUtxos(address: string): Promise<{
  txid: string
  vout: number
  value: number
  confirmed: boolean
}[]> {
  const raw = await fetchJson<RawUtxo[]>(`${BLOCKSTREAM_API}/address/${address}/utxo`)
  return raw.map(u => ({
    txid: u.txid,
    vout: u.vout,
    value: u.value,
    confirmed: u.status.confirmed,
  }))
}

/**
 * Fetch address summary (tx count, balance).
 */
export async function getAddressSummary(address: string): Promise<{
  txCount: number
  fundedSum: number
  spentSum: number
  balance: number
}> {
  const data = await fetchJson<{
    chain_stats: { tx_count: number; funded_txo_sum: number; spent_txo_sum: number }
    mempool_stats: { tx_count: number; funded_txo_sum: number; spent_txo_sum: number }
  }>(`${BLOCKSTREAM_API}/address/${address}`)

  return {
    txCount: data.chain_stats.tx_count + data.mempool_stats.tx_count,
    fundedSum: data.chain_stats.funded_txo_sum + data.mempool_stats.funded_txo_sum,
    spentSum: data.chain_stats.spent_txo_sum + data.mempool_stats.spent_txo_sum,
    balance: (data.chain_stats.funded_txo_sum - data.chain_stats.spent_txo_sum) +
             (data.mempool_stats.funded_txo_sum - data.mempool_stats.spent_txo_sum),
  }
}

function parseRawTx(raw: RawTx): Transaction {
  return {
    txid: raw.txid,
    inputs: raw.vin
      .filter(v => v.prevout?.scriptpubkey_address)
      .map(v => ({
        address: v.prevout.scriptpubkey_address!,
        value: v.prevout.value,
      })),
    outputs: raw.vout
      .filter(v => v.scriptpubkey_address)
      .map(v => ({
        address: v.scriptpubkey_address!,
        value: v.value,
        index: v.n,
      })),
    fee: raw.fee,
    timestamp: raw.status.block_time ?? 0,
    blockHeight: raw.status.block_height ?? 0,
  }
}

/**
 * Clear the API cache. Call between analyses if memory is a concern.
 */
export function clearCache() {
  cache.clear()
}
