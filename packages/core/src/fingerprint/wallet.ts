/**
 * Wallet software fingerprinting from transaction structure.
 *
 * 8 heuristics extracted from each transaction:
 *
 * 1. Input ordering: BIP-69 lexicographic vs random
 * 2. Output ordering: BIP-69 vs random
 * 3. Script types: P2PKH / P2SH / P2WPKH / P2TR + mixing
 * 4. Change output position: first / last / random
 * 5. nLockTime: 0 (most wallets) vs block height (Bitcoin Core anti-fee-sniping)
 * 6. Fee rate: round sat/vB (Electrum) vs precise (Bitcoin Core)
 * 7. Output count: 2 (standard) vs many (batch payment) vs CoinJoin
 * 8. Consistency across multiple transactions (aggregate fingerprint)
 *
 * Log-likelihood scoring against 7 known wallet profiles.
 *
 * Reference: Ishaana Misra — "Wallet Fingerprints: Detection & Analysis"
 *            https://ishaana.com/blog/wallet_fingerprinting/
 * Reference: Bitcoin Wiki — Privacy page, wallet fingerprinting section
 * Reference: BIP-69 — Lexicographical Indexing of Transaction Inputs and Outputs
 */

import type { Transaction } from '../graph/cospend.js'
import { shannonEntropy } from '../entropy/shannon.js'

export type ScriptType = 'p2pkh' | 'p2sh' | 'p2wpkh' | 'p2tr' | 'unknown'

export interface WalletFingerprint {
  features: TransactionFeatures
  scores: { wallet: string; score: number; confidence: number }[]
  anonymityReduction: number
}

export interface TransactionFeatures {
  inputOrdering: 'bip69' | 'random' | 'unknown'
  outputOrdering: 'bip69' | 'random' | 'unknown'
  scriptTypes: ScriptType[]
  mixedScriptTypes: boolean
  changePosition: 'first' | 'last' | 'middle' | 'unknown'
  hasAntiFeeSniping: boolean
  feeRateRound: boolean
  feeRateSatVb: number | null
  outputCount: number
  isBatch: boolean
  isLikelyCoinJoin: boolean
}

export function detectScriptType(address: string): ScriptType {
  if (address.startsWith('1')) return 'p2pkh'
  if (address.startsWith('3')) return 'p2sh'
  if (address.startsWith('bc1q')) return 'p2wpkh'
  if (address.startsWith('bc1p')) return 'p2tr'
  return 'unknown'
}

export function extractFeatures(tx: Transaction): TransactionFeatures {
  const inputTypes = tx.inputs.map(i => detectScriptType(i.address))
  const outputTypes = tx.outputs.map(o => detectScriptType(o.address))
  const allTypes = new Set([...inputTypes, ...outputTypes].filter(t => t !== 'unknown'))

  // BIP-69 check
  const outputValues = tx.outputs.map(o => o.value)
  const outputsSorted = outputValues.length > 1 && outputValues.every((v, i) => i === 0 || v >= outputValues[i - 1])
  const inputAddrs = tx.inputs.map(i => i.address)
  const inputsSorted = inputAddrs.length > 1 && inputAddrs.every((a, i) => i === 0 || a >= inputAddrs[i - 1])

  // Change detection
  const change = detectChangeOutput(tx)
  let changePosition: TransactionFeatures['changePosition'] = 'unknown'
  if (change.changeIndex === 0) changePosition = 'first'
  else if (change.changeIndex === tx.outputs.length - 1) changePosition = 'last'
  else if (change.changeIndex !== null) changePosition = 'middle'

  // Anti-fee-sniping: nLockTime ≈ block height
  const hasAntiFeeSniping = tx.locktime !== undefined && tx.locktime > 0 &&
    tx.blockHeight > 0 && Math.abs(tx.locktime - tx.blockHeight) <= 1

  // Fee rate
  let feeRateSatVb: number | null = null
  let feeRateRound = false
  if (tx.vsize && tx.vsize > 0) {
    feeRateSatVb = tx.fee / tx.vsize
    feeRateRound = feeRateSatVb % 1 === 0 || feeRateSatVb % 0.5 === 0
  }

  // CoinJoin: 3+ inputs + 3+ equal outputs
  const valueCounts = new Map<number, number>()
  for (const v of outputValues) valueCounts.set(v, (valueCounts.get(v) ?? 0) + 1)
  const maxEqual = Math.max(...valueCounts.values(), 0)
  const isLikelyCoinJoin = tx.inputs.length >= 3 && maxEqual >= 3

  return {
    inputOrdering: tx.inputs.length > 1 ? (inputsSorted ? 'bip69' : 'random') : 'unknown',
    outputOrdering: tx.outputs.length > 1 ? (outputsSorted ? 'bip69' : 'random') : 'unknown',
    scriptTypes: [...allTypes],
    mixedScriptTypes: allTypes.size > 1,
    changePosition,
    hasAntiFeeSniping,
    feeRateRound,
    feeRateSatVb,
    outputCount: tx.outputs.length,
    isBatch: tx.outputs.length > 2 && !isLikelyCoinJoin,
    isLikelyCoinJoin,
  }
}

export function detectChangeOutput(tx: Transaction): {
  changeIndex: number | null
  confidence: number
  heuristic: string
} {
  if (tx.outputs.length !== 2) {
    return { changeIndex: null, confidence: 0, heuristic: 'non-standard-output-count' }
  }

  const [o0, o1] = tx.outputs
  const inputScriptTypes = new Set(tx.inputs.map(i => detectScriptType(i.address)))

  const o0Match = inputScriptTypes.has(detectScriptType(o0.address))
  const o1Match = inputScriptTypes.has(detectScriptType(o1.address))

  if (o0Match && !o1Match) return { changeIndex: 0, confidence: 0.7, heuristic: 'script-type-match' }
  if (o1Match && !o0Match) return { changeIndex: 1, confidence: 0.7, heuristic: 'script-type-match' }

  const r0 = roundness(o0.value), r1 = roundness(o1.value)
  if (r0 > r1) return { changeIndex: 1, confidence: 0.6, heuristic: 'round-payment' }
  if (r1 > r0) return { changeIndex: 0, confidence: 0.6, heuristic: 'round-payment' }

  return { changeIndex: null, confidence: 0, heuristic: 'inconclusive' }
}

function roundness(sats: number): number {
  if (sats === 0) return 0
  let r = 0, v = sats
  while (v % 10 === 0 && v > 0) { r++; v = Math.floor(v / 10) }
  return r
}

// --- Wallet profiles ---

interface WalletProfile {
  id: string
  ordering?: 'bip69' | 'random'
  scripts?: ScriptType[]
  antiFeeSniping?: boolean
  roundFee?: boolean
  changePos?: 'first' | 'last' | 'random'
  coinJoin?: boolean
}

// Compiled from research + direct testing
const PROFILES: WalletProfile[] = [
  { id: 'bitcoin-core', ordering: 'random', scripts: ['p2wpkh', 'p2tr'], antiFeeSniping: true, changePos: 'random' },
  { id: 'electrum', ordering: 'bip69', scripts: ['p2wpkh'], roundFee: true },
  { id: 'wasabi', ordering: 'random', scripts: ['p2wpkh'], coinJoin: true, changePos: 'random' },
  { id: 'sparrow', ordering: 'random', scripts: ['p2wpkh', 'p2tr'], antiFeeSniping: true },
  { id: 'blue-wallet', scripts: ['p2sh', 'p2wpkh'], changePos: 'last' },
  { id: 'ledger-live', scripts: ['p2sh', 'p2wpkh'], changePos: 'last' },
  { id: 'legacy', scripts: ['p2pkh'] },
]

function scoreWallets(features: TransactionFeatures): WalletFingerprint['scores'] {
  return PROFILES.map(p => {
    let s = 0

    // Ordering (+2 match, -2 mismatch)
    if (p.ordering === 'bip69') {
      if (features.inputOrdering === 'bip69') s += 2
      if (features.outputOrdering === 'bip69') s += 2
      if (features.inputOrdering === 'random') s -= 2
    }
    if (p.ordering === 'random') {
      if (features.inputOrdering === 'random') s += 1.5
      if (features.outputOrdering === 'random') s += 1.5
      if (features.inputOrdering === 'bip69') s -= 1
    }

    // Script types (+1.5 per match, -2 per mismatch)
    if (p.scripts) {
      s += features.scriptTypes.filter(t => p.scripts!.includes(t)).length * 1.5
      s -= features.scriptTypes.filter(t => !p.scripts!.includes(t)).length * 2
    }

    // Anti-fee-sniping (+2 match, -1 mismatch)
    if (p.antiFeeSniping !== undefined) {
      if (features.hasAntiFeeSniping === p.antiFeeSniping) s += 2
      else s -= 1
    }

    // Fee rounding
    if (p.roundFee && features.feeRateRound) s += 1.5

    // Change position
    if (p.changePos && features.changePosition !== 'unknown') {
      if (p.changePos === features.changePosition) s += 1
      else s -= 0.5
    }

    // CoinJoin
    if (p.coinJoin && features.isLikelyCoinJoin) s += 4
    if (p.coinJoin && !features.isLikelyCoinJoin) s -= 2

    // P2PKH bonus for legacy
    if (p.id === 'legacy' && features.scriptTypes.every(t => t === 'p2pkh')) s += 3

    // Sigmoid confidence
    const confidence = 1 / (1 + Math.exp(-s / 3))

    return { wallet: p.id, score: s, confidence }
  }).sort((a, b) => b.score - a.score)
}

export function fingerprintTransaction(tx: Transaction): WalletFingerprint {
  const features = extractFeatures(tx)
  const scores = scoreWallets(features)

  const totalConf = scores.reduce((s, w) => s + w.confidence, 0)
  const probs = totalConf > 0
    ? scores.map(w => w.confidence / totalConf)
    : scores.map(() => 1 / scores.length)

  const maxH = Math.log2(scores.length)
  const actualH = shannonEntropy(probs)

  return { features, scores, anonymityReduction: Math.max(0, maxH - actualH) }
}

/**
 * Aggregate fingerprint across multiple transactions.
 * Consistent features boost confidence significantly.
 */
export function aggregateFingerprints(txs: Transaction[]): WalletFingerprint | null {
  if (txs.length === 0) return null
  if (txs.length === 1) return fingerprintTransaction(txs[0])

  const allFeatures = txs.map(extractFeatures)
  const primary = fingerprintTransaction(txs[0])

  // Count consistency
  const bip69Pct = allFeatures.filter(f => f.inputOrdering === 'bip69').length / txs.length
  const afsCount = allFeatures.filter(f => f.hasAntiFeeSniping).length / txs.length
  const roundFeePct = allFeatures.filter(f => f.feeRateRound).length / txs.length

  const boosted = primary.scores.map(s => {
    let boost = 0
    const p = PROFILES.find(pr => pr.id === s.wallet)
    if (!p) return s

    if (p.ordering === 'bip69' && bip69Pct > 0.8) boost += 2
    if (p.antiFeeSniping && afsCount > 0.7) boost += 1.5
    if (p.roundFee && roundFeePct > 0.7) boost += 1

    const newScore = s.score + boost
    return { wallet: s.wallet, score: newScore, confidence: 1 / (1 + Math.exp(-newScore / 3)) }
  }).sort((a, b) => b.score - a.score)

  const totalConf = boosted.reduce((s, w) => s + w.confidence, 0)
  const probs = totalConf > 0 ? boosted.map(w => w.confidence / totalConf) : boosted.map(() => 1 / boosted.length)
  const maxH = Math.log2(boosted.length)

  return {
    features: primary.features,
    scores: boosted,
    anonymityReduction: Math.max(0, maxH - shannonEntropy(probs)),
  }
}
