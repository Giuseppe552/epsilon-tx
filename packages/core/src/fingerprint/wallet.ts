/**
 * Wallet software fingerprinting from transaction structure.
 *
 * Different wallet software creates structurally different transactions.
 * These structural fingerprints reduce the anonymity set — if an adversary
 * knows you use Electrum, they only need to search Electrum users.
 *
 * Fingerprinting signals (from Ishaana Misra's research + Bitcoin Wiki):
 *
 * 1. Input/output ordering:
 *    - BIP-69: lexicographic ordering (Electrum, some others)
 *    - Insertion order: outputs in order they were added (Bitcoin Core pre-0.19)
 *    - Random: shuffled (Bitcoin Core 0.19+, Wasabi)
 *
 * 2. Signature encoding:
 *    - Low-R only: Bitcoin Core since 2018 grinds for low-R (saves 1 byte)
 *    - Standard: half of signatures have high-R (extra DER byte)
 *
 * 3. Change output position:
 *    - Always last (some mobile wallets)
 *    - Random (Bitcoin Core, Wasabi)
 *
 * 4. Script types:
 *    - P2PKH (1...) — legacy
 *    - P2SH-P2WPKH (3...) — nested SegWit
 *    - P2WPKH (bc1q...) — native SegWit v0
 *    - P2TR (bc1p...) — Taproot
 *    - Mixing types in one tx is a fingerprint itself
 *
 * 5. Fee patterns:
 *    - Round sats/vB (Electrum)
 *    - Exact estimation (Bitcoin Core)
 *    - Always overpaying (some mobile wallets)
 *
 * 6. nLockTime:
 *    - 0 (most wallets)
 *    - Current block height (Bitcoin Core anti-fee-sniping)
 *
 * Reference: https://ishaana.com/blog/wallet_fingerprinting/
 * Reference: https://en.bitcoin.it/wiki/Privacy
 */

import type { Transaction } from '../graph/cospend.js'
import { shannonEntropy } from '../entropy/shannon.js'

export type ScriptType = 'p2pkh' | 'p2sh' | 'p2wpkh' | 'p2tr' | 'unknown'

export interface WalletFingerprint {
  // Detected features
  inputOrdering: 'bip69' | 'insertion' | 'random' | 'unknown'
  outputOrdering: 'bip69' | 'insertion' | 'random' | 'unknown'
  scriptTypes: { inputs: ScriptType[]; outputs: ScriptType[] }
  mixedScriptTypes: boolean
  changePosition: 'first' | 'last' | 'random' | 'unknown'

  // Confidence scores per wallet
  scores: { wallet: string; confidence: number }[]

  // Privacy impact
  anonymityReduction: number  // bits of information leaked by the fingerprint
}

/**
 * Detect script type from a Bitcoin address.
 */
export function detectScriptType(address: string): ScriptType {
  if (address.startsWith('1')) return 'p2pkh'
  if (address.startsWith('3')) return 'p2sh'
  if (address.startsWith('bc1q')) return 'p2wpkh'
  if (address.startsWith('bc1p')) return 'p2tr'
  return 'unknown'
}

/**
 * Check if inputs/outputs follow BIP-69 lexicographic ordering.
 *
 * BIP-69: inputs sorted by (txid, vout), outputs sorted by (value, scriptPubKey).
 * We approximate by checking if output values are sorted ascending.
 */
function isBip69Ordered(tx: Transaction): { inputs: boolean; outputs: boolean } {
  const outputValues = tx.outputs.map(o => o.value)
  const outputsSorted = outputValues.every((v, i) => i === 0 || v >= outputValues[i - 1])

  // For inputs we'd need the previous txid:vout, which we don't always have.
  // Approximate: check if input addresses are lexicographically sorted.
  const inputAddrs = tx.inputs.map(i => i.address)
  const inputsSorted = inputAddrs.every((a, i) => i === 0 || a >= inputAddrs[i - 1])

  return { inputs: inputsSorted, outputs: outputsSorted }
}

/**
 * Detect likely change output.
 *
 * Heuristics (from Bitcoin Wiki Privacy page):
 * 1. Round payment heuristic: the round-number output is the payment
 * 2. Script type match: change uses the same script type as inputs
 * 3. Fresh address: change goes to an address not seen before
 *    (we can't check this without full history, so we skip it)
 */
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

  // Heuristic 1: script type match
  const o0TypeMatch = inputScriptTypes.has(detectScriptType(o0.address))
  const o1TypeMatch = inputScriptTypes.has(detectScriptType(o1.address))

  if (o0TypeMatch && !o1TypeMatch) {
    return { changeIndex: 0, confidence: 0.7, heuristic: 'script-type-match' }
  }
  if (o1TypeMatch && !o0TypeMatch) {
    return { changeIndex: 1, confidence: 0.7, heuristic: 'script-type-match' }
  }

  // Heuristic 2: round payment amount
  const o0Round = isRoundAmount(o0.value)
  const o1Round = isRoundAmount(o1.value)

  if (o0Round && !o1Round) {
    // o0 is the payment (round), o1 is change
    return { changeIndex: 1, confidence: 0.6, heuristic: 'round-payment' }
  }
  if (o1Round && !o0Round) {
    return { changeIndex: 0, confidence: 0.6, heuristic: 'round-payment' }
  }

  return { changeIndex: null, confidence: 0, heuristic: 'inconclusive' }
}

/**
 * Check if an amount is "round" (likely a deliberate payment amount).
 * Round amounts: multiples of 0.001 BTC (100,000 sats), 0.01, 0.1, etc.
 */
function isRoundAmount(sats: number): boolean {
  return sats % 100000 === 0 || sats % 1000000 === 0 || sats % 10000000 === 0
}

/**
 * Fingerprint a transaction — identify which wallet software likely created it.
 */
export function fingerprintTransaction(tx: Transaction): WalletFingerprint {
  const bip69 = isBip69Ordered(tx)

  // Script types
  const inputTypes = tx.inputs.map(i => detectScriptType(i.address))
  const outputTypes = tx.outputs.map(o => detectScriptType(o.address))
  const allTypes = new Set([...inputTypes, ...outputTypes])
  const mixedScriptTypes = allTypes.size > 1 &&
    // Exclude 'unknown' from the count
    [...allTypes].filter(t => t !== 'unknown').length > 1

  // Change position
  const change = detectChangeOutput(tx)
  let changePosition: WalletFingerprint['changePosition'] = 'unknown'
  if (change.changeIndex === 0) changePosition = 'first'
  else if (change.changeIndex === tx.outputs.length - 1) changePosition = 'last'

  // Ordering
  const inputOrdering: WalletFingerprint['inputOrdering'] = bip69.inputs ? 'bip69' : 'random'
  const outputOrdering: WalletFingerprint['outputOrdering'] = bip69.outputs ? 'bip69' : 'random'

  // Score wallets based on features
  const scores = scoreWallets(tx, {
    inputOrdering,
    outputOrdering,
    mixedScriptTypes,
    changePosition,
    inputTypes,
    outputTypes,
  })

  // Anonymity reduction: entropy of the wallet probability distribution
  // If one wallet is very likely, the anonymity set shrinks
  const totalConfidence = scores.reduce((s, w) => s + w.confidence, 0)
  const probs = totalConfidence > 0
    ? scores.map(w => w.confidence / totalConfidence)
    : scores.map(() => 1 / scores.length)

  // H(wallet) for uniform distribution over all wallets
  const maxEntropy = Math.log2(scores.length)
  // H(wallet | fingerprint) — actual entropy given the fingerprint
  const actualEntropy = shannonEntropy(probs)
  // Information leaked = max - actual
  const anonymityReduction = Math.max(0, maxEntropy - actualEntropy)

  return {
    inputOrdering,
    outputOrdering,
    scriptTypes: { inputs: inputTypes, outputs: outputTypes },
    mixedScriptTypes,
    changePosition,
    scores,
    anonymityReduction,
  }
}

interface Features {
  inputOrdering: string
  outputOrdering: string
  mixedScriptTypes: boolean
  changePosition: string
  inputTypes: ScriptType[]
  outputTypes: ScriptType[]
}

/**
 * Score known wallet software against observed features.
 *
 * Wallet signatures compiled from:
 * - https://ishaana.com/blog/wallet_fingerprinting/
 * - https://en.bitcoin.it/wiki/Privacy
 * - Direct testing of wallet software
 */
function scoreWallets(tx: Transaction, features: Features): WalletFingerprint['scores'] {
  const wallets: { wallet: string; confidence: number }[] = []

  // Bitcoin Core (0.19+): random ordering, P2WPKH/P2TR, low-R sigs, anti-fee-sniping nLockTime
  let coreScore = 0
  if (features.inputOrdering === 'random') coreScore += 0.2
  if (features.outputOrdering === 'random') coreScore += 0.2
  if (!features.mixedScriptTypes) coreScore += 0.15
  if (features.inputTypes.every(t => t === 'p2wpkh' || t === 'p2tr')) coreScore += 0.15
  if (features.changePosition === 'random' || features.changePosition === 'unknown') coreScore += 0.1
  wallets.push({ wallet: 'bitcoin-core', confidence: Math.min(coreScore, 1) })

  // Electrum: BIP-69, P2WPKH, round fee/vB
  let electrumScore = 0
  if (features.inputOrdering === 'bip69') electrumScore += 0.3
  if (features.outputOrdering === 'bip69') electrumScore += 0.3
  if (features.inputTypes.every(t => t === 'p2wpkh')) electrumScore += 0.1
  wallets.push({ wallet: 'electrum', confidence: Math.min(electrumScore, 1) })

  // Wasabi: P2WPKH, random ordering, CoinJoin structure
  let wasabiScore = 0
  if (features.inputOrdering === 'random') wasabiScore += 0.15
  if (features.outputOrdering === 'random') wasabiScore += 0.15
  if (tx.inputs.length > 2 && tx.outputs.length > 4) wasabiScore += 0.3 // CoinJoin-like
  if (features.inputTypes.every(t => t === 'p2wpkh')) wasabiScore += 0.1
  wallets.push({ wallet: 'wasabi', confidence: Math.min(wasabiScore, 1) })

  // Mobile (Blue Wallet, Muun, etc.): P2SH-P2WPKH or P2WPKH, change last
  let mobileScore = 0
  if (features.changePosition === 'last') mobileScore += 0.3
  if (features.inputTypes.some(t => t === 'p2sh')) mobileScore += 0.2
  wallets.push({ wallet: 'mobile-wallet', confidence: Math.min(mobileScore, 1) })

  // Legacy wallet: P2PKH, no SegWit
  let legacyScore = 0
  if (features.inputTypes.every(t => t === 'p2pkh')) legacyScore += 0.5
  if (features.outputTypes.every(t => t === 'p2pkh')) legacyScore += 0.3
  wallets.push({ wallet: 'legacy', confidence: Math.min(legacyScore, 1) })

  return wallets.sort((a, b) => b.confidence - a.confidence)
}
