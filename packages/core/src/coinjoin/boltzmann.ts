/**
 * Boltzmann entropy analysis for CoinJoin transactions.
 *
 * The Boltzmann score measures the number of possible interpretations
 * of a transaction — how many ways could the inputs map to the outputs?
 * More interpretations = higher entropy = better privacy.
 *
 * For a standard 2-in-2-out transaction: typically 1 interpretation
 * (the change output is obvious). Entropy ≈ 0 bits.
 *
 * For a Whirlpool CoinJoin with 5 equal outputs: 5! = 120 possible
 * mappings. Entropy = log₂(120) ≈ 6.9 bits.
 *
 * For Wasabi 2.x with arbitrary values: the number of valid sub-
 * transaction decompositions. This is a variant of the subset sum
 * problem — NP-hard in general, but tractable for typical CoinJoin
 * sizes (5-150 participants).
 *
 * We also compute:
 * - Wallet efficiency: actual_entropy / max_possible_entropy
 * - Link probability matrix: P(input_i → output_j) for each pair
 * - Post-mix degradation: how much entropy was lost by subsequent spending
 *
 * Reference: LaurentMT (2016). "Introducing Boltzmann."
 *            https://medium.com/@laurentmt/introducing-boltzmann-85930984a159
 * Reference: Maurer et al. (2025). "Analysis of input-output mappings in
 *            coinjoin transactions with arbitrary values." arXiv 2510.17284.
 * Reference: Samourai Wallet — Whirlpool THEORY.md, Boltzmann §2.
 */

import { shannonEntropy } from '../entropy/shannon.js'
import type { Transaction } from '../graph/cospend.js'

export interface BoltzmannResult {
  entropy: number                    // bits — log₂(number of valid interpretations)
  maxEntropy: number                 // bits — max possible for this tx structure
  efficiency: number                 // entropy / maxEntropy (0-1, Whirlpool targets 1.0)
  interpretations: number            // raw count of valid decompositions
  linkProbabilities: LinkMatrix      // P(input_i → output_j)
  isLikelyCoinJoin: boolean
  txid: string
}

export interface LinkMatrix {
  inputs: string[]   // addresses
  outputs: string[]  // addresses
  matrix: number[][] // P[i][j] = probability input i funds output j
}

/**
 * Compute the Boltzmann entropy of a transaction.
 *
 * For equal-output CoinJoins (Whirlpool): uses combinatorial counting.
 * For arbitrary-value CoinJoins (Wasabi 2.x): uses subset sum decomposition.
 * For standard transactions: computes based on change detection.
 */
export function computeBoltzmann(tx: Transaction): BoltzmannResult {
  const inputValues = tx.inputs.map(i => i.value)
  const outputValues = tx.outputs.map(o => o.value)
  const nIn = inputValues.length
  const nOut = outputValues.length

  // Detect equal-output CoinJoin
  const valueCounts = new Map<number, number>()
  for (const v of outputValues) valueCounts.set(v, (valueCounts.get(v) ?? 0) + 1)
  const maxEqual = Math.max(...valueCounts.values())
  const isEqualOutput = maxEqual >= 3 && maxEqual === nOut

  if (isEqualOutput) {
    return equalOutputBoltzmann(tx, nIn, nOut)
  }

  // Detect arbitrary-value CoinJoin (many inputs + many outputs)
  if (nIn >= 3 && nOut >= 4) {
    return arbitraryValueBoltzmann(tx, inputValues, outputValues)
  }

  // Standard transaction
  return standardTxBoltzmann(tx, inputValues, outputValues)
}

/**
 * Equal-output CoinJoin (Whirlpool style).
 *
 * All outputs have the same denomination. The number of valid
 * input→output mappings = nIn! / Π(k_i!) where k_i is the number
 * of inputs from each entity (usually 1 each, so = nIn!).
 *
 * Since we don't know entity grouping, we assume each input is
 * independent: interpretations = min(nIn, nOut)!
 *
 * Whirlpool requires efficiency = 1.0 (max entropy for the structure).
 */
function equalOutputBoltzmann(tx: Transaction, nIn: number, nOut: number): BoltzmannResult {
  const k = Math.min(nIn, nOut)

  // k! interpretations (each input could map to any output)
  const interpretations = factorial(k)
  const entropy = Math.log2(interpretations)

  // Max entropy for this structure = log₂(k!)
  const maxEntropy = entropy // equal outputs already achieve max

  return {
    entropy,
    maxEntropy,
    efficiency: 1.0,
    interpretations,
    linkProbabilities: uniformLinkMatrix(tx, nIn, nOut),
    isLikelyCoinJoin: true,
    txid: tx.txid,
  }
}

/**
 * Arbitrary-value CoinJoin (Wasabi 2.x style).
 *
 * Find all valid sub-transaction decompositions: partitions of outputs
 * into groups where each group's sum matches some subset of inputs
 * (within fee tolerance).
 *
 * This is a variant of the subset sum problem. We use dynamic
 * programming with a tolerance of ±fee_per_input.
 *
 * Reference: Maurer et al. (2025) — arXiv 2510.17284, §3.
 */
function arbitraryValueBoltzmann(
  tx: Transaction,
  inputValues: number[],
  outputValues: number[],
): BoltzmannResult {
  const nIn = inputValues.length
  const nOut = outputValues.length
  const feePerInput = Math.ceil(tx.fee / nIn)

  // For each input, find which outputs it COULD fund (within tolerance)
  // This builds a bipartite compatibility graph
  const compatible: boolean[][] = Array.from({ length: nIn }, () => new Array(nOut).fill(false))

  for (let i = 0; i < nIn; i++) {
    for (let j = 0; j < nOut; j++) {
      // Input i could fund output j if input_value >= output_value
      // (the difference goes to fee or other outputs)
      if (inputValues[i] >= outputValues[j] - feePerInput) {
        compatible[i][j] = true
      }
    }
  }

  // Count valid assignments using backtracking
  // A valid assignment: each output is funded by exactly one input,
  // and each input's total funding doesn't exceed its value + tolerance
  const interpretations = countAssignments(compatible, inputValues, outputValues, feePerInput)

  const entropy = interpretations > 0 ? Math.log2(interpretations) : 0

  // Max entropy: if all assignments were valid = nIn^nOut (each output could come from any input)
  const maxEntropy = nOut * Math.log2(nIn)
  const efficiency = maxEntropy > 0 ? entropy / maxEntropy : 0

  // Link probability matrix
  const linkMatrix = computeLinkMatrix(compatible, inputValues, outputValues, feePerInput, tx)

  return {
    entropy,
    maxEntropy,
    efficiency: Math.min(efficiency, 1),
    interpretations,
    linkProbabilities: linkMatrix,
    isLikelyCoinJoin: entropy > 1.0,
    txid: tx.txid,
  }
}

/**
 * Standard transaction (not CoinJoin).
 *
 * Typically 1-2 inputs, 1-2 outputs. The "entropy" is based on
 * how many ways the inputs could map to outputs — usually just 1
 * or 2 (payment vs change ambiguity).
 */
function standardTxBoltzmann(
  tx: Transaction,
  inputValues: number[],
  outputValues: number[],
): BoltzmannResult {
  const nIn = inputValues.length
  const nOut = outputValues.length

  if (nOut <= 1) {
    return {
      entropy: 0, maxEntropy: 0, efficiency: 0,
      interpretations: 1,
      linkProbabilities: uniformLinkMatrix(tx, nIn, nOut),
      isLikelyCoinJoin: false, txid: tx.txid,
    }
  }

  // For 2-output tx: 2 possible interpretations (which is change?)
  // But if change is detectable, effective interpretations = 1
  if (nOut === 2) {
    // Check if outputs are distinguishable
    const [v0, v1] = outputValues
    const roundDiff = Math.abs(roundness(v0) - roundness(v1))
    const distinguishable = roundDiff >= 2 // one is much rounder

    return {
      entropy: distinguishable ? 0.3 : 1.0, // partial vs full ambiguity
      maxEntropy: 1.0, // log₂(2) = 1 bit
      efficiency: distinguishable ? 0.3 : 1.0,
      interpretations: distinguishable ? 1 : 2,
      linkProbabilities: uniformLinkMatrix(tx, nIn, nOut),
      isLikelyCoinJoin: false, txid: tx.txid,
    }
  }

  // 3+ outputs: more complex, approximate
  const entropy = Math.log2(nOut) * 0.7 // rough: some outputs are distinguishable
  return {
    entropy,
    maxEntropy: Math.log2(nOut) * nIn,
    efficiency: Math.min(entropy / (Math.log2(nOut) * nIn), 1),
    interpretations: Math.round(Math.pow(2, entropy)),
    linkProbabilities: uniformLinkMatrix(tx, nIn, nOut),
    isLikelyCoinJoin: false, txid: tx.txid,
  }
}

/**
 * Count valid output→input assignments via backtracking.
 * Each output must be assigned to exactly one input.
 * Each input's assigned outputs must not exceed its value.
 */
function countAssignments(
  compatible: boolean[][],
  inputValues: number[],
  outputValues: number[],
  tolerance: number,
): number {
  const nIn = inputValues.length
  const nOut = outputValues.length
  const remaining = [...inputValues] // remaining capacity per input
  let count = 0

  // Cap search to prevent exponential blowup
  const MAX_SEARCH = 100000
  let searched = 0

  function backtrack(outIdx: number) {
    if (searched >= MAX_SEARCH) return
    if (outIdx === nOut) { count++; return }

    for (let i = 0; i < nIn; i++) {
      if (!compatible[i][outIdx]) continue
      if (remaining[i] + tolerance < outputValues[outIdx]) continue

      searched++
      remaining[i] -= outputValues[outIdx]
      backtrack(outIdx + 1)
      remaining[i] += outputValues[outIdx]
    }
  }

  backtrack(0)
  return count
}

/**
 * Compute link probability matrix P(input_i → output_j).
 *
 * For each pair (i, j), count how many valid assignments include
 * input i funding output j, divided by total valid assignments.
 */
function computeLinkMatrix(
  compatible: boolean[][],
  inputValues: number[],
  outputValues: number[],
  tolerance: number,
  tx: Transaction,
): LinkMatrix {
  const nIn = inputValues.length
  const nOut = outputValues.length

  // Approximate: use compatibility as a proxy for probability
  // (exact computation requires enumerating all assignments)
  const matrix: number[][] = Array.from({ length: nIn }, () => new Array(nOut).fill(0))

  for (let i = 0; i < nIn; i++) {
    let totalCompat = 0
    for (let j = 0; j < nOut; j++) {
      if (compatible[i][j]) totalCompat++
    }
    for (let j = 0; j < nOut; j++) {
      matrix[i][j] = compatible[i][j] && totalCompat > 0 ? 1 / totalCompat : 0
    }
  }

  return {
    inputs: tx.inputs.map(i => i.address),
    outputs: tx.outputs.map(o => o.address),
    matrix,
  }
}

function uniformLinkMatrix(tx: Transaction, nIn: number, nOut: number): LinkMatrix {
  const prob = nOut > 0 ? 1 / nOut : 0
  return {
    inputs: tx.inputs.map(i => i.address),
    outputs: tx.outputs.map(o => o.address),
    matrix: Array.from({ length: nIn }, () => new Array(nOut).fill(prob)),
  }
}

function factorial(n: number): number {
  if (n <= 1) return 1
  let r = 1
  for (let i = 2; i <= n; i++) r *= i
  return r
}

function roundness(sats: number): number {
  if (sats === 0) return 0
  let r = 0, v = sats
  while (v % 10 === 0 && v > 0) { r++; v = Math.floor(v / 10) }
  return r
}
