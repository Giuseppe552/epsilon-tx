/**
 * Information-theoretic primitives for privacy quantification.
 *
 * All privacy measurements in ε-tx reduce to entropy computations.
 * A perfectly private transaction has H(sender | blockchain) = H(sender) —
 * observing the blockchain tells the adversary nothing.
 * A fully exposed transaction has H(sender | blockchain) = 0 —
 * the sender is deterministic given the blockchain.
 *
 * The privacy loss (mutual information) is:
 *   I(S; R | B) = H(S | B) - H(S | R, B)
 *
 * where S = sender, R = receiver, B = blockchain observation.
 * ε-tx computes upper bounds on I for proposed transactions.
 *
 * Reference: Shannon, C.E. (1948). A Mathematical Theory of Communication.
 */

/**
 * Shannon entropy: H(X) = -Σ p(x) log₂ p(x)
 *
 * Measures uncertainty in bits. Maximum when all outcomes are equally
 * likely (uniform distribution). Zero when one outcome is certain.
 *
 * @param probabilities - Array of probabilities (must sum to 1)
 * @returns Entropy in bits
 */
export function shannonEntropy(probabilities: number[]): number {
  let H = 0
  for (const p of probabilities) {
    if (p > 0 && p <= 1) {
      H -= p * Math.log2(p)
    }
  }
  return H
}

/**
 * Conditional entropy: H(X | Y) = Σ P(y) · H(X | Y=y)
 *
 * Measures remaining uncertainty about X after observing Y.
 * Privacy application: H(sender | observed_features) — how uncertain
 * is an adversary about the sender given what they can observe?
 *
 * @param jointProbabilities - P(x, y) as a 2D array [x][y]
 * @returns Conditional entropy H(X | Y) in bits
 */
export function conditionalEntropy(jointProbabilities: number[][]): number {
  const numY = jointProbabilities[0]?.length ?? 0
  if (numY === 0) return 0

  // P(Y=y) = Σ_x P(x, y)
  const pY: number[] = new Array(numY).fill(0)
  for (const row of jointProbabilities) {
    for (let y = 0; y < numY; y++) {
      pY[y] += row[y]
    }
  }

  // H(X | Y) = Σ_y P(y) · H(X | Y=y)
  let H = 0
  for (let y = 0; y < numY; y++) {
    if (pY[y] <= 0) continue

    // H(X | Y=y) = -Σ_x P(x|y) log₂ P(x|y)
    // where P(x|y) = P(x,y) / P(y)
    let Hy = 0
    for (const row of jointProbabilities) {
      const pXgivenY = row[y] / pY[y]
      if (pXgivenY > 0 && pXgivenY <= 1) {
        Hy -= pXgivenY * Math.log2(pXgivenY)
      }
    }
    H += pY[y] * Hy
  }

  return H
}

/**
 * Mutual information: I(X; Y) = H(X) - H(X | Y)
 *
 * Measures how much observing Y reduces uncertainty about X.
 * Privacy application: I(sender; blockchain_features) — how much
 * information does the blockchain leak about the sender?
 *
 * This is the core privacy metric. ε-tx aims to bound I ≤ ε.
 *
 * @param jointProbabilities - P(x, y) as a 2D array
 * @returns Mutual information in bits
 */
export function mutualInformation(jointProbabilities: number[][]): number {
  // P(X=x) = Σ_y P(x, y)
  const pX: number[] = jointProbabilities.map(row => row.reduce((a, b) => a + b, 0))

  const Hx = shannonEntropy(pX)
  const HxGivenY = conditionalEntropy(jointProbabilities)

  return Math.max(0, Hx - HxGivenY)
}

/**
 * Binary entropy: H(p) = -p·log₂(p) - (1-p)·log₂(1-p)
 *
 * Special case for a binary random variable. Used for
 * change detection: P(output is change) = p.
 *
 * @param p - Probability of one outcome
 * @returns Entropy in bits (max 1 at p=0.5)
 */
export function binaryEntropy(p: number): number {
  if (p <= 0 || p >= 1) return 0
  return -p * Math.log2(p) - (1 - p) * Math.log2(1 - p)
}

/**
 * Anonymity set size from entropy.
 *
 * Effective anonymity set = 2^H. If H = 4 bits, the effective
 * anonymity set is 16 — equivalent to a uniform distribution
 * over 16 candidates.
 *
 * @param entropyBits - Entropy in bits
 * @returns Effective anonymity set size
 */
export function anonymitySetSize(entropyBits: number): number {
  return Math.pow(2, entropyBits)
}

/**
 * Privacy score from multiple independent leakage sources.
 *
 * If attack surfaces are independent, total information leakage
 * is bounded by the sum: I_total ≤ Σ I_i
 *
 * This is analogous to differential privacy composition:
 * ε_total ≤ Σ ε_i (basic composition theorem).
 *
 * @param leakages - Array of { source, bits } — leakage per attack surface
 * @returns Total privacy score
 */
export function composedPrivacyScore(
  leakages: { source: string; bits: number }[],
): { total: number; breakdown: { source: string; bits: number }[] } {
  const total = leakages.reduce((sum, l) => sum + l.bits, 0)
  return {
    total,
    breakdown: leakages.sort((a, b) => b.bits - a.bits),
  }
}
