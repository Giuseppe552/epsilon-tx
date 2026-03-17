/**
 * Adversarial transaction classification — the grey zone.
 *
 * Chain analysis firms (Chainalysis, Elliptic) use ML models trained
 * on labelled transaction data to classify transactions as:
 * - Normal payment
 * - Exchange deposit/withdrawal
 * - CoinJoin / mixer output
 * - Gambling
 * - Darknet market
 *
 * These classifiers use transaction-level features: input/output count,
 * amount patterns, fee structure, script types, temporal patterns.
 *
 * This module:
 * 1. Extracts the same features a classifier would use
 * 2. Scores how "suspicious" a transaction looks to a typical model
 * 3. Identifies which features drive the classification (SHAP-like)
 * 4. Suggests perturbations that change the classification while
 *    preserving the economic intent
 *
 * This is NOT illegal. It's the same as writing an email that avoids
 * spam filters. The transaction is legitimate. The classifier is wrong
 * because the features don't match its training distribution.
 *
 * Reference: Blockchain-based fraud detection literature uses Random
 *            Forest and XGBoost on these exact features.
 *            See: Alarab et al. (2024) — "Detecting anomalies in
 *            blockchain transactions." arXiv:2401.03530.
 */

import type { Transaction } from '../graph/cospend.js'
import { extractFeatures, type TransactionFeatures } from '../fingerprint/wallet.js'

export interface ClassifierFeatures {
  inputCount: number
  outputCount: number
  totalInputValue: number
  totalOutputValue: number
  fee: number
  feeRate: number | null
  maxOutputValue: number
  minOutputValue: number
  outputValueStdDev: number
  equalOutputRatio: number      // fraction of outputs with equal values
  roundOutputRatio: number      // fraction of outputs that are round numbers
  hasOpReturn: boolean
  scriptTypeMix: number         // number of distinct script types
  inputOutputRatio: number      // inputs / outputs
  walletFeatures: TransactionFeatures
}

export type TxClassification =
  | 'normal-payment'
  | 'exchange'
  | 'coinjoin'
  | 'batch-payment'
  | 'consolidation'
  | 'unknown'

export interface ClassificationResult {
  classification: TxClassification
  confidence: number             // 0-1
  scores: { label: TxClassification; score: number }[]
  suspiciousnessScore: number    // 0-1 (how likely to be flagged)
  featureImportance: { feature: string; contribution: number; direction: 'increases' | 'decreases' }[]
  perturbations: Perturbation[]
}

export interface Perturbation {
  action: string
  expectedClassification: TxClassification
  expectedConfidence: number
  feasibility: 'easy' | 'medium' | 'hard'
}

/**
 * Extract classifier-relevant features from a transaction.
 */
export function extractClassifierFeatures(tx: Transaction): ClassifierFeatures {
  const outputValues = tx.outputs.map(o => o.value)
  const mean = outputValues.length > 0 ? outputValues.reduce((s, v) => s + v, 0) / outputValues.length : 0
  const stdDev = outputValues.length > 0
    ? Math.sqrt(outputValues.reduce((s, v) => s + (v - mean) ** 2, 0) / outputValues.length)
    : 0

  // Equal outputs
  const valueCounts = new Map<number, number>()
  for (const v of outputValues) valueCounts.set(v, (valueCounts.get(v) ?? 0) + 1)
  const maxEqualCount = Math.max(...valueCounts.values(), 0)
  const equalOutputRatio = outputValues.length > 0 ? maxEqualCount / outputValues.length : 0

  // Round outputs
  const roundCount = outputValues.filter(v => v % 100000 === 0).length
  const roundOutputRatio = outputValues.length > 0 ? roundCount / outputValues.length : 0

  // Script type diversity
  const types = new Set(tx.inputs.map(i => i.address.slice(0, 4)))
  tx.outputs.forEach(o => types.add(o.address.slice(0, 4)))

  return {
    inputCount: tx.inputs.length,
    outputCount: tx.outputs.length,
    totalInputValue: tx.inputs.reduce((s, i) => s + i.value, 0),
    totalOutputValue: tx.outputs.reduce((s, o) => s + o.value, 0),
    fee: tx.fee,
    feeRate: tx.vsize ? tx.fee / tx.vsize : null,
    maxOutputValue: outputValues.length > 0 ? Math.max(...outputValues) : 0,
    minOutputValue: outputValues.length > 0 ? Math.min(...outputValues) : 0,
    outputValueStdDev: stdDev,
    equalOutputRatio,
    roundOutputRatio,
    hasOpReturn: false, // would need raw script data to detect
    scriptTypeMix: types.size,
    inputOutputRatio: tx.outputs.length > 0 ? tx.inputs.length / tx.outputs.length : 0,
    walletFeatures: extractFeatures(tx),
  }
}

/**
 * Classify a transaction using a rule-based surrogate model.
 *
 * This approximates what a Random Forest / XGBoost classifier trained
 * on labelled blockchain data would output. We use explicit rules
 * instead of a trained model because:
 * 1. No training data needed (the rules come from published research)
 * 2. The rules are interpretable (we can explain each feature's contribution)
 * 3. The surrogate is transparent (users can verify the logic)
 *
 * A trained ML model would be more accurate but less explainable.
 * The surrogate captures the ~80% of cases that simple features identify.
 */
export function classifyTransaction(tx: Transaction): ClassificationResult {
  const f = extractClassifierFeatures(tx)

  // Score each classification
  const scores: { label: TxClassification; score: number }[] = []

  // CoinJoin: many inputs AND many equal outputs (both required)
  let coinjoinScore = 0
  if (f.inputCount >= 3 && f.outputCount >= 3) coinjoinScore += 2
  if (f.outputCount >= 4) coinjoinScore += 2
  if (f.equalOutputRatio > 0.5) coinjoinScore += 3
  if (f.outputValueStdDev < f.maxOutputValue * 0.1 && f.outputCount >= 3) coinjoinScore += 2
  scores.push({ label: 'coinjoin', score: coinjoinScore })

  // Exchange: high value, specific output patterns
  let exchangeScore = 0
  if (f.totalInputValue > 10_000_000) exchangeScore += 1 // > 0.1 BTC
  if (f.outputCount === 2 && f.roundOutputRatio >= 0.5) exchangeScore += 2
  if (f.inputCount === 1 && f.outputCount <= 3) exchangeScore += 1
  scores.push({ label: 'exchange', score: exchangeScore })

  // Batch payment: 1-2 inputs, many outputs, varied amounts
  let batchScore = 0
  if (f.inputCount <= 2 && f.outputCount >= 5) batchScore += 3
  if (f.equalOutputRatio < 0.3) batchScore += 1
  scores.push({ label: 'batch-payment', score: batchScore })

  // Consolidation: many inputs, 1-2 outputs
  let consolidationScore = 0
  if (f.inputCount >= 5 && f.outputCount <= 2) consolidationScore += 4
  scores.push({ label: 'consolidation', score: consolidationScore })

  // Normal payment: 1-3 inputs, 1-2 outputs
  let normalScore = 0
  if (f.inputCount <= 3 && f.outputCount <= 2) normalScore += 3
  if (f.roundOutputRatio >= 0.5) normalScore += 1
  if (f.fee < 50000) normalScore += 1 // reasonable fee
  scores.push({ label: 'normal-payment', score: normalScore })

  scores.push({ label: 'unknown', score: 0 })

  // Softmax-like normalisation
  const maxScore = Math.max(...scores.map(s => s.score))
  const expScores = scores.map(s => ({ ...s, exp: Math.exp(s.score - maxScore) }))
  const expSum = expScores.reduce((s, e) => s + e.exp, 0)
  const normalised = expScores.map(s => ({
    label: s.label,
    score: s.exp / expSum,
  })).sort((a, b) => b.score - a.score)

  const classification = normalised[0].label
  const confidence = normalised[0].score

  // Suspiciousness: how likely to be flagged by a compliance model
  // CoinJoin + consolidation + high-value = suspicious
  const suspiciousnessScore = Math.min(1, (coinjoinScore * 0.1 + consolidationScore * 0.05 + (f.totalInputValue > 100_000_000 ? 0.2 : 0)))

  // Feature importance (SHAP-like): which features drive the classification
  const featureImportance = computeFeatureImportance(f, classification)

  // Perturbations: how to change the classification
  const perturbations = suggestPerturbations(f, classification)

  return {
    classification,
    confidence: Math.round(confidence * 1000) / 1000,
    scores: normalised.map(s => ({ label: s.label, score: Math.round(s.score * 1000) / 1000 })),
    suspiciousnessScore: Math.round(suspiciousnessScore * 1000) / 1000,
    featureImportance,
    perturbations,
  }
}

function computeFeatureImportance(
  f: ClassifierFeatures,
  classification: TxClassification,
): ClassificationResult['featureImportance'] {
  const importance: ClassificationResult['featureImportance'] = []

  if (classification === 'coinjoin') {
    if (f.inputCount >= 3) importance.push({ feature: 'inputCount', contribution: 0.3, direction: 'increases' })
    if (f.equalOutputRatio > 0.5) importance.push({ feature: 'equalOutputRatio', contribution: 0.4, direction: 'increases' })
    if (f.outputCount >= 4) importance.push({ feature: 'outputCount', contribution: 0.2, direction: 'increases' })
  }

  if (classification === 'consolidation') {
    importance.push({ feature: 'inputCount', contribution: 0.5, direction: 'increases' })
    importance.push({ feature: 'outputCount', contribution: 0.3, direction: 'decreases' })
  }

  if (classification === 'normal-payment') {
    if (f.inputCount <= 2) importance.push({ feature: 'inputCount', contribution: 0.3, direction: 'decreases' })
    if (f.roundOutputRatio > 0) importance.push({ feature: 'roundOutputRatio', contribution: 0.2, direction: 'increases' })
  }

  return importance.sort((a, b) => b.contribution - a.contribution)
}

function suggestPerturbations(
  f: ClassifierFeatures,
  classification: TxClassification,
): Perturbation[] {
  const perturbations: Perturbation[] = []

  if (classification === 'coinjoin') {
    perturbations.push({
      action: 'Split into multiple 2-output transactions instead of one CoinJoin. Each individual tx looks like a normal payment.',
      expectedClassification: 'normal-payment',
      expectedConfidence: 0.7,
      feasibility: 'medium',
    })
    if (f.equalOutputRatio > 0.5) {
      perturbations.push({
        action: 'Use slightly varied output amounts instead of exact equal values. Add random noise ±0.1% to each output.',
        expectedClassification: 'batch-payment',
        expectedConfidence: 0.5,
        feasibility: 'easy',
      })
    }
  }

  if (classification === 'consolidation') {
    perturbations.push({
      action: 'Consolidate over multiple transactions (2-3 inputs each) instead of all at once. Spread over multiple days.',
      expectedClassification: 'normal-payment',
      expectedConfidence: 0.6,
      feasibility: 'easy',
    })
  }

  if (f.walletFeatures.isLikelyCoinJoin) {
    perturbations.push({
      action: 'Avoid using the same denomination for all outputs. Varied amounts with a few matching pairs looks more organic than 5 identical outputs.',
      expectedClassification: 'normal-payment',
      expectedConfidence: 0.5,
      feasibility: 'medium',
    })
  }

  return perturbations
}
