/**
 * Temporal privacy analysis — what transaction timestamps reveal.
 *
 * Attack surfaces:
 * 1. Timezone inference: activity peaks during local daytime hours.
 *    Fitting a circadian model estimates timezone within ±1 hour.
 *    Reference: Biryukov et al. (2014) — "Deanonymisation of Clients
 *    in Bitcoin P2P Network." CCS. §4.2 timing analysis.
 *
 * 2. Periodicity detection: regular transactions (DCA every Monday,
 *    payroll every 2 weeks) create autocorrelation at specific lags.
 *
 * 3. Activity windows: transactions only during business hours
 *    suggest a corporate wallet. Only evenings suggest personal.
 *
 * We measure each as information leakage in bits.
 *
 * Reference: Bitcoin Wiki Privacy — Timing correlation section.
 */

import { shannonEntropy } from './shannon.js'
import type { Transaction } from '../graph/cospend.js'

export interface TimingAnalysis {
  timezoneEstimate: number       // UTC offset in hours (e.g., 0 = UK, -5 = EST)
  timezoneConfidence: number     // 0-1
  periodicityLags: number[]      // detected periodic lags in hours
  activityWindow: { startHour: number; endHour: number }
  hourlyEntropy: number          // bits — higher = more uniform = more private
  totalLeakage: number           // bits of information leaked by timing
}

/**
 * Analyse transaction timing patterns.
 *
 * @param transactions - Transactions with timestamps (unix seconds)
 * @returns Timing privacy analysis
 */
export function analyseTimingPrivacy(transactions: Transaction[]): TimingAnalysis {
  const timestamps = transactions
    .map(tx => tx.timestamp)
    .filter(t => t > 0)
    .sort((a, b) => a - b)

  if (timestamps.length < 5) {
    return {
      timezoneEstimate: 0,
      timezoneConfidence: 0,
      periodicityLags: [],
      activityWindow: { startHour: 0, endHour: 24 },
      hourlyEntropy: Math.log2(24), // max: uniform across 24 hours
      totalLeakage: 0,
    }
  }

  // Bin transactions by UTC hour
  const hourCounts = new Array(24).fill(0)
  for (const t of timestamps) {
    const hour = new Date(t * 1000).getUTCHours()
    hourCounts[hour]++
  }

  // Hourly entropy: how uniform is the activity across hours?
  const total = timestamps.length
  const hourProbs = hourCounts.map(c => c / total)
  const hourlyEntropy = shannonEntropy(hourProbs)
  const maxEntropy = Math.log2(24) // ~4.58 bits for uniform

  // Timezone estimation: find the UTC offset that centres activity
  // around typical waking hours (peak at local 12:00-14:00).
  // Try all 24 offsets, score each by how well it fits a circadian model.
  const tz = estimateTimezone(hourCounts)

  // Periodicity: autocorrelation on inter-transaction intervals
  const intervals = []
  for (let i = 1; i < timestamps.length; i++) {
    intervals.push((timestamps[i] - timestamps[i - 1]) / 3600) // hours
  }
  const periodicityLags = detectPeriodicity(intervals)

  // Activity window: hours with >5% of transactions
  const threshold = total * 0.05
  let startHour = 0
  let endHour = 23
  for (let h = 0; h < 24; h++) {
    if (hourCounts[h] >= threshold) { startHour = h; break }
  }
  for (let h = 23; h >= 0; h--) {
    if (hourCounts[h] >= threshold) { endHour = h + 1; break }
  }

  // Total timing leakage
  // = (maxEntropy - hourlyEntropy) for activity distribution
  // + timezone confidence (knowing timezone narrows geography)
  // + periodicity bonus (each detected period leaks schedule info)
  const distributionLeakage = Math.max(0, maxEntropy - hourlyEntropy)
  const timezoneLeakage = tz.confidence * 1.5 // timezone worth ~1.5 bits
  const periodicityLeakage = periodicityLags.length * 0.5 // each pattern ~0.5 bits

  const totalLeakage = distributionLeakage + timezoneLeakage + periodicityLeakage

  return {
    timezoneEstimate: tz.offset,
    timezoneConfidence: tz.confidence,
    periodicityLags,
    activityWindow: { startHour, endHour },
    hourlyEntropy,
    totalLeakage,
  }
}

/**
 * Estimate the most likely timezone from hourly activity distribution.
 *
 * Model: humans are most active at local hours 09:00-21:00 with a
 * peak at 12:00-14:00. We shift the observed UTC distribution by
 * each possible offset and measure how well it fits this model.
 */
function estimateTimezone(hourCounts: number[]): { offset: number; confidence: number } {
  // Circadian model: expected relative activity per local hour
  // Peak at 12-14, low at 02-06
  const model = [
    0.02, 0.01, 0.01, 0.01, 0.01, 0.02, // 00-05: sleeping
    0.03, 0.05, 0.06, 0.07, 0.08, 0.09, // 06-11: morning ramp
    0.10, 0.09, 0.08, 0.07, 0.06, 0.05, // 12-17: afternoon
    0.04, 0.03, 0.02, 0.02, 0.01, 0.01, // 18-23: evening decline
  ]

  const total = hourCounts.reduce((s, c) => s + c, 0)
  if (total === 0) return { offset: 0, confidence: 0 }

  const observed = hourCounts.map(c => c / total)

  let bestOffset = 0
  let bestScore = -Infinity

  for (let offset = -12; offset <= 12; offset++) {
    // Shift observed distribution by -offset to get "local time" distribution
    let score = 0
    for (let h = 0; h < 24; h++) {
      const localH = ((h - offset) % 24 + 24) % 24
      // Correlation between observed and model
      score += observed[h] * model[localH]
    }
    if (score > bestScore) {
      bestScore = score
      bestOffset = offset
    }
  }

  // Confidence: how much better is the best fit vs the second best?
  const scores: number[] = []
  for (let offset = -12; offset <= 12; offset++) {
    let score = 0
    for (let h = 0; h < 24; h++) {
      const localH = ((h - offset) % 24 + 24) % 24
      score += observed[h] * model[localH]
    }
    scores.push(score)
  }
  scores.sort((a, b) => b - a)
  const confidence = scores.length >= 2 && scores[1] > 0
    ? Math.min(1, (scores[0] - scores[1]) / scores[1])
    : 0

  return { offset: bestOffset, confidence }
}

/**
 * Detect periodicity in inter-transaction intervals using autocorrelation.
 *
 * Returns lag values (in hours) where significant autocorrelation exists.
 * Common patterns:
 *   - 24h: daily transactions
 *   - 168h (7 days): weekly
 *   - 336h (14 days): biweekly (payroll)
 *   - 720h (30 days): monthly
 */
function detectPeriodicity(intervals: number[]): number[] {
  if (intervals.length < 20) return []

  const n = intervals.length
  const mean = intervals.reduce((s, v) => s + v, 0) / n
  const variance = intervals.reduce((s, v) => s + (v - mean) ** 2, 0) / n

  if (variance === 0) return []

  const lags = [24, 48, 168, 336, 720] // hours: daily, 2-day, weekly, biweekly, monthly
  const significantLags: number[] = []

  // 95% confidence threshold for autocorrelation
  const threshold = 2 / Math.sqrt(n)

  for (const lag of lags) {
    if (lag >= n) continue

    let autoCorr = 0
    for (let i = 0; i < n - lag; i++) {
      autoCorr += (intervals[i] - mean) * (intervals[i + lag] - mean)
    }
    autoCorr /= (n - lag) * variance

    if (Math.abs(autoCorr) > threshold) {
      significantLags.push(lag)
    }
  }

  return significantLags
}
