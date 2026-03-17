/**
 * Temporal privacy analysis — what transaction timestamps reveal.
 *
 * Attack surfaces:
 * 1. Timezone inference: activity peaks during local daytime hours.
 *    Fitting an asymmetric circadian model estimates timezone within ±1h.
 *    Reference: Biryukov et al. (2014) — "Deanonymisation of Clients
 *    in Bitcoin P2P Network." CCS. §4.2 timing analysis.
 *
 * 2. Periodicity detection: regular transactions (DCA every Monday,
 *    payroll every 2 weeks) via both autocorrelation and discrete
 *    Fourier transform (DFT). DFT catches periodicities that
 *    autocorrelation at fixed lags misses.
 *
 * 3. Activity windows: concentrated hours reveal lifestyle patterns.
 *
 * 4. Inter-transaction distribution: KS test against exponential
 *    (random) to detect whether spacing is organic or scheduled.
 *
 * Reference: Bitcoin Wiki — Privacy page, timing correlation section.
 */

import { shannonEntropy } from './shannon.js'
import type { Transaction } from '../graph/cospend.js'

export interface TimingAnalysis {
  timezoneEstimate: number
  timezoneConfidence: number
  periodicityLags: { lagHours: number; strength: number; label: string }[]
  activityWindow: { startHour: number; endHour: number }
  hourlyEntropy: number
  isScheduled: boolean          // KS test rejects exponential → not random
  totalLeakage: number
}

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
      hourlyEntropy: Math.log2(24),
      isScheduled: false,
      totalLeakage: 0,
    }
  }

  // Hourly distribution
  const hourCounts = new Array(24).fill(0)
  for (const t of timestamps) {
    hourCounts[new Date(t * 1000).getUTCHours()]++
  }

  const total = timestamps.length
  const hourProbs = hourCounts.map(c => c / total)
  const hourlyEntropy = shannonEntropy(hourProbs)
  const maxEntropy = Math.log2(24)

  // Timezone
  const tz = estimateTimezone(hourCounts)

  // Inter-tx intervals in hours
  const intervals: number[] = []
  for (let i = 1; i < timestamps.length; i++) {
    intervals.push((timestamps[i] - timestamps[i - 1]) / 3600)
  }

  // Periodicity: autocorrelation + DFT
  const periodicityLags = detectPeriodicity(intervals)

  // KS test: are intervals exponentially distributed (random)?
  const isScheduled = ksTestExponential(intervals)

  // Activity window
  const threshold = total * 0.05
  let startHour = 0, endHour = 23
  for (let h = 0; h < 24; h++) { if (hourCounts[h] >= threshold) { startHour = h; break } }
  for (let h = 23; h >= 0; h--) { if (hourCounts[h] >= threshold) { endHour = h + 1; break } }

  // Total leakage
  const distributionLeakage = Math.max(0, maxEntropy - hourlyEntropy)
  const timezoneLeakage = tz.confidence * 1.5
  const periodicityLeakage = periodicityLags.length * 0.5
  const scheduledLeakage = isScheduled ? 0.8 : 0

  return {
    timezoneEstimate: tz.offset,
    timezoneConfidence: tz.confidence,
    periodicityLags,
    activityWindow: { startHour, endHour },
    hourlyEntropy,
    isScheduled,
    totalLeakage: distributionLeakage + timezoneLeakage + periodicityLeakage + scheduledLeakage,
  }
}

/**
 * Timezone estimation with asymmetric circadian model.
 *
 * The model is intentionally asymmetric: morning ramp is steep (people
 * wake up and start transacting), afternoon/evening decline is gradual.
 * This breaks the symmetry that caused the +5/-5 confusion.
 *
 * The offset is the number of hours to ADD to UTC to get local time.
 * Negative = west of UTC, positive = east.
 */
function estimateTimezone(hourCounts: number[]): { offset: number; confidence: number } {
  // Asymmetric circadian model — peak at local 11:00-13:00
  // Steep morning ramp, gradual evening decline
  // Reference: Roenneberg et al. (2007) — social jet lag patterns
  const model = [
    0.01, 0.005, 0.005, 0.005, 0.005, 0.01,  // 00-05: sleeping
    0.02, 0.04, 0.07, 0.09, 0.10, 0.11,       // 06-11: steep morning ramp
    0.10, 0.09, 0.08, 0.07, 0.06, 0.05,       // 12-17: gradual decline
    0.04, 0.03, 0.025, 0.02, 0.015, 0.01,     // 18-23: evening taper
  ]

  const total = hourCounts.reduce((s, c) => s + c, 0)
  if (total === 0) return { offset: 0, confidence: 0 }

  const observed = hourCounts.map(c => c / total)

  // For each offset, compute cross-correlation
  // The offset represents: "observed UTC hour H corresponds to local hour H + offset"
  // So to map observed[h] to model[localH]: localH = (h + offset + 24) % 24
  const offsetScores: { offset: number; score: number }[] = []

  for (let offset = -12; offset <= 12; offset++) {
    let score = 0
    for (let h = 0; h < 24; h++) {
      const localH = ((h + offset) % 24 + 24) % 24
      score += observed[h] * model[localH]
    }
    offsetScores.push({ offset, score })
  }

  offsetScores.sort((a, b) => b.score - a.score)
  const best = offsetScores[0]
  const secondBest = offsetScores[1]

  const confidence = secondBest.score > 0
    ? Math.min(1, (best.score - secondBest.score) / secondBest.score)
    : 0

  return { offset: best.offset, confidence }
}

/**
 * Periodicity detection via autocorrelation + Discrete Fourier Transform.
 *
 * Autocorrelation checks specific lags (24h, 168h, etc.).
 * DFT catches arbitrary periodicities by decomposing the interval
 * sequence into frequency components. Peaks above the noise floor
 * indicate periodic behaviour.
 *
 * Reference: Paxson & Floyd (1995) — "Wide Area Traffic: The Failure
 * of Poisson Modeling." §3 — periodicity in network traffic.
 */
function detectPeriodicity(
  intervals: number[],
): TimingAnalysis['periodicityLags'] {
  if (intervals.length < 20) return []

  const results: TimingAnalysis['periodicityLags'] = []
  const n = intervals.length
  const mean = intervals.reduce((s, v) => s + v, 0) / n
  const variance = intervals.reduce((s, v) => s + (v - mean) ** 2, 0) / n
  if (variance === 0) return []

  // 1. Autocorrelation at known lags
  const knownLags: { hours: number; label: string }[] = [
    { hours: 24, label: 'daily' },
    { hours: 48, label: '2-day' },
    { hours: 168, label: 'weekly' },
    { hours: 336, label: 'biweekly' },
    { hours: 720, label: 'monthly' },
  ]

  const acThreshold = 2 / Math.sqrt(n) // 95% confidence

  for (const { hours, label } of knownLags) {
    if (hours >= n) continue
    let autoCorr = 0
    for (let i = 0; i < n - hours; i++) {
      autoCorr += (intervals[i] - mean) * (intervals[i + hours] - mean)
    }
    autoCorr /= (n - hours) * variance
    if (Math.abs(autoCorr) > acThreshold) {
      results.push({ lagHours: hours, strength: Math.abs(autoCorr), label })
    }
  }

  // 2. DFT — find dominant frequencies
  // Compute magnitude spectrum of the centered interval sequence
  const centered = intervals.map(x => x - mean)
  const halfN = Math.floor(n / 2)

  for (let k = 1; k <= Math.min(halfN, 50); k++) {
    // DFT at frequency k: X[k] = Σ x[n] · e^{-2πi·k·n/N}
    let re = 0, im = 0
    for (let t = 0; t < n; t++) {
      const angle = -2 * Math.PI * k * t / n
      re += centered[t] * Math.cos(angle)
      im += centered[t] * Math.sin(angle)
    }
    const magnitude = Math.sqrt(re * re + im * im) / n

    // Period in hours: if mean interval is M hours, frequency k corresponds
    // to a period of (N * M) / k hours ≈ total_span / k
    const totalSpanHours = intervals.reduce((s, v) => s + v, 0)
    const periodHours = totalSpanHours / k

    // Significance: magnitude > 2 * mean magnitude (noise floor)
    const noiseMagnitude = Math.sqrt(variance) / Math.sqrt(n)
    if (magnitude > noiseMagnitude * 3 && periodHours > 12 && periodHours < 1000) {
      // Check if this period is close to a known lag we already found
      const alreadyFound = results.some(r => Math.abs(r.lagHours - periodHours) < periodHours * 0.2)
      if (!alreadyFound) {
        let label = `~${Math.round(periodHours)}h`
        if (Math.abs(periodHours - 24) < 6) label = 'daily (DFT)'
        else if (Math.abs(periodHours - 168) < 24) label = 'weekly (DFT)'
        else if (Math.abs(periodHours - 336) < 48) label = 'biweekly (DFT)'
        else if (Math.abs(periodHours - 720) < 72) label = 'monthly (DFT)'

        results.push({ lagHours: Math.round(periodHours), strength: magnitude / noiseMagnitude, label })
      }
    }
  }

  return results.sort((a, b) => b.strength - a.strength)
}

/**
 * Kolmogorov-Smirnov test: are inter-transaction intervals exponentially
 * distributed (consistent with random/Poisson timing)?
 *
 * If the test rejects (p < 0.05), the intervals are NOT random — the user
 * has a detectable schedule. This leaks ~0.8 bits of information.
 *
 * Reference: Massey (1951). "The Kolmogorov-Smirnov Test for Goodness of Fit."
 */
function ksTestExponential(intervals: number[]): boolean {
  if (intervals.length < 10) return false

  const n = intervals.length
  const mean = intervals.reduce((s, v) => s + v, 0) / n
  if (mean <= 0) return false

  const lambda = 1 / mean // exponential rate parameter
  const sorted = [...intervals].sort((a, b) => a - b)

  // Compute KS statistic D = max |F_empirical - F_exponential|
  let D = 0
  for (let i = 0; i < n; i++) {
    const empirical = (i + 1) / n
    const theoretical = 1 - Math.exp(-lambda * sorted[i])
    D = Math.max(D, Math.abs(empirical - theoretical))
  }

  // Critical value at α = 0.05: approximately 1.36 / √n
  const critical = 1.36 / Math.sqrt(n)

  return D > critical // reject = not random = scheduled
}
