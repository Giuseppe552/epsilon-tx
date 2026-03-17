// Entropy primitives
export {
  shannonEntropy,
  conditionalEntropy,
  mutualInformation,
  binaryEntropy,
  anonymitySetSize,
  composedPrivacyScore,
} from './entropy/shannon.js'

export {
  amountEntropy,
  roundness,
  amountCorrelation,
} from './entropy/amount.js'

// Graph analysis
export {
  buildCoSpendGraph,
  findClusters,
  clusterStats,
  privacyExposure,
  findBridgeTransactions,
} from './graph/cospend.js'
export type { Transaction, CoSpendGraph } from './graph/cospend.js'

// Wallet fingerprinting
export {
  detectScriptType,
  detectChangeOutput,
  fingerprintTransaction,
  aggregateFingerprints,
  extractFeatures,
} from './fingerprint/wallet.js'
export type { ScriptType, WalletFingerprint, TransactionFeatures } from './fingerprint/wallet.js'

// Evidence fusion — Dempster-Shafer (1967, 1976)
export { createMass, combine, fuseEvidence, HEURISTIC_RELIABILITY, MAX_LEAKAGE_BITS } from './entropy/evidence.js'
export type { MassFunction, FusedResult } from './entropy/evidence.js'

// Spectral graph analysis — Fiedler (1973), Von Luxburg (2007)
export { analyseClusterSpectrum } from './graph/spectral.js'
export type { SpectralAnalysis } from './graph/spectral.js'

// Timing analysis
export { analyseTimingPrivacy } from './entropy/timing.js'
export type { TimingAnalysis } from './entropy/timing.js'

// Unified analysis
export { analyseAddress } from './analyse.js'
export type { PrivacyReport } from './analyse.js'

// Bitcoin API
export {
  getAddressTransactions,
  getTransaction,
  getUtxos,
  getAddressSummary,
  clearCache,
} from './bitcoin/api.js'
