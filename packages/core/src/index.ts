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

// CoinJoin analysis — LaurentMT (2016), Maurer et al. (2025)
export { computeBoltzmann } from './coinjoin/boltzmann.js'
export type { BoltzmannResult, LinkMatrix } from './coinjoin/boltzmann.js'

export { analysePostMix } from './coinjoin/postmix.js'
export type { PostMixAnalysis, PostMixIssue } from './coinjoin/postmix.js'

// Monero ring analysis — OSPEAD (2025), Möser et al. (2018)
export { analyseRing, constructOptimalRing } from './monero/ring.js'
export type { RingMember, RingAnalysis, OptimalRing } from './monero/ring.js'

// Lightning routing privacy — Romiti (2020), Herrera-Joancomartí (2019)
export { computeSenderAnonymity, computeTimingLeakage, computeBalanceProbeResistance, analyseRoutePrivacy, paretoFrontier } from './lightning/routing.js'
export type { LightningNode, LightningChannel, RouteHop, RoutePrivacy, ParetoPoint } from './lightning/routing.js'

// Unified analysis
export { analyseAddress } from './analyse.js'
export type { PrivacyReport } from './analyse.js'

// Recommendations — Ishaana Misra (2024), Bitcoin Wiki Privacy
export { generateRecommendations } from './fingerprint/recommendations.js'
export type { Recommendation } from './fingerprint/recommendations.js'

// Graph expansion — Meiklejohn et al. (2013) §3
export { expandGraph } from './bitcoin/expand.js'

// Bitcoin API
export {
  getAddressTransactions,
  getTransaction,
  getUtxos,
  getAddressSummary,
  clearCache,
} from './bitcoin/api.js'
