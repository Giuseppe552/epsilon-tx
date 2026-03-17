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
} from './fingerprint/wallet.js'
export type { ScriptType, WalletFingerprint } from './fingerprint/wallet.js'

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
