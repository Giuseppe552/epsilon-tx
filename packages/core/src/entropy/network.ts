/**
 * Network-level privacy analysis — transaction propagation timing.
 *
 * When you broadcast a Bitcoin transaction, the first node to relay
 * it is likely your node or your node's direct peer. An adversary
 * running multiple listening nodes can observe propagation patterns
 * and infer the origin IP.
 *
 * Biryukov et al. (2014) demonstrated 11-60% accuracy in linking
 * transactions to IP addresses via propagation timing.
 *
 * A 2025 paper (arXiv:2508.21440) found that RPC users (Electrum,
 * etc.) can be deanonymized via temporal correlation between the
 * wallet-RPC-network interaction pattern — awarded CVE-2025-43968.
 *
 * A 2025 network topology study (arXiv:2506.14197) showed that most
 * blocks arrive at mining nodes within 50ms but take seconds to reach
 * home nodes — confirming that propagation delay reveals node type.
 *
 * This module estimates the network-level privacy risk based on:
 * 1. Are you using a full node or a light client (SPV/Electrum)?
 * 2. Are you broadcasting through Tor?
 * 3. How many connections does your node have?
 *
 * Reference: Biryukov et al. (2014). "Deanonymisation of Clients
 *            in Bitcoin P2P Network." CCS.
 * Reference: arXiv:2508.21440 (2025). "Time Tells All: Deanonymization
 *            of Blockchain RPC Users." CVE-2025-43968.
 * Reference: arXiv:2506.14197 (2025). "The Redundancy of Full Nodes
 *            in Bitcoin." Network topology analysis.
 */

export type NodeType = 'full-node' | 'light-client' | 'spv' | 'electrum' | 'unknown'
export type BroadcastMethod = 'direct' | 'tor' | 'vpn' | 'rpc-provider' | 'unknown'

export interface NetworkPrivacyInput {
  nodeType: NodeType
  broadcastMethod: BroadcastMethod
  connectionCount: number       // number of peers your node connects to
  usesTor: boolean
  usesRpcProvider: boolean      // Electrum server, Blockstream API, etc.
  rpcProviderName?: string
}

export interface NetworkPrivacy {
  ipLeakageRisk: number        // bits — how much IP info leaks
  nodeTypeLeakage: number      // bits — leaked by propagation timing
  rpcCorrelation: number       // bits — CVE-2025-43968 temporal correlation
  totalLeakage: number         // bits — combined network-level risk
  recommendations: string[]
}

/**
 * Analyse network-level privacy.
 *
 * This is a risk ASSESSMENT, not a measurement — we can't observe
 * actual propagation from the API. We estimate based on configuration.
 */
export function analyseNetworkPrivacy(input: NetworkPrivacyInput): NetworkPrivacy {
  const recs: string[] = []

  // IP leakage: depends on broadcast method
  let ipLeakage = 0
  switch (input.broadcastMethod) {
    case 'direct':
      // Broadcasting from your own IP → Biryukov 11-60% accuracy
      // Average case: ~30% → about 1.7 bits
      ipLeakage = input.usesTor ? 0.3 : 1.7
      if (!input.usesTor) {
        recs.push('broadcast through Tor to prevent IP-to-transaction linking (Biryukov et al. 2014 achieved 11-60% accuracy without it)')
      }
      break
    case 'tor':
      ipLeakage = 0.3 // Tor exit node is known but not your IP
      break
    case 'vpn':
      ipLeakage = 0.8 // VPN provider knows your IP + activity
      recs.push('VPN hides your IP from peers but the VPN provider sees your transactions — Tor is stronger')
      break
    case 'rpc-provider':
      ipLeakage = 2.0 // the provider sees everything
      recs.push(`RPC provider ${input.rpcProviderName ?? ''} sees all your transactions, addresses, and IP. Run your own node.`.trim())
      break
    default:
      ipLeakage = 1.5
  }

  // Node type leakage: light clients leak more than full nodes
  // Full nodes receive all txs → hard to tell which are yours
  // Light clients only request txs for their addresses → obvious
  let nodeTypeLeakage = 0
  switch (input.nodeType) {
    case 'full-node':
      nodeTypeLeakage = 0.2 // minimal — you process everything
      break
    case 'light-client':
    case 'spv':
      nodeTypeLeakage = 1.5 // bloom filters leak address patterns
      recs.push('SPV/light clients leak address patterns via bloom filters. Full node provides maximum privacy.')
      break
    case 'electrum':
      nodeTypeLeakage = 2.0 // Electrum sends addresses directly to server
      recs.push('Electrum sends your addresses directly to the server. Use your own Electrum server or switch to a full node.')
      break
    default:
      nodeTypeLeakage = 1.0
  }

  // RPC correlation: CVE-2025-43968
  // Temporal correlation between wallet queries and tx broadcast
  let rpcCorrelation = 0
  if (input.usesRpcProvider) {
    rpcCorrelation = 1.5
    recs.push('RPC temporal correlation (CVE-2025-43968): timing between your balance queries and tx broadcast identifies you. Add random delays between queries.')
  }

  // Connection count: more connections = faster propagation = harder to pinpoint origin
  // But also more peers see your tx first
  let connectionFactor = 0
  if (input.connectionCount < 8) {
    connectionFactor = 0.5
    recs.push(`only ${input.connectionCount} connections — increase to 20+ to make propagation analysis harder`)
  }

  const totalLeakage = ipLeakage + nodeTypeLeakage + rpcCorrelation + connectionFactor

  return {
    ipLeakageRisk: Math.round(ipLeakage * 100) / 100,
    nodeTypeLeakage: Math.round(nodeTypeLeakage * 100) / 100,
    rpcCorrelation: Math.round(rpcCorrelation * 100) / 100,
    totalLeakage: Math.round(totalLeakage * 100) / 100,
    recommendations: recs,
  }
}
