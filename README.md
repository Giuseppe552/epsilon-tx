# ε-tx

[![CI](https://github.com/Giuseppe552/epsilon-tx/actions/workflows/ci.yml/badge.svg)](https://github.com/Giuseppe552/epsilon-tx/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests: 170](https://img.shields.io/badge/tests-170_passing-brightgreen)]()

Privacy analysis for cryptocurrency transactions. Computes information-theoretic bounds on what a blockchain observer can learn. Bitcoin, Monero, Lightning, cross-chain.

## Run it

```sh
git clone https://github.com/Giuseppe552/epsilon-tx.git && cd epsilon-tx
npm install && npm run build
```

```sh
etx analyse bc1q...                                        # Bitcoin address
etx analyse bc1q... --adversary law-enforcement             # who's watching?
etx coinjoin abc123...                                      # Boltzmann entropy
etx classify abc123...                                      # Chainalysis classification
etx ring abc123... --optimise                                # Monero optimal decoys
etx route 02abc... 03def...                                  # Lightning privacy vs cost
etx crosschain 0xabc...                                     # bridge linking risk
etx network --node-type electrum --broadcast direct --rpc    # network leakage
```

Every command outputs JSON to stdout. Pipe into `jq`, Python, anything.

## 8 attack surfaces

| # | Surface | Method | Reference |
|---|---|---|---|
| 1 | UTXO clustering | Co-spend graph + spectral sub-clustering (Fiedler vector) | Meiklejohn (2013), Fiedler (1973) |
| 2 | Wallet fingerprinting | 8 heuristics x 7 profiles, log-likelihood scoring | Ishaana Misra (2024) |
| 3 | Amount analysis | Shannon entropy, roundness detection, cross-tx correlation | Androulaki (2013) |
| 4 | Timing + network | Circadian timezone, DFT periodicity, KS test, IP/RPC leakage | Biryukov (2014), CVE-2025-43968 |
| 5 | CoinJoin | Boltzmann entropy, sub-tx decomposition, post-mix degradation | LaurentMT (2016), Maurer (2025) |
| 6 | Monero rings | Likelihood ratio analysis, inverse-OSPEAD optimal decoys | OSPEAD (2025), Moser (2018) |
| 7 | Lightning | Sender anonymity, timing leakage, balance probing, Pareto frontier | Romiti (2020) |
| 8 | Cross-chain | HTLC hash linking, timing/amount correlation, DP composition | Dwork (2006), P2C2T (2024) |

Evidence fused via Dempster-Shafer (1967). Adversary-weighted scoring.

<details>
<summary><strong>Adversary models</strong></summary>

The same address has different scores depending on who's watching.

| Model | Capabilities |
|---|---|
| `casual` | public block explorer |
| `exchange` | KYC + Chainalysis + ML classifiers |
| `law-enforcement` | subpoena + ISP data + full chain analysis |
| `nation-state` | backbone surveillance + Sybil + unlimited compute |

`etx analyse <addr> --adversary nation-state`

</details>

<details>
<summary><strong>Adversarial classification</strong></summary>

Surrogate model approximating what chain analysis firms detect. Shows which features drive the classification and how to change it.

`etx classify <txid>`

</details>

<details>
<summary><strong>Inverse-OSPEAD (novel)</strong></summary>

Instead of attacking Monero rings (OSPEAD), construct the optimal ring that maximises adversary uncertainty. Selects decoys at indistinguishability ages where P_spend/P_decoy = 1.

`etx ring <monero-hash> --optimise`

</details>

## Stack

```
packages/core/
  entropy/       Shannon, Dempster-Shafer, timing, amount, network, adversary models
  graph/         UTXO clustering (BFS + Tarjan + spectral Laplacian)
  fingerprint/   8-heuristic classifier, 10 recommendation types
  coinjoin/      Boltzmann entropy, subset sum, post-mix degradation
  monero/        ring analysis, inverse-OSPEAD, daemon RPC
  lightning/     routing privacy, Pareto frontier, mempool.space API
  crosschain/    bridge linking, DP composition, Wormhole/LayerZero API
  adversarial/   surrogate classifier, feature importance, evasion
  bitcoin/       Blockstream API (paginated, cached, rate-limited)

apps/cli/        7 commands, input validation, JSON piping
```

## Develop

```sh
npm install && npm run build
npm test           # 170 tests across 14 files
npm run cli -- analyse <address>
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Origin

Maths dissertation on Bitcoin cryptography. The dissertation asks "how does the cryptography work?" This tool asks "where does privacy actually break?"

## License

MIT
