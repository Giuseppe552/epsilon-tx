# ε-tx

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests: 146](https://img.shields.io/badge/tests-146_passing-brightgreen)]()

Privacy analysis for cryptocurrency transactions. Computes information-theoretic bounds on what a blockchain observer can learn. Bitcoin, Monero, Lightning.

```
$ etx analyse 3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5

  privacy score: 3.16 bits (medium)
  anonymity set: ~115

  breakdown:
    timing                  2.16 bits  ██████
    wallet-fingerprint      0.70 bits  ██
    amount-analysis         0.29 bits  █
```

## Run it

```sh
git clone https://github.com/Giuseppe552/epsilon-tx.git && cd epsilon-tx
npm install && npm run build
npm run cli -- analyse <bitcoin-address>
npm run cli -- analyse <bitcoin-address> --expand 1      # follow co-spend graph 1 hop
npm run cli -- analyse <bitcoin-address> --json | jq .recommendations
```

## What it analyses

| Attack surface | Method | Reference |
|---|---|---|
| Wallet clustering | Co-spend graph + BFS + Tarjan bridge detection | Meiklejohn et al. (2013) |
| Sub-cluster detection | Spectral analysis via normalized Laplacian eigendecomposition | Fiedler (1973), Von Luxburg (2007) |
| Wallet fingerprinting | 7 profiles × 8 heuristics (BIP-69, script types, nLockTime, fee patterns) | Ishaana Misra (2024) |
| Change detection | Script-type match + round-payment heuristic | Bitcoin Wiki Privacy |
| Amount entropy | Shannon entropy of output distributions, CoinJoin scoring | Shannon (1948) |
| Amount correlation | Cross-tx near-match detection (±1% tolerance) | — |
| Timing analysis | Asymmetric circadian timezone model + autocorrelation + DFT + KS test | Biryukov (2014), Massey (1951) |
| Evidence fusion | Dempster-Shafer combination rule | Dempster (1967), Shafer (1976) |
| Graph expansion | Recursive co-spend address following (configurable depth) | Meiklejohn (2013) §3 |
| CoinJoin entropy | Boltzmann score + sub-transaction decomposition + link probability matrix | LaurentMT (2016), Maurer (2025) |
| Post-mix degradation | Consolidation, toxic change, address reuse, timing correlation | Maurer (2025) §5 |
| Monero ring analysis | Per-member probability via spend/decoy likelihood ratio, ring entropy | OSPEAD (2025), Möser (2018) |
| Optimal decoy construction | Inverse-OSPEAD: maximise adversary entropy at indistinguishability ages | Novel contribution |
| Lightning routing | Sender anonymity, timing leakage, balance probe resistance, Pareto frontier | Romiti (2020), Herrera-Joancomartí (2019) |
| Adversarial classification | Surrogate classifier, feature importance, evasion perturbations | Alarab (2024) |
| Recommendations | 10 actionable fixes with estimated bit savings per fix | Bitcoin Wiki Privacy |

All scores are in **bits**. Lower = more private. The breakdown shows which surface leaks the most.

<details>
<summary><strong>How the score works</strong></summary>

Each heuristic produces a mass function over Θ = {EXPOSED, PRIVATE} with a reliability weight from published accuracy data. Dempster's combination rule fuses all sources, properly handling conflicting evidence (e.g., clustering says exposed, timing says private).

The unified score = Bel(EXPOSED) × Σ max_leakage_per_source.

This is tighter than basic composition (ε_total ≤ Σ ε_i) because conflicting evidence reduces rather than increases the total.

</details>

<details>
<summary><strong>Spectral clustering</strong></summary>

Beyond BFS connected components, the spectral analyser computes the normalized graph Laplacian and extracts eigenvalues via power iteration with deflation. The Fiedler vector (λ₂) partitions the cluster at its weakest point. The eigengap heuristic estimates the number of sub-clusters.

This reveals sub-wallets, mixing outputs, and temporary addresses within a single co-spend cluster.

</details>

## Stack

```
packages/core/
  entropy/       Shannon, conditional, mutual information, timing, amount, Dempster-Shafer
  graph/         UTXO co-spend graph, BFS clustering, Tarjan bridges, spectral analysis
  fingerprint/   8-heuristic wallet classifier (7 profiles), recommendations
  coinjoin/      Boltzmann entropy, sub-transaction matching, post-mix degradation
  monero/        Ring analysis, inverse-OSPEAD optimal decoy construction
  lightning/     Sender anonymity, timing leakage, balance probing, Pareto frontier
  adversarial/   Surrogate classifier, feature importance, evasion perturbations
  bitcoin/       Blockstream API client (rate-limited, cached, expandable)
  analyse.ts     Unified privacy report with Dempster-Shafer fusion

apps/cli/
  index.ts       etx analyse <address> [--expand N] [--json]
```

## Develop

```sh
npm install
npm run build
npm test          # 146 tests across 12 files
npm run cli -- analyse <address>
```

## Origin

Started as a maths dissertation on Bitcoin's cryptography (secp256k1, ECDSA, SHA-256). The dissertation asks "how does the cryptography work?" This tool asks "given that the crypto is perfect, where does privacy actually break?"

## License

MIT
