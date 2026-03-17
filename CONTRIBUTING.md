# Contributing to ε-tx

## Reporting bugs

Open an issue with the command you ran, what happened, and what you expected.

## Pull requests

1. Fork the repo
2. Create a branch from `main`
3. `npm install && npm run build && npm test`
4. Make your changes
5. `npm run lint && npm test`
6. Open a PR

One feature per PR. Reference the relevant paper in code comments.

## Code rules

- TypeScript strict mode
- All privacy scores in **bits** with explicit units
- Mathematical properties must be tested (H ≥ 0, I ≥ 0, Σp = 1)
- Reference papers inline: `// Meiklejohn et al. (2013) — common-input-ownership`
- No external dependencies beyond vitest

## Architecture

```
packages/core/src/
  entropy/       information theory primitives + evidence fusion
  graph/         UTXO clustering + spectral analysis
  fingerprint/   wallet classifier + recommendations
  coinjoin/      Boltzmann entropy + post-mix degradation
  monero/        ring analysis + inverse-OSPEAD
  lightning/     routing privacy + Pareto frontier
  crosschain/    bridge linking + composition theorems
  adversarial/   surrogate classifier + evasion
  bitcoin/       Blockstream API client
  analyse.ts     unified privacy report

apps/cli/        7 commands: analyse, coinjoin, classify, ring, route, crosschain, network
```

## Security

If you find a vulnerability in the analysis that could be exploited, email contact@giuseppegiona.com.
