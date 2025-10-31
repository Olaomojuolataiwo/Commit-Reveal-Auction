# Secure Auction Research Series

A comprehensive series of security-driven tests exploring **commit–reveal auction mechanisms**, common exploit vectors, and defensive design improvements. A Research series exploring commit–reveal sealed-bid auctions, adversarial exploitation and hardened design on Ethereum.

This repository contains all five stages of the research project, including Solidity contract deployments, exploit simulations, and cross-language test orchestration (Foundry + Python). Each stage builds on the previous, progressively revealing failure modes and defensive architecture.

**Project Summary**

🎯 Problem solved: “Front-running, non-reveal griefing and oracle manipulation threaten sealed-bid auctions.”

🛠 Solution: “Built a full on-chain & local test suite demonstrating vulnerabilities and hardening patterns.”

📈 Skills demonstrated: “Solidity, Foundry, Python automation, EVM orchestration, security testing, MEV bundles”.
---

## 🧩 Overview

| Stage | Focus Area | Description |
|-------|-------------|--------------|
| [Stage 1 – Baseline & Griefing (Impersonation)](https://github.com/Olaomojuolataiwo/Commit-Reveal-Auction/tree/main/docs/stage1) | Foundation | Core auction manager, ERC20-backed sealed-bid auctions, impersonation and griefing attacks. |
| [Stage 2 – Adversarial Scenarios (Front-Running, Replay, Late Reveal)](https://github.com/Olaomojuolataiwo/Commit-Reveal-Auction/tree/main/docs/stage2) | Transaction Layer | Valid adversarial front-runs, replay relayers, and late reveals. |
| [Stage 3 – Oracle / MEV Simulation](https://github.com/Olaomojuolataiwo/Commit-Reveal-Auction/tree/main/docs/stage3) | Oracle Layer | Real-time price distortion attack using a mock oracle and Flashbots bundles (falling back to sequential broadcast). |
| [Stage 4 – Transaction-Layer Denial Tests](https://github.com/Olaomojuolataiwo/Commit-Reveal-Auction/tree/main/docs/stage4) | Gas & Refund Logic | Griefing-style denial-of-service exploits (revert-on-refund, gas burn, reentrancy, and conditional failures). |
| [Stage 5 – Time Bandit & Reorganisation Tests](https://github.com/Olaomojuolataiwo/Commit-Reveal-Auction/tree/main/docs/stage5) | Consensus Layer | Multi-block reorganisation and timestamp manipulation tests proving auction determinism and replay protection. |

---

## 🧠 Research Objective

The **Secure Auction Research Series** investigates layered attack vectors against commit–reveal style auctions across transaction, execution, and consensus layers.  
Each stage validates that the **hardened variants** maintain integrity under stress and adversarial conditions — including chain reorgs, gas starvation, malicious refunds, and oracle front-running.

---

## 🧪 Components

| Category | Description |
|-----------|--------------|
| **Contracts** | Located in `/src/contracts` — includes AuctionManager, SealedBidAuction, and variants (Vulnerable, Hardened). |
| **Scripts** | Foundry deployment and attack simulation scripts (`/scripts`). |
| **Python** | Cross-chain and orchestration scripts for live EVM tests (`/python`). |
| **Docs** | Per-stage `README.md` and `deployment.md` records under `/docs`. |
| **Logs** | Raw test logs, reports, and JSON traces under `/logs`. |
| **Shell** | shell orchestrators and helpers that wait for block windows, call `cast`, and chain steps (e.g., `run_reveal_finalize.sh`, `run_all_scenarios.sh`).|
 
---

## ⚙️ How to Verify on Etherscan

Each stage’s `deployment.md` includes:
- Contract addresses (Sepolia network, Chain ID 11155111)
- Transaction hashes for deploy, commit, reveal, and finalize phases

To verify:
1. Visit [https://sepolia.etherscan.io](https://sepolia.etherscan.io)
2. Paste any listed **contract address** or **transaction hash**
3. Confirm bytecode matches source and check events for commit/reveal/finalize cycles.

---

## 🧾 Directory Map

Commit-Reveal-Auction/
│
├── contracts/ # Solidity contracts (previously src/): AuctionManager, SealedBidAuction, variants, MockERC20
├── scripts/ # Foundry scripts: deployment & scenario scripts (s.sol)
├── python/ # Python orchestrators and simulation scripts (auctionwithspot.py, Orchestrator.py, reorg_test_ethertester.py)
├── shell/ # Shell wrappers & orchestration helpers (run_all_scenarios.sh, run_reveal_finalize.sh, utils)
├── docs/ # Per-stage docs (Stage1..Stage5): README.md + deployment.md with canonical txs
├── broadcast/ # Foundry broadcast output JSONs (run-latest.json) — authoritative tx lists for each script run
├── artifacts/ # Build artifacts (ABI, bytecode) and recorded receipts from local tests
├── cache/ # Foundry / local cache including sensitive broadcast cache — handle securely
├── reports/ # JSON reports & aggregated summaries (per-run / summary_report_.json)
├── logs/ # Archived logs: deploy_.log, commit_.log, reveal_.log, finalize_*.log
├── lib/ # Third-party libraries / local packages used in tests (if present)
├── .github/ # Optional: CI / workflow definitions (if present)
├── tests/ # Foundry unit tests (.t.sol)
├── README.md # (this file — root summary)
└── .env.example # Example environment variables (RPC, private keys placeholders)

---

## 📚 Summary

The **Secure Auction Research Series** demonstrates that commit–reveal mechanisms can be hardened against:
- **Front-running**
- **Replay attacks**
- **Oracle manipulation**
- **Gas griefing / refund reverts**
- **Reentrancy & reorgs**

This repository consolidates all final test results and on-chain proofs across multiple layers — providing a reproducible framework for secure sealed-bid auctions.

---
**Author:** Olaomoju Ola-Taiwo  
**Network:** Sepolia (Chain ID 11155111)  
**Repository:** [Commit-Reveal-Auction](https://github.com/Olaomojuolataiwo/Commit-Reveal-Auction)

