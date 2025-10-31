#!/usr/bin/env python3
"""
reorg_test_ethertester.py

Simulate a chain reorg against two contracts (SecureAuction and VulnAuction)
using web3.py + EthereumTester (evm_snapshot / evm_revert / evm_mine).

Requirements:
 - python3
 - web3 (pip install web3)
 - eth-tester (pip install eth-tester[py-evm])
 - eth-utils (pip install eth-utils)
 - Foundry installed (forge in PATH) because this script calls `forge build`
   to compile contracts and produce artifact JSON files in `out/`.

How it works:
 1. `forge build` is run to ensure artifacts are fresh.
 2. The script reads out/SecureAuction.json and out/VulnAuction.json for ABI+bytecode.
 3. Deploy both contracts with requiredConfirmations = 3.
 4. Use accounts: deployer, honest, malicious, miner (from EthereumTester)
 5. Commit phase (both bidders commit). Take snapshot AFTER commits (this is the fork point).
 6. Branch A: include both reveals -> mine confirmations -> finalize -> record winner/state.
 7. Revert to snapshot (this removes branch A reveals).
 8. Branch B: only honest reveals (or alternate reveals) -> mine confirmations -> finalize -> record winner/state.
 9. Compare winners for Secure vs Vuln to show divergence.

Note: this script assumes Foundry's compile output files are located at `out/<ContractName>.json`.
If your project layout differs, adjust the artifact paths accordingly.
"""

import json
import subprocess
import time
from pathlib import Path
from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider
from eth_utils import to_hex
from web3 import Web3, HTTPProvider
from web3.exceptions import ContractCustomError, ContractLogicError

PROJECT_ROOT = Path(__file__).resolve().parents[1]  # repo root (adjust if different)
OUT_DIR = PROJECT_ROOT / "out"

SECURE_ARTIFACT = Path("out/SecureAuction.sol/SecureAuction.json")
VULN_ARTIFACT   = Path("out/VulnAuction.sol/VulnAuction.json")

AUCTION_ID_VULN = 1
AUCTION_ID_SECURE = 2

REQUIRED_CONFIRMATIONS = 3  # will pass to constructor; tests also read from contract
GAS = 6_000_000

# Helper: run forge build
def forge_build():
    print("🔨 Running `forge build` to compile contracts...")
    proc = subprocess.run(["forge", "build"], cwd=PROJECT_ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        print(" forge build failed. stdout/stderr:")
        print(proc.stdout)
        print(proc.stderr)
        raise RuntimeError("forge build failed")
    print(" forge build finished.")

# Helper: load artifact
def load_artifact(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"Artifact not found: {path}\nRun `forge build` first.")

    with open(path, "r") as f:
        data = json.load(f)

    abi = data.get("abi") or data.get("output", {}).get("abi")

    # Extract bytecode string safely
    bytecode = None
    if isinstance(data.get("bytecode"), dict):
        bytecode = data["bytecode"].get("object")
    elif isinstance(data.get("bytecode"), str):
        bytecode = data["bytecode"]
    elif isinstance(data.get("deployedBytecode"), dict):
        bytecode = data["deployedBytecode"].get("object")
    elif isinstance(data.get("deployedBytecode"), str):
        bytecode = data["deployedBytecode"]
    elif isinstance(data.get("output"), dict):
        # fallback for nested output
        for file, contracts in data["output"].get("contracts", {}).items():
            for name, co in contracts.items():
                if name in path.stem:
                    bytecode = co.get("evm", {}).get("bytecode", {}).get("object")
                    abi = co.get("abi", abi)
                    break

    if not abi:
        raise ValueError(f"ABI not found in artifact {path}")
    if not bytecode:
        raise ValueError(f"Bytecode not found in artifact {path}")

    return abi, bytecode

# Helper: solidity keccak matching Solidity's keccak256(abi.encodePacked(...))
def solidity_keccak(types, values):
    return Web3.solidity_keccak(types, values)

def evm_snapshot(w3: Web3):
    resp = w3.provider.make_request("evm_snapshot", [])
    return resp["result"]

def evm_revert(w3: Web3, snap_id):
    resp = w3.provider.make_request("evm_revert", [snap_id])
    return resp["result"]

def evm_mine(w3: Web3, n=1):
    for _ in range(n):
        w3.provider.make_request("evm_mine", [])

def wait_for_tx_success(w3: Web3, tx_hash: bytes, name: str = "Transaction") -> dict:
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    if receipt.status == 0:
        # Attempt to decode the revert reason
        try:
            tx = w3.eth.get_transaction(tx_hash)
            # Find the contract that was called
            contract = w3.eth.contract(address=tx['to'])
            # NOTE: Decoding requires ABI, this might be simplified to checking the receipt for error data
        except Exception:
            pass # Keep silent if decoding fails

        # This will now fail the test if any reveal/finalize reverts
        raise RuntimeError(f"💥 {name} REVERTED (Status 0). Hash: {to_hex(tx_hash)}")
    return receipt

def safe_revert(w3, snapshot_id, name):
    print(f"Attempting evm_revert to snapshot {snapshot_id} for {name}...")
    res = w3.provider.make_request("evm_revert", [snapshot_id])
    if not res.get("result"):
        raise RuntimeError(
        f"❌ Critical Revert Failure: Snapshot {snapshot_id} for {name} is invalid. "
        "Reorg simulation is compromised. Check block mining sequence."
        )
    print(f"✅ Successfully reverted to snapshot {snapshot_id}.")
    return snapshot_id

# Short helper to print winner
def get_winner(contract, auction_id):
    try:
        winner = contract.functions.winnerOf(auction_id).call()
        return winner.lower()
    except ContractLogicError as e:
        # A ContractLogicError usually means the function reverted on-chain 
        # (e.g., trying to call winnerOf before finalize)
        return None
    except Exception as e:
        # Catch other unexpected errors
        print(f"⚠️ Error calling winnerOf({auction_id}) on {contract.address}: {e}")
        return None

def main():
    forge_build()

    # Load artifacts
    abi_secure, bytecode_secure = load_artifact(SECURE_ARTIFACT)
    abi_vuln, bytecode_vuln = load_artifact(VULN_ARTIFACT)
    print("Loaded artifacts.")

    # Setup web3 + eth-tester (py-evm)
    GANACHE_URL = 'http://127.0.0.1:8545'
    print(f"🔗 Connecting to Ganache at {GANACHE_URL}...")
    w3 = Web3(HTTPProvider(GANACHE_URL))

    if not w3.is_connected():
        raise ConnectionError(f"❌ Failed to connect to Ganache at {GANACHE_URL}. Please ensure Ganache is running.")

    accounts = w3.eth.accounts
    deployer = accounts[0]
    honest = accounts[1]
    malicious = accounts[2]
    miner = accounts[3]

    print(f"Accounts: deployer={deployer}, honest={honest}, malicious={malicious}, miner={miner}")

    # Fund accounts if necessary: with EthereumTester, accounts already have balance.

    # Construct contract factories
    Secure = w3.eth.contract(abi=abi_secure, bytecode=bytecode_secure)
    Vuln = w3.eth.contract(abi=abi_vuln, bytecode=bytecode_vuln)

    # Deploy both contracts (requiredConfirmations constructor arg)
    print(f"📦 Deploying SecureAuction with requiredConfirmations={REQUIRED_CONFIRMATIONS}...")
    tx_hash = Secure.constructor(REQUIRED_CONFIRMATIONS).transact({"from": deployer, "gas": GAS})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    secure_addr = tx_receipt.contractAddress
    secure = w3.eth.contract(address=secure_addr, abi=abi_secure)
    print(" SecureAuction at", secure_addr)

    print(f"📦 Deploying VulnAuction with requiredConfirmations={REQUIRED_CONFIRMATIONS}...")
    tx_hash = Vuln.constructor(REQUIRED_CONFIRMATIONS).transact({"from": deployer, "gas": GAS})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    vuln_addr = tx_receipt.contractAddress
    vuln = w3.eth.contract(address=vuln_addr, abi=abi_vuln)
    print(" VulnAuction at", vuln_addr)

    GLOBAL_BASELINE_SNAPSHOT = w3.provider.make_request("evm_snapshot", [])["result"]
    print(f"Global Baseline Snapshot taken (pre-commit state): {GLOBAL_BASELINE_SNAPSHOT}")

    # Precompute salts and commits
    salt_honest = Web3.keccak(text="salt_honest_42")
    salt_mal = Web3.keccak(text="salt_malicious_99")
    honest_bid = 100
    mal_bid = 150

    honest_commit = solidity_keccak(['uint256','bytes32'], [honest_bid, salt_honest])
    mal_commit = solidity_keccak(['uint256','bytes32'], [mal_bid, salt_mal])

    # -------------------------
    # Vulneable Auction Flow
    # -------------------------

    # Commit phase (on canonical chain prior to snapshot)

    # After loading artifacts, before commits
    contract_hash = vuln.functions.debugHash(honest_bid, salt_honest).call()
    python_hash = solidity_keccak(['uint256','bytes32'], [honest_bid, salt_honest])

    print(f"Python Hash: {to_hex(python_hash)}")
    print(f"Solidity Hash: {to_hex(contract_hash)}")
    assert python_hash == contract_hash, "Hash Mismatch - Commit/Reveal will fail!"

    # Commit to vulnerable contract 
    tx = vuln.functions.commit(AUCTION_ID_VULN, honest_commit).transact({"from": honest, "gas": GAS})
    wait_for_tx_success(w3, tx, "Vuln Honest Commit")
    tx = vuln.functions.commit(AUCTION_ID_VULN, mal_commit).transact({"from": malicious, "gas": GAS})
    wait_for_tx_success(w3, tx, "Vuln Malicious Commit")

    print("Commits included on-chain. Current block:", w3.eth.block_number)
    try:
        ok = eth_tester.revert(0)  # safe noop if no prior snapshot
        if not ok:
            print("No valid snapshot to revert — continuing.")
    except Exception:
        pass

    # Snapshot the chain now — this will be the fork point for the reorg.
    baseline_vuln_snapshot = w3.provider.make_request("evm_snapshot", [])["result"]  
    print(f"Baseline snapshot for Vulnerable Contract taken (pre-reveal fork): {baseline_vuln_snapshot}")

    # -------------------------
    # Branch A (include both reveals) => finalize (expected Bob/Malicious wins)
    # -------------------------
    print("\n=== Branch A (both reveal) ===")
    # Reveal on vuln
    print(f"Revealing for auction {AUCTION_ID_VULN} on VulnAuction at {vuln.address}")
    tx = vuln.functions.reveal(AUCTION_ID_VULN, honest_bid, salt_honest).transact({"from": honest, "gas": GAS})
    g = wait_for_tx_success(w3, tx, "Vuln Honest Reveal")
    honest_reveal_block_vulnerable = g.blockNumber
    tx = vuln.functions.reveal(AUCTION_ID_VULN, mal_bid, salt_mal).transact({"from": malicious, "gas": GAS})
    h = wait_for_tx_success(w3, tx, "Vuln Malicious Reveal")
    mal_reveal_block_vulnerable = h.blockNumber

    print("Reveals included on branch A. Blocks:", w3.eth.block_number)
    print(f"📘 Branch A summary:")
    print(f"   Honest reveal block (Vulnerable): {honest_reveal_block_vulnerable}")
    print(f"   Malicious reveal block (Vulnerable): {mal_reveal_block_vulnerable}")
    print(f"   Current head block: {w3.eth.block_number}")
    print("Branch A completed — ready to simulate reorg.")

    # Attempt premature finalize (should fail for secure due to confirmations; vuln may succeed)
    try:
        print("Attempting immediate finalize on VulnAuction (may succeed)...")
        tx = vuln.functions.finalizeWithCandidates(AUCTION_ID_VULN, [honest, malicious]).transact({"from": miner, "gas": GAS})
        wait_for_tx_success(w3, tx, "Vuln Finalize")
        vuln_winner_after_premature = get_winner(vuln, AUCTION_ID_VULN)
        print(" ✅ VulnAuction finalized immediately on Branch A, winner:", vuln_winner_after_premature)
    except Exception as e:
        print("❌ VulnAuction finalize reverted unexpectedly on Branch A:", str(e).splitlines()[0])

    # Save Branch A state (before reorg)
    winner_vuln_A = get_winner(vuln, AUCTION_ID_VULN)
    vuln_stateA = {
        "vuln_winner": winner_vuln_A,
        "block_number": w3.eth.block_number,
    }

    reorg_snapshot = safe_revert(w3, baseline_vuln_snapshot, "Vulnerable Auction")
    print(f"Successfully reverted to basline snapshot for vulnerable auction (id = {reorg_snapshot}) — starting Branch B (canonical chain)")

    print(f"  Branch B starting point:")
    print(f"   Current block after revert: {w3.eth.block_number}")


   # --- Honest-only reveal sequence ---
    print("Proceeding with honest-only reveal on branch B...")
    print(f"Revealing for auction {AUCTION_ID_VULN} on VulnAuction at {vuln.address}")
    tx = vuln.functions.reveal(AUCTION_ID_VULN, honest_bid, salt_honest).transact({"from": honest, "gas": GAS})
    wait_for_tx_success(w3, tx, "Vuln Honest Reveal")
    receipt = w3.eth.wait_for_transaction_receipt(tx)
    w3.provider.make_request("evm_mine", [])
    honest_reveal_block = receipt.blockNumber
    print(f" Honest reveal included at block {honest_reveal_block}")

    # Mine additional blocks to simulate confirmation period
    required_confirmations = 3
    for _ in range(required_confirmations):
        w3.provider.make_request("evm_mine", [])

    print(f" Advanced {required_confirmations} blocks to satisfy confirmation requirement.")

    # Finalize under canonical branch B
    print("Finalizing VulnAuction under branch B...")
    tx = vuln.functions.finalizeWithCandidates(
        AUCTION_ID_VULN, [honest, malicious]
    ).transact({"from": miner, "gas": GAS})
    wait_for_tx_success(w3, tx, "Vuln Finalize")

    winner_vuln_B = get_winner(vuln, AUCTION_ID_VULN)
    print(" ✅ VulnAuction finalized on branch B. Canonical winner:", winner_vuln_B)

    # Save state for later comparison
    vuln_stateB = {
        "vuln_winner": winner_vuln_B,
        "block_number": w3.eth.block_number,
    }

    print("\n\n--- Resetting to Global Baseline Before Secure Auction ---")
    # Revert to the snapshot taken after deployment but before ANY commits.
    safe_revert(w3, GLOBAL_BASELINE_SNAPSHOT, "Global Reset before SecureAuction")
    print(f"Current block after global reset: {w3.eth.block_number}")


    # -------------------------
    # Secure Auction Flow
    # -------------------------
    # Precompute salts and commits
    salt_honest = Web3.keccak(text="salt_honest_42")
    salt_mal = Web3.keccak(text="salt_malicious_99")
    honest_bid = 100
    mal_bid = 150

    honest_commit = solidity_keccak(['uint256','bytes32'], [honest_bid, salt_honest])
    mal_commit = solidity_keccak(['uint256','bytes32'], [mal_bid, salt_mal])

    # Commit phase (on canonical chain prior to snapshot)

    # After loading artifacts, before commits
    contract_hash_honest = secure.functions.debugHash(honest_bid, salt_honest).call()
    python_hash_honest = solidity_keccak(['uint256','bytes32'], [honest_bid, salt_honest])

    print(f"Python Hash: {to_hex(python_hash_honest)}")
    print(f"Solidity Hash: {to_hex(contract_hash_honest)}")
    assert python_hash_honest == contract_hash_honest, "Hash Mismatch - Commit/Reveal will fail!"

    print("\n--- Commit phase (both actors commit) ---")
    tx = secure.functions.commit(AUCTION_ID_SECURE, honest_commit).transact({"from": honest, "gas": GAS})
    wait_for_tx_success(w3, tx, "Secure Honest Commit")
    tx = secure.functions.commit(AUCTION_ID_SECURE, mal_commit).transact({"from": malicious, "gas": GAS})
    wait_for_tx_success(w3, tx, "Secure Malicious Commit")
    print("Commits included on-chain. Current block:", w3.eth.block_number)

    # Snapshot the chain now — this will be the fork point for the reorg.
    baseline_secure_snapshot = w3.provider.make_request("evm_snapshot", [])["result"]
    print(f"Baseline snapshot for secure contract taken (pre-reveal fork): {baseline_secure_snapshot}")

    # -------------------------
    # Branch A (include both reveals) => finalize (expected Bob/Malicious wins)
    # -------------------------
    print("\n=== Branch A (both reveal) ===")
    # Reveal on secure
    print(f"Revealing for auction {AUCTION_ID_SECURE} on SecureAuction at {secure.address}")
    tx = secure.functions.reveal(AUCTION_ID_SECURE, honest_bid, salt_honest).transact({"from": honest, "gas": GAS})
    honest_receipt = wait_for_tx_success(w3, tx, "Secure Honest Reveal")
    honest_reveal_block_secure = honest_receipt.blockNumber
    w3.provider.make_request("evm_mine", [])

    tx = secure.functions.reveal(AUCTION_ID_SECURE, mal_bid, salt_mal).transact({"from": malicious, "gas": GAS})
    malicious_receipt = wait_for_tx_success(w3, tx, "Secure Malicious Reveal")
    mal_reveal_block_secure = malicious_receipt.blockNumber
    w3.provider.make_request("evm_mine", [])

    print("Reveals included on branch A. Blocks:", w3.eth.block_number)
    print(f"  Branch A summary:")
    print(f"   Honest reveal block (Secure): {honest_reveal_block_secure}")
    print(f"   Malicious reveal block (Secure): {mal_reveal_block_secure}")
    print(f"   Current head block: {w3.eth.block_number}")
    print("Branch A completed — ready to simulate reorg.")


    print(f" Confirming reveal blocks before finalize:")
    for addr in [honest, malicious]:
        rb = secure.functions.revealBlock(AUCTION_ID_SECURE, addr).call()
        print(f"   {addr} revealBlock={rb}, current block={w3.eth.block_number}")

    # Try premature finalize (should revert due to confirmations)
    tx_finalize = secure.functions.finalizeWithCandidates(AUCTION_ID_SECURE, [honest, malicious]).transact({"from": miner, "gas": GAS})
    try:
        wait_for_tx_success(w3, tx_finalize, "Secure Finalize")
        secure_winner_after_premature = get_winner(secure, AUCTION_ID_SECURE)
        print(" ⚠️ SecureAuction finalized prematurely (unexpected). Winner:", secure_winner_after_premature)
    except RuntimeError as e:
        print(" ✅ SecureAuction rejected premature finalize (expected):", str(e).splitlines()[0])
    except TimeoutError as e:
        print(" ✅ SecureAuction rejected premature finalize (expected - Timeout):", str(e).splitlines()[0])

    # Save Branch A state (before reorg)
    winner_secure_A = get_winner(secure, AUCTION_ID_SECURE)
    secure_stateA = {
        "secure_winner": winner_secure_A,
        "block_number": w3.eth.block_number,
    }

    # --- Branch B (after reorg): simulate alternate (honest-only) reveal ---
    print("\n=== Branch B (honest-only path, SecureAuction) ===")
    # --- Honest-only reveal sequence ---
    reorg_secure_snapshot = safe_revert(w3, baseline_secure_snapshot, "Secure Auction (Branch A Cleanup)")
    print(f"Successfully reverted to basline snapshot for secure auction (id = {reorg_secure_snapshot}) — starting Branch B (canonical chain)")
    print(f"  Branch B starting point:")
    print(f"   Current block after revert: {w3.eth.block_number}")

    print("Proceeding with honest-only reveal on branch B...")
    print(f"Revealing for auction {AUCTION_ID_SECURE} on SecureAuction at {secure.address}")
    tx = secure.functions.reveal(AUCTION_ID_SECURE, honest_bid, salt_honest).transact({"from": honest, "gas": GAS})
    receipt = wait_for_tx_success(w3, tx, "Secure Honest Reveal")
    honest_reveal_block = receipt.blockNumber
    print(f" Honest reveal included at block {honest_reveal_block}")

    # Mine additional blocks to satisfy confirmation requirement
    required_confirmations = 3
    for _ in range(required_confirmations):
        w3.provider.make_request("evm_mine", [])

    print(f" Advanced {required_confirmations} blocks to satisfy confirmation requirement.")

    # Finalize canonical branch B
    print("Finalizing SecureAuction under branch B...")
    tx = secure.functions.finalizeWithCandidates(
        AUCTION_ID_SECURE, [honest, malicious]
    ).transact({"from": miner, "gas": GAS})
    wait_for_tx_success(w3, tx, "Secure Finalize")

    winner_secure_B = get_winner(secure, AUCTION_ID_SECURE)
    print(" ✅ SecureAuction finalized on branch B. Canonical winner:", winner_secure_B)

    # Save state for later comparison
    secure_stateB = {
        "secure_winner": winner_secure_B,
        "block_number": w3.eth.block_number,
    }

    # -------------------------
    # Compare outcomes
    # -------------------------

    # =============================
    # === Save Results for Comparison ===
    # =============================

    # Branch A (pre-reorg) recorded states
    vuln_stateA = {
        "vuln_winner": winner_vuln_A,  # from vulnerable branch A finalize
        "block_number": w3.eth.block_number,
    }

    secure_stateA = {
        "secure_winner": winner_secure_A,  # from secure branch A finalize
        "block_number": w3.eth.block_number,
    }

    # Branch B (post-reorg canonical chain) recorded states
    vuln_stateB = {
        "vuln_winner": winner_vuln_B,  # from vulnerable branch B finalize
        "block_number": w3.eth.block_number,
    }

    secure_stateB = {
        "secure_winner": winner_secure_B,  # from secure branch B finalize
        "block_number": w3.eth.block_number,
    }

    # Optional quick sanity check before summary
    print("\n📊 State summary collected:")
    print(f"  VulnAuction A winner={vuln_stateA['vuln_winner']}  B winner={vuln_stateB['vuln_winner']}")
    print(f"  SecureAuction A winner={secure_stateA['secure_winner']}  B winner={secure_stateB['secure_winner']}")


    print("\n=== Comparison Summary ===")

    secure_winner_A = (secure_stateA.get("secure_winner") or "").lower()
    vuln_winner_A   = (vuln_stateA.get("vuln_winner") or "").lower()
    secure_winner_B = (secure_stateB.get("secure_winner") or "").lower()
    vuln_winner_B   = (vuln_stateB.get("vuln_winner") or "").lower()

    print("Branch A (before reorg):")
    print(f" - VulnAuction winner:  {vuln_stateA.get('vuln_winner')}")
    print(f" - SecureAuction winner: {secure_stateA.get('secure_winner')}")
    print("\nBranch B (after reorg):")
    print(f" - VulnAuction winner:  {vuln_stateB.get('vuln_winner')}")
    print(f" - SecureAuction winner: {secure_stateB.get('secure_winner')}")

    zero_addr = "0x0000000000000000000000000000000000000000"

    # 1) Vulnerable contract must be able to finalize on A immediately (malicious wins on A)
    assert vuln_stateA["vuln_winner"] is not None, "VulnAuction did not finalize on Branch A (expected vulnerability)."
    assert vuln_stateA["vuln_winner"].lower() == malicious.lower(), "VulnAuction Branch A winner should be malicious."

    # 2) Secure contract must NOT finalize on A (it requires confirmations)
    assert secure_stateA["secure_winner"] in (None, zero_addr), "SecureAuction unexpectedly finalized on Branch A."

    # 3) Both contracts must finalize to honest on canonical branch B
    assert vuln_stateB["vuln_winner"].lower() == honest.lower(), "VulnAuction Branch B winner must be honest."
    assert secure_stateB["secure_winner"].lower() == honest.lower(), "SecureAuction Branch B winner must be honest."

    # 4) Divergence observed: A winners differ from B winners (malicious -> honest)
    assert vuln_stateA["vuln_winner"].lower() != vuln_stateB["vuln_winner"].lower(), "VulnAuction should diverge (A != B)."
    assert (secure_stateA["secure_winner"] in (None, zero_addr)) and (secure_stateB["secure_winner"].lower() == honest.lower()), "SecureAuction should not finalize on A but finalize to honest on B."

    # ---- Optional: Debug prints for clarity ----
    print("\n🔎 Debug — Secure winners: A =", secure_winner_A, ", B =", secure_winner_B)
    print("🔎 Debug — Vuln winners:   A =", vuln_winner_A, ", B =", vuln_winner_B)

    # ---- End summary ----
    print("\nSimulation completed successfully ✅")
    print("Tip: re-run with altered branch order or reorg timing to observe different outcomes.")

if __name__ == "__main__":
    main()
