#!/usr/bin/env python3
"""
auctionwithspot.py
Single orchestrator script to:
 - deploy auctions (via DeployWithSpots forge script)
 - distribute mock token to actors
 - perform commit / reveal flow with attacker sandwich via Flashbots (optional)
 - finalize auctions and run assertions
 - save run-record.json for analysis

Environment variables (required):
 - RPC_URL
 - PRIVATE_KEY_DEPLOYER, PRIVATE_KEY_ALICE, PRIVATE_KEY_ATTACKER  (hex private keys, 0x...)
 - FORGE_CMD (optional, default "forge")
 - MOCK_ERC20_ADDRESS (0x0 for ETH auctions)
 - PRICE_ORACLE_ADDRESS (mock with setPrice)
 - FLASHBOTS_ENABLED (true/false)
 - FLASHBOTS_SIGNER_PRIVKEY (if FLASHBOTS_ENABLED)
 - CHAIN_ID (optional, default 11155111)
 - AUCTION_MANAGER_ADDR (optional) - if you prefer manager to deploy auctions instead

Run:
  source venv/Scripts/activate
  python auctionwithspot.py
"""

import os, json, time, subprocess
from dotenv import load_dotenv
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
from eth_account import Account
from hexbytes import HexBytes
from flashbot_helper import FlashbotHelper  # your file from earlier
from pathlib import Path

load_dotenv()

# ----------------------
# Config from env
# ----------------------
RPC_URL = os.environ["RPC_URL"]
FORGE_CMD = os.environ.get("FORGE_CMD", "forge")
CHAIN_ID = int(os.environ.get("CHAIN_ID", "11155111"))

PRIVATE_KEY_DEPLOYER = os.environ["PRIVATE_KEY_DEPLOYER"]
PRIVATE_KEY_ALICE = os.environ["PRIVATE_KEY_ALICE"]
PRIVATE_KEY_ATTACKER = os.environ["PRIVATE_KEY_ATTACKER"]

MOCK_ERC20 = os.environ.get("MOCK_ERC20_ADDRESS", "0x0000000000000000000000000000000000000000")
PRICE_ORACLE_ADDR = os.environ.get("PRICE_ORACLE_ADDRESS", "")
AUCTION_MANAGER_ADDR = os.environ.get("AUCTION_MANAGER_ADDR", "")

FLASHBOTS_ENABLED = os.environ.get("FLASHBOTS_ENABLED", "false").lower() in ("1","true","yes")
FLASHBOTS_SIGNER = os.environ.get("FLASHBOTS_SIGNER_PRIVKEY", None)
FLASHBOTS_RELAY = os.environ.get("FLASHBOTS_RELAY", "https://relay-sepolia.flashbots.net")

# Minimal ABIs (expand if you need more functions)
AUCTION_ABI = [
    {"inputs":[{"internalType":"bytes32","name":"_commitment","type":"bytes32"}],"name":"commit","outputs":[],"stateMutability":"payable","type":"function"},
    {"inputs":[{"internalType":"uint256","name":"amount","type":"uint256"},{"internalType":"bytes32","name":"nonce","type":"bytes32"}],"name":"reveal","outputs":[],"stateMutability":"payable","type":"function"},
    {"inputs":[],"name":"finalize","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"commitments","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},
    {"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"revealedBid","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
    {"inputs":[],"name":"winner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},
    {"inputs":[],"name":"winningBid","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
]

PRICE_ORACLE_ABI = [
    {"inputs":[{"internalType":"uint256","name":"_price","type":"uint256"}],"name":"setPrice","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[],"name":"getPrice","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}
]

ERC20_ABI = [
    {"constant":False,"inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"},
    {"constant":False,"inputs":[{"name":"spender","type":"address"},{"name":"value","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"type":"function"},
    {"constant":True,"inputs":[{"name":"who","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"type":"function"},
    {"constant":False,"inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}],"name":"mint","outputs":[],"type":"function"}
]

# ----------------------
# web3 + accounts
# ----------------------
w3 = Web3(HTTPProvider(RPC_URL))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)

deployer = Account.from_key(PRIVATE_KEY_DEPLOYER)
alice = Account.from_key(PRIVATE_KEY_ALICE)
attacker = Account.from_key(PRIVATE_KEY_ATTACKER)

print("Deployer:", deployer.address)
print("Alice:", alice.address)
print("Attacker:", attacker.address)

fb = None
if FLASHBOTS_ENABLED:
    if not FLASHBOTS_SIGNER:
        raise SystemExit("FLASHBOTS_ENABLED=true but FLASHBOTS_SIGNER_PRIVKEY not set")
    fb = FlashbotHelper(rpc_url=RPC_URL, relay_url=FLASHBOTS_RELAY, searcher_privkey=FLASHBOTS_SIGNER)

# ----------------------
# Helpers
# ----------------------
def run_forge_script_and_extract_addresses(script_name="DeployWithSpot"):
    """
    Run a forge script that deploys auctions and returns (vuln, hard) by return values.
    We run: forge script script/DeployWithSpots.s.sol:DeployWithSpots --rpc-url ...
    Parse stdout for console.log lines or fallback to broadcast JSON.
    """
    cmd = f"{FORGE_CMD} script script/{script_name}.s.sol:{script_name} --rpc-url {RPC_URL} --broadcast"
    print("Running script command:", cmd)
    proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, encoding="utf-8", errors="replace", env={**os.environ, "PYTHONIOENCODING":"utf-8"})
    out = proc.stdout or ""
    print(out)

    if proc.returncode != 0:
        raise SystemExit(f"Forge script failed (exit {proc.returncode}). See output above.")

    # Try parse console log (pattern: "Vulnerable Auction deployed at:" or "VULN_AUCTION_ADDR")
    vuln_addr, hard_addr = None, None
    for line in out.splitlines():
        if "Vulnerable Auction deployed at" in line or "VULN_AUCTION_ADDR" in line:
            vuln_addr = line.split()[-1].strip()
        if "Hardened Auction deployed at" in line or "HARDENED_AUCTION_ADDR" in line:
            hard_addr = line.split()[-1].strip()

    # Fallback to broadcast JSON
    if not vuln_addr or not hard_addr:
        import glob
        for f in glob.glob("broadcast/**/*run-latest.json", recursive=True) + glob.glob("broadcast/*/*/run-latest.json"):
            try:
                data = json.load(open(f))
            except Exception:
                continue
            for tx in data.get("transactions", []):
                if tx.get("contractAddress"):
                    c = tx["contractAddress"]
                    if not vuln_addr:
                        vuln_addr = c
                    elif not hard_addr and c != vuln_addr:
                        hard_addr = c
            if vuln_addr and hard_addr:
                break

    if not vuln_addr or not hard_addr:
        raise SystemExit("Could not parse deployed addresses from forge output or broadcast JSON")

    return Web3.to_checksum_address(vuln_addr), Web3.to_checksum_address(hard_addr)


def build_and_sign_tx(function_call, from_account, value=0, gas=None):
    """
    Build, sign and return raw tx bytes (signed).
    function_call: Contract.function(...).buildTransaction(...) already prepared or function object + args passed in.
    """
    tx = function_call.build_transaction({
        "from": from_account.address,
        "nonce": w3.eth.get_transaction_count(from_account.address),
        "gasPrice": w3.eth.gas_price,
        "value": value,
        "chainId": CHAIN_ID
    })
    if gas:
        tx["gas"] = gas
    # Estimate gas if missing
    if "gas" not in tx:
        try:
            tx["gas"] = w3.eth.estimate_gas(tx)
        except Exception:
            tx["gas"] = 500_000
    signed = from_account.sign_transaction(tx)
    return signed

def send_raw_and_wait(signed_tx):
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash)

def distribute_token(erc20, to_address, amount, from_account=deployer):
    tx = erc20.functions.transfer(to_address, amount).build_transaction({
        "from": from_account.address,
        "nonce": w3.eth.get_transaction_count(from_account.address),
        "gasPrice": w3.eth.gas_price,
        "chainId": CHAIN_ID
    })
    signed = from_account.sign_transaction(tx)
    return send_raw_and_wait(signed)

def approve_if_token(token_contract, owner_account, spender, amount):
    tx = token_contract.functions.approve(spender, amount).build_transaction({
        "from": owner_account.address,
        "nonce": w3.eth.get_transaction_count(owner_account.address),
        "gasPrice": w3.eth.gas_price,
        "chainId": CHAIN_ID
    })
    signed = owner_account.sign_transaction(tx)
    return send_raw_and_wait(signed)

# ----------------------
# Core scenario flow
# ----------------------
def main():
    # 1) Deploy auctions
    print("--- Deploy auctions via deploy script ---")
    vuln_addr, hard_addr = run_forge_script_and_extract_addresses("DeployWithSpot")
    print("VULN:", vuln_addr, "HARD:", hard_addr)

    vuln = w3.eth.contract(address=vuln_addr, abi=AUCTION_ABI)
    hard = w3.eth.contract(address=hard_addr, abi=AUCTION_ABI)
    price_oracle = None
    if PRICE_ORACLE_ADDR:
        price_oracle = w3.eth.contract(address=PRICE_ORACLE_ADDR, abi=PRICE_ORACLE_ABI)

    # 2) Optional: distribute mock token (if token-mode)
    is_token = (MOCK_ERC20 != "0x0000000000000000000000000000000000000000")
    erc20 = None
    if is_token:
        erc20 = w3.eth.contract(address=MOCK_ERC20, abi=ERC20_ABI)
        amount = w3.to_wei(10, "ether")
        print("Distributing token to Alice and Attacker...")
        distribute_token(erc20, alice.address, amount)
        distribute_token(erc20, attacker.address, amount)

    # 3) Alice commit
    print("Preparing Alice commit...")
    bid_amount = w3.to_wei(1, "ether")  # change as desired
    nonce = Web3.keccak(text="secret-nonce-1")  # deterministic for test - bytes32
    commit_hash = Web3.solidity_keccak(["uint256","address","bytes32"], [bid_amount, alice.address, nonce])
    deposit_amount = w3.to_wei(1, "ether")  # must match deployed contract's depositAmount
    # If token auction: approve auction contract to pull deposit from Alice
    if is_token:
        print("Alice approve deposit to vuln auction")
        approve_if_token(erc20, alice, vuln_addr, deposit_amount)
        print("Alice approve deposit to hardened auction")
        approve_if_token(erc20, alice, hard_addr, deposit_amount)
    # Commit to vulnerable auction
    signed_commit_vuln = build_and_sign_tx(vuln.functions.commit(commit_hash), alice, value=deposit_amount if not is_token else 0)
    print("Sending Alice commit to vulnerable auction...")
    send_raw_and_wait(signed_commit_vuln)
    print("Alice committed to vulnerable auction")

    # Commit to hardened auction as well (same process) - to compare later
    if is_token:
        # ensure approval already done
        pass
    signed_commit_hard = build_and_sign_tx(hard.functions.commit(commit_hash), alice, value=deposit_amount if not is_token else 0)
    send_raw_and_wait(signed_commit_hard)
    print("Alice committed to hardened auction")

    # 4) Attacker will sandwich the reveal: prepare front-run (set price high), victim reveal, back-run (set price back)
    # Build signed transactions but do NOT broadcast them individually if using flashbots.
    PHIGH = w3.to_wei(4000, "ether") if price_oracle else None  # example high price
    P0 = None
    if price_oracle:
        P0 = price_oracle.functions.getPrice().call()
        print("Current oracle price:", P0)
        # FRONT tx: set price high
        front_signed = build_and_sign_tx(price_oracle.functions.setPrice(PHIGH), attacker)
        # REVEAL tx by alice (must be signed by alice)
        # For token auction, ensure alice approved the auction for bid amount (reveal will transferFrom)
        if is_token:
            # approve bid transfer for reveal
            approve_if_token(erc20, alice, vuln_addr, bid_amount)
            approve_if_token(erc20, alice, hard_addr, bid_amount)
            reveal_signed = build_and_sign_tx(vuln.functions.reveal(bid_amount, nonce), alice, value=0)
        else:
            reveal_signed = build_and_sign_tx(vuln.functions.reveal(bid_amount, nonce), alice, value=bid_amount)
        # BACK tx: restore price
        back_signed = build_and_sign_tx(price_oracle.functions.setPrice(P0), attacker)
    else:
        # If no price oracle, we can still simulate an attacker that does nothing or manipulates another contract
        print("No price oracle configured; skipping price-manipulation sandwich. Will still perform reveal.")
        if is_token:
            approve_if_token(erc20, alice, vuln_addr, bid_amount)
            reveal_signed = build_and_sign_tx(vuln.functions.reveal(bid_amount, nonce), alice, value=0)
        else:
            reveal_signed = build_and_sign_tx(vuln.functions.reveal(bid_amount, nonce), alice, value=bid_amount)
        front_signed, back_signed = None, None

    # 5) Send bundle via Flashbots or broadcast sequentially
    print("Submitting sandwich...")
    if FLASHBOTS_ENABLED and fb:
        # Pack hex strings
        bund = []
        if front_signed:
            bund.append(front_signed.raw_transaction.hex())
        bund.append(reveal_signed.raw_transaction.hex())
        if back_signed:
            bund.append(back_signed.raw_transaction.hex())

        # send_bundle expects raw signed tx hexes; adjust FlashbotHelper.send_bundle signature if needed
        fb.send_bundle(*bund)
        print("Bundle submitted via Flashbots (check inclusion logs).")
    else:
        # If not using flashbots: broadcast front, reveal, back sequentially (danger of being frontrun in real network)
        if front_signed:
            send_raw_and_wait(front_signed)
        send_raw_and_wait(reveal_signed)
        if back_signed:
            send_raw_and_wait(back_signed)
        print("Sent front/reveal/back sequentially (not using Flashbots)")

    # 6) Also reveal on hardened auction (to keep states comparable)
    print("Reveal on hardened auction (same preimage)...")
    if is_token:
        reveal_hard_signed = build_and_sign_tx(hard.functions.reveal(bid_amount, nonce), alice, value=0)
    else:
        reveal_hard_signed = build_and_sign_tx(hard.functions.reveal(bid_amount, nonce), alice, value=bid_amount)
    send_raw_and_wait(reveal_hard_signed)
    print("Revealed on hardened auction")

    # 7) Wait until reveal window closes (simple sleep; better: poll block.number)
    print("Waiting reveal window to close...")
    time.sleep(12)  # adjust depending on commit/reveal windows used in deploy script

    # 8) Finalize both auctions (deployer does this)
    print("Finalizing vulnerable auction...")
    finalize_vuln = build_and_sign_tx(vuln.functions.finalize(), deployer)
    send_raw_and_wait(finalize_vuln)
    print("Finalizing hardened auction...")
    finalize_hard = build_and_sign_tx(hard.functions.finalize(), deployer)
    send_raw_and_wait(finalize_hard)

    # 9) Assertions & snapshots
    print("Running assertions...")
    run_record = {
        "vuln": vuln_addr,
        "hard": hard_addr,
        "alice": alice.address,
        "attacker": attacker.address,
        "bid_amount": str(bid_amount),
        "nonce": nonce.hex()
    }

    # Commit privacy: ensure commitments storage is hash (non-zero) and no plaintext in storage
    comm = vuln.functions.commitments(alice.address).call()
    assert comm != b'\x00'*32 and comm is not None, "commit should be non-zero"
    print("Commit stored (non-zero).")

    # Reveal recorded
    revealed_v = vuln.functions.revealedBid(alice.address).call()
    revealed_h = hard.functions.revealedBid(alice.address).call()
    print("revealed_v:", revealed_v, "revealed_h:", revealed_h)
    assert revealed_v == bid_amount, "vulnerable reveal mismatch"
    assert revealed_h == bid_amount, "hardened reveal mismatch"

    # Divergence check: winner/winningBid differences
    v_winner = vuln.functions.winner().call()
    h_winner = hard.functions.winner().call()
    v_bid = vuln.functions.winningBid().call()
    h_bid = hard.functions.winningBid().call()
    print("v_winner", v_winner, "h_winner", h_winner, "v_bid", v_bid, "h_bid", h_bid)
    diverged = (v_winner != h_winner) or (v_bid != h_bid)
    assert diverged, "expected divergence between vulnerable and hardened auction outcomes"
    print("Divergence confirmed.")

    run_record.update({
        "revealed_v": str(revealed_v),
        "revealed_h": str(revealed_h),
        "v_winner": v_winner,
        "h_winner": h_winner,
        "v_bid": str(v_bid),
        "h_bid": str(h_bid)
    })

    # Attacker profit check (optional, approximate)
    try:
        if is_token:
            atk_before = erc20.functions.balanceOf(attacker.address).call()
        else:
            atk_before = w3.eth.get_balance(attacker.address)
        # compute after by reading current balances (approx — gas costs ignored unless you compute them)
        if is_token:
            atk_after = erc20.functions.balanceOf(attacker.address).call()
        else:
            atk_after = w3.eth.get_balance(attacker.address)
        run_record.update({"attacker_before": str(atk_before), "attacker_after": str(atk_after)})
        print("Attacker bal before/after:", atk_before, atk_after)
    except Exception as e:
        print("Attacker snapshot failed:", e)

    # Save run record
    Path("artifacts").mkdir(parents=True, exist_ok=True)
    with open("artifacts/run-record.json", "w") as fh:
        json.dump(run_record, fh, indent=2)

    print("Run complete. Saved artifacts/run-record.json")

if __name__ == "__main__":
    main()
