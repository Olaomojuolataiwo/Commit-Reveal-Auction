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
 - PRIVATE_KEY_DEPLOYER, PRIVATE_KEY_ALICE, PRIVATE_KEY_ATTACKER (hex private keys, 0x...)
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
from flashbot_helper import FlashbotHelper
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

PRICE_ORACLE_ABI = [
    {"inputs":[{"internalType":"uint256","name":"_price","type":"uint256"}],"name":"setPrice","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[],"name":"getPrice","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}
]


ERC20_ABI = [
    {"constant":False,"inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}],"name":"mint","outputs":[],"type":"function"}, 
    {"constant":True,"inputs":[{"name":"owner","type":"address"},{"name":"spender","type":"address"}],"name":"allowance","outputs":[{"name":"","type":"uint256"}],"type":"function"},
    {"constant":False,"inputs":[{"name":"spender","type":"address"},{"name":"amount","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"type":"function"}, 
    {"constant":True,"inputs":[{"name":"account","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"type":"function"}, 
    {"constant":False,"inputs":[{"name":"recipient","type":"address"},{"name":"amount","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"}, 
    {"constant":False,"inputs":[{"name":"sender","type":"address"},{"name":"recipient","type":"address"},
    {"name":"amount","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"","type":"bool"}],"type":"function"}]



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


def build_and_sign_tx(function_call, from_account, value=0, gas=None, nonce=None):
    """
    Build, sign and return raw tx bytes (signed).
    function_call: Contract.function(...).buildTransaction(...) already prepared or function object + args passed in.
    """
    tx = function_call.build_transaction({
        "from": from_account.address,
        "nonce": w3.eth.get_transaction_count(from_account.address) if nonce is None else nonce,
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
    if isinstance(signed_tx, (bytes, bytearray)):
        tx_hash = w3.eth.send_raw_transaction(signed_tx)
    else:
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
    with open("out/VulnerableSealedBidAuctionWithSpot.sol/VulnerableSealedBidAuctionWithSpot.json") as f:
        vuln_abi = json.load(f)["abi"]
    with open("out/HardenedSealedBidAuctionWithSpot.sol/HardenedSealedBidAuctionWithSpot.json") as f:
        hard_abi = json.load(f)["abi"]

    vuln = w3.eth.contract(address=vuln_addr, abi=vuln_abi)
    hard = w3.eth.contract(address=hard_addr, abi=hard_abi)
    print("Vuln contract functions:", [fn.fn_name for fn in vuln.all_functions()])

    ORACLE_ADDR = "0xE6429C6e938684ed6B9Dd950481ed7282EB94b9D"
    ORACLE_ABI = [
        {"inputs":[{"internalType":"uint256","name":"_price","type":"uint256"}],"name":"setPrice","outputs":[],"stateMutability":"nonpayable","type":"function"},
        {"inputs":[],"name":"getPrice","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}
    ]

    # create a contract instance for the oracle (use checksum address)
    price_oracle = w3.eth.contract(address=Web3.to_checksum_address(ORACLE_ADDR), abi=ORACLE_ABI)
    print("Connected to PriceOracleMock at", ORACLE_ADDR, "current price:", price_oracle.functions.getPrice().call())


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
    bid_amount = w3.to_wei(3, "ether")  # change as desired
    nonce = Web3.keccak(text="secret-nonce-1")  # deterministic for test - bytes32
    commit_hash = Web3.solidity_keccak(["uint256","address","bytes32"], [bid_amount, alice.address, nonce])
    deposit_amount = w3.to_wei(1, "ether")  # must match deployed contract's depositAmount
    
    # If token auction: approve auction contract to pull deposit from Alice
    if is_token:
        print("Alice approve deposit to vuln auction")
        approve_if_token(erc20, alice, vuln_addr, bid_amount + deposit_amount)
        print("Alice approve deposit to hardened auction")
        approve_if_token(erc20, alice, hard_addr, bid_amount + deposit_amount)
     # --- Debug: print allowance after approval ---
        alice_allowance_vuln = erc20.functions.allowance(alice.address, vuln_addr).call()
        alice_allowance_hard = erc20.functions.allowance(alice.address, hard_addr).call()
        print(f"Alice allowance to vuln auction after approve: {alice_allowance_vuln}")
        print(f"Alice allowance to hardened auction after approve: {alice_allowance_hard}")

    
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
    print(f"Alice intended bid_amount: {bid_amount}")

    # wait until we're in reveal phase (prefer polling blocks over sleep)
    commit_end_block = vuln.functions.commitEndBlock().call()  # read commitEndBlock from contract
    print("commitEndBlock =", commit_end_block)

    print("Waiting for block > commitEndBlock (reveal phase)...")
    while True:
        current = w3.eth.block_number
        if current > commit_end_block + 1:
            print("Now in reveal phase at block", current)
            break
        # sleep small amount to avoid tight loop; block times ~12s on Sepolia typically
        time.sleep(12)

    print("Alice commit on hard:", hard.functions.commitments(alice.address).call())
    print("Alice commit on vuln:", vuln.functions.commitments(alice.address).call())


    # sanity: verify commit stored before revealing
    comm_check = vuln.functions.commitments(alice.address).call()
    assert comm_check != b'\x00'*32, "alice commitment missing (unexpected)"

    # if using token mode, ensure allowance >= bid_amount
    if is_token:
        print(f"Alice allowance before reveal: {alice_allowance_vuln}, bid_amount: {bid_amount}")
        print(f"Alice allowance to hardened auction before reveal: {alice_allowance_hard}, bid_amount: {bid_amount}")
        assert alice_allowance_vuln >= bid_amount, "alice token allowance insufficient for reveal"
        assert alice_allowance_hard >= bid_amount, "alice token allowance insufficient for hardened reveal"

    # 4)---------- Sandwich: build front, reveal, back (single unified block) ----------
    # Build values
    PHIGH = w3.to_wei(4000, "ether") if price_oracle else None
    P0 = price_oracle.functions.getPrice().call() if price_oracle else None
    if price_oracle:
        print("Current oracle price:", P0)

    # Prepare nonces: explicit attacker nonces for deterministic ordering
    att_nonce = w3.eth.get_transaction_count(attacker.address)
    alice_nonce = w3.eth.get_transaction_count(alice.address)

    # Build & sign transactions (specify nonces where needed)
    front_signed = None
    back_signed = None

    if price_oracle:
        # attacker front-run: use nonce = att_nonce
        front_signed = build_and_sign_tx(price_oracle.functions.setPrice(PHIGH), attacker, nonce=att_nonce)
        # attacker back-run (prepared now, nonce = att_nonce + 1)
        back_signed = build_and_sign_tx(price_oracle.functions.setPrice(P0), attacker, nonce=att_nonce + 1)


    # victim reveal (alice) — use her current nonce (separate for clarity)
    reveal_signed = build_and_sign_tx(vuln.functions.reveal(bid_amount, nonce), alice, value=(0 if is_token else bid_amount), nonce=alice_nonce)

    # 5) Send bundle via Flashbots or broadcast sequentially

    print("Submitting sandwich...")

    # Build bund list using raw signed tx bytes (no .hex())
    bundle = []
    if front_signed:
        bundle.append(front_signed.rawTransaction)   # bytes
    bundle.append(reveal_signed.rawTransaction)
    if back_signed:
        bundle.append(back_signed.rawTransaction)

    # Helper: try sending bundle for a few target blocks (polite retry)
    def try_flashbots_bundle(bundle_bytes_list, attempt_blocks=3, offset=1):
    # attempt_blocks: how many successive blocks to try (0 -> only once)
        for i in range(attempt_blocks):
            target_block = w3.eth.block_number + offset + i
            try:
            # If your FlashbotHelper.send_bundle supports target_block_offset or target_block_number,
            # adapt the signature. Below we try to pass target_block_number for clarity.
                print(f"  Sending bundle to Flashbots for target block {target_block} (attempt {i+1}/{attempt_blocks})")
                res = fb.send_bundle(*bundle, target_block_offset=1)
            # If send_bundle returns an object exposing wait() or get results, call it
            # Many flashbots helpers return an object you must wait on; handle both.
                try:
                    receipt = res.wait()   # blocking — returns inclusion info if included
                    if receipt:
                        print(f"  Bundle included in block {receipt.blockNumber}")
                        return True
                except Exception:
                # some libraries don't implement .wait(); fallback to simple log
                    print("  Flashbots send returned; inclusion unknown (no .wait()).")
                # you can check chain or logs later if desired
                    return True
            except Exception as e:
                print("  Flashbots send failed:", e)
            # continue and retry next target block
                continue
        return False

    bundle_included = False
    if FLASHBOTS_ENABLED and fb:
    # Try the bundle for up to 3 target blocks (adjust as you like)
        bundle_included = try_flashbots_bundle(bundle, attempt_blocks=3, offset=1)
        if bundle_included:
            print("Bundle submitted via Flashbots and (likely) included.")
        else:
            print("Bundle sent but not included in target blocks (or send failed).")

     # If bundle not included: if we are still in reveal phase, we must re-sign a fresh public reveal
    alice_revealed_amount = vuln.functions.revealedBid(alice.address).call()
    current_block = w3.eth.block_number
    reveal_end_block = vuln.functions.revealEndBlock().call()
    print(f"Current block: {current_block} revealEndBlock: {reveal_end_block}")

    if bundle_included:
    # proceed normally — will check after reveal window
        pass
    else:
    # bundle not included. If still in reveal phase, broadcast public reveal (freshly signed)
        if current_block <= reveal_end_block:
            print("Bundle failed to include. Broadcasting Alice's reveal publicly *now* (still in reveal phase).")
        # Get fresh nonce for Alice in case it changed
            fresh_alice_nonce = w3.eth.get_transaction_count(alice.address)
            try:
                reveal_signed_pub = build_and_sign_tx(vuln.functions.reveal(bid_amount, nonce),
                                                  alice,
                                                  value=(0 if is_token else bid_amount),
                                                  nonce=fresh_alice_nonce)
            # send and wait
                send_raw_and_wait(reveal_signed_pub)
                print("Public reveal broadcasted and mined (or at least submitted).")
            except Exception as e:
            # If nonce error or RPC error: refresh nonce and retry once
                print("Public reveal failed:", e)
            # refresh nonce once more and retry if still in reveal phase
                fresh_alice_nonce = w3.eth.get_transaction_count(alice.address)
                try:
                    reveal_signed_pub = build_and_sign_tx(vuln.functions.reveal(bid_amount, nonce),
                                                      alice,
                                                      value=(0 if is_token else bid_amount),
                                                      nonce=fresh_alice_nonce)
                    send_raw_and_wait(reveal_signed_pub)
                    print("Public reveal retry succeeded.")
                except Exception as e2:
                    print("Public reveal retry failed:", e2)
        else:
            print("Reveal window already passed; cannot broadcast reveal publicly.")

    # -------------------------------------------------------------------------------


    # 5) Also reveal on hardened auction (to keep states comparable)
    print("Reveal on hardened auction (same preimage)...")
    if is_token:
        reveal_hard_signed = build_and_sign_tx(hard.functions.reveal(bid_amount, nonce), alice, value=0)
    else:
        reveal_hard_signed = build_and_sign_tx(hard.functions.reveal(bid_amount, nonce), alice, value=bid_amount)
    send_raw_and_wait(reveal_hard_signed)
    print("Revealed on hardened auction")

    # 6) Wait until reveal window closes (simple sleep; better: poll block.number)
    print("Waiting reveal window to close...")
    reveal_end_block = vuln.functions.revealEndBlock().call()
    print("revealEndBlock =", reveal_end_block)
    print("Waiting for block > revealEndBlock (finalize phase)...")
    while True:
        current = w3.eth.block_number
        if current > reveal_end_block:
            print("Now past revealEndBlock at block", current)
            break
        time.sleep(5)
    # sanity: ensure Alice's reveal was recorded on the vulnerable auction
    alice_revealed_amount = vuln.functions.revealedBid(alice.address).call()
    if alice_revealed_amount == 0:
        print("Warning: Alice reveal not recorded on vulnerable auction (alice_revealed_amount==0).")

    # 7) Finalize both auctions (deployer does this)

    while w3.eth.block_number <= reveal_end_block:
          time.sleep(5)

    print("Finalizing vulnerable auction...")
    # Get the current nonce for the deployer
    deployer_nonce = w3.eth.get_transaction_count(deployer.address)
    finalize_tx_vuln = build_and_sign_tx(vuln.functions.finalize(), deployer, nonce=deployer_nonce)
    send_raw_and_wait(finalize_tx_vuln.rawTransaction)
    print("Vulnerable auction finalized.")

    print("Finalizing hardened auction...")

    # Increment the nonce for the next transaction from the same account
    deployer_nonce += 1
    finalize_tx_hard = build_and_sign_tx(hard.functions.finalize(), deployer, nonce=deployer_nonce)
    send_raw_and_wait(finalize_tx_hard.rawTransaction)
    print("Hardened auction finalized.")

    # 8) Assertions & snapshots
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
