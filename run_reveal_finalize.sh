#!/usr/bin/env bash
set -euo pipefail

# ---------- CONFIG ---------- #
# Ensure these env vars are exported before running:
# - INFURA_KEY (or RPC_URL)
# - AUCTION_ADDR
# - DEPLOYER_PK   (for finalize)
# - ALICE_PK      (forge script uses this)
# - ATTACKER_PK   (if needed)
# - MOCK_TOKEN_ADDR
# - BENEFICIARY   (address to check balances)

SCRIPT_PATH="script/Grieving_Onchain2.s.sol"

# ---------- RPC endpoint ----------
if [ -z "${RPC_URL:-}" ]; then
  if [ -z "${INFURA_KEY:-}" ]; then
    echo "Set RPC_URL or INFURA_KEY"
    exit 1
  else
    RPC_URL="https://sepolia.infura.io/v3/$INFURA_KEY"
  fi
fi

# ---------- Required env ----------
AUCTION_ADDR="${AUCTION_ADDR:-}"
DEPLOYER_PK="${DEPLOYER_PK:-}"
ALICE_PK="${ALICE_PK:-}"
MOCK_TOKEN_ADDR="${MOCK_TOKEN_ADDR:-}"
BENEFICIARY="${BENEFICIARY:-}"

if [ -z "$AUCTION_ADDR" ] || [ -z "$DEPLOYER_PK" ] || [ -z "$ALICE_PK" ] || [ -z "$MOCK_TOKEN_ADDR" ] || [ -z "$BENEFICIARY" ]; then
  echo "Missing required env vars. Please export AUCTION_ADDR, DEPLOYER_PK, ALICE_PK, MOCK_TOKEN_ADDR, BENEFICIARY"
  exit 1
fi

TMP_OUT="$(mktemp)"
trap 'rm -f "$TMP_OUT"' EXIT

# ---------- STEP 1: Run forge reveal script ----------
echo "=== STEP 1: running forge reveal script ==="
forge script "$SCRIPT_PATH" --rpc-url "$RPC_URL" --broadcast --private-key "$ALICE_PK" -vvvv 2>&1 | tee "$TMP_OUT"

# Extract tx hashes from forge output
echo
echo "=== Extracted forge broadcast transaction hashes ==="
grep -Eo '0x[a-f0-9]{64}' "$TMP_OUT" | sort -u || echo "(no tx hashes found)"

# ---------- STEP 2: Wait for reveal window ----------
# Read revealEndBlock directly from the live contract
REVEAL_END_BLOCK_HEX=$(cast call "$AUCTION_ADDR" "revealEndBlock()" --rpc-url "$RPC_URL")
if [ -z "$REVEAL_END_BLOCK_HEX" ] || [ "$REVEAL_END_BLOCK_HEX" = "0x0" ]; then
    echo "Could not read revealEndBlock. Aborting."
    exit 1
fi

# Convert to decimal
REVEAL_END_BLOCK=$((REVEAL_END_BLOCK_HEX))
WAIT_BLOCK=$((REVEAL_END_BLOCK + 1))  # Wait 1 block past reveal window

echo "RevealEndBlock: $REVEAL_END_BLOCK"
echo "Waiting until block $WAIT_BLOCK (past reveal window)..."

while [ "$(cast block-number --rpc-url "$RPC_URL")" -le "$WAIT_BLOCK" ]; do
    printf "."
    sleep 12
done

echo -e "\nReveal window passed. Current block: $(cast block-number --rpc-url "$RPC_URL")"


# ---------- Finalize ---------- #
echo
echo "=== STEP 3: calling finalize() ==="

# Fetch latest revealEndBlock from contract
REVEAL_END_BLOCK=$(cast call "$AUCTION_ADDR" "revealEndBlock()" --rpc-url "$RPC_URL" | sed 's/[^0-9]*//g')
CURRENT_BLOCK=$(cast block-number --rpc-url "$RPC_URL")

echo "RevealEndBlock: $REVEAL_END_BLOCK"
echo "Current block: $CURRENT_BLOCK"

# Wait until we are safely past revealEndBlock (+1 block buffer)
if [ "$CURRENT_BLOCK" -le "$REVEAL_END_BLOCK" ]; then
  echo "Reveal window still open. Waiting until block > $REVEAL_END_BLOCK ..."
  while [ "$(cast block-number --rpc-url "$RPC_URL")" -le "$REVEAL_END_BLOCK" ]; do
    printf "."
    sleep 12
  done
  echo
fi

echo "Reveal window closed. Current block: $(cast block-number --rpc-url "$RPC_URL")"

# Call finalize
FINALIZE_OUTPUT=$(cast send "$AUCTION_ADDR" "finalize()" \
  --private-key "$DEPLOYER_PK" --rpc-url "$RPC_URL" 2>&1) \
  || { echo "finalize failed: $FINALIZE_OUTPUT"; exit 1; }

echo "$FINALIZE_OUTPUT"
echo "Finalize tx hash:"
echo "$FINALIZE_OUTPUT" | grep -Eo '0x[a-f0-9]{64}' || true


# ---------- STEP 4: Post-finalize checks ----------
echo
echo "=== STEP 4: Post-finalize checks ==="

BEN_AFTER=$(cast call "$MOCK_TOKEN_ADDR" "balanceOf(address)" "$BENEFICIARY" --rpc-url "$RPC_URL" | sed 's/[^0-9]*//g')
echo "Beneficiary token balance after finalize: $BEN_AFTER"

# Optional: read winner() and winningBid()
if cast call "$AUCTION_ADDR" "winner()" --rpc-url "$RPC_URL" >/dev/null 2>&1; then
  WINNER_ADDR=$(cast call "$AUCTION_ADDR" "winner()" --rpc-url "$RPC_URL")
  echo "Auction winner(): $WINNER_ADDR"
fi

if cast call "$AUCTION_ADDR" "winningBid()" --rpc-url "$RPC_URL" >/dev/null 2>&1; then
  WIN_BID=$(cast call "$AUCTION_ADDR" "winningBid()" --rpc-url "$RPC_URL")
  echo "Auction winningBid(): $WIN_BID"
fi

echo
echo "=== DONE ==="
