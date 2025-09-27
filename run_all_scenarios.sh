#!/usr/bin/env bash

# Default values for scenarios
: "${DEPOSIT_AMOUNT:=10}"
: "${ALICE_BID:=100}"
: "${ATTACKER_BID:=120}"
: "${ALICE_NONCE:=123}"
: "${ATTACKER_NONCE:=999}"
: "${CHEAT_INFLATE:=5}"
: "${REPLAYER_PK:=0}"
: "${ATTACKER_PK:=0}"
: "${COMMIT_BLOCKS:=10}"
: "${REVEAL_BLOCKS:=10}"
: "${MOCK_TOKEN_ADDR:=}"
: "${BENEFICIARY:=}"

set -euo pipefail

# Ensure required env vars
if [ -z "${RPC_URL:-}" ] || [ -z "${DEPLOYER_PK:-}" ] || [ -z "${ALICE_PK:-}" ] || [ -z "${ATTACKER_PK:-}" ]; then
  echo "Please export RPC_URL, DEPLOYER_PK, ALICE_PK, ATTACKER_PK before running."
  exit 1
fi

SCRIPT="script/frontrunning_Onchain.s.sol:ScenarioActions"
FORGE_BASE="forge script $SCRIPT --rpc-url $RPC_URL --broadcast -vvvv"

# Fetch latest auction from manager on-chain
get_latest_auction() {
  local auctions
  auctions=$(cast call "$MANAGER_ADDR" "getAllAuctions()(address[])" --rpc-url "$RPC_URL")

  # Remove brackets
  auctions="${auctions#[}"
  auctions="${auctions%]}"

  # Split by comma into array
  IFS=',' read -ra ADDR_ARRAY <<< "$auctions"

  # Return the last element (trim quotes/spaces)
  echo "${ADDR_ARRAY[-1]//\"/}"
}

get_commit_end() {
  local AUCTION=$1
  cast call "$AUCTION" "commitEndBlock()" --rpc-url "$RPC_URL" | cast --to-dec
}

get_reveal_end() {
  local AUCTION=$1
  cast call "$AUCTION" "revealEndBlock()" --rpc-url "$RPC_URL" | cast --to-dec
}

get_block_number() {
  cast block-number --rpc-url "$RPC_URL"
}

# Wait for tx confirmation
wait_for_tx() {
  local TX_HASH=$1
  echo "Waiting for tx $TX_HASH to confirm..."
  while true; do
    local RECEIPT
    RECEIPT=$(cast receipt "$TX_HASH" --rpc-url "$RPC_URL" 2>/dev/null || true)
    if [[ -n "$RECEIPT" && "$RECEIPT" != "null" ]]; then
      echo "Tx $TX_HASH confirmed."
      break
    fi
    sleep 6
  done
}

is_local=false
[[ "$RPC_URL" == "http://127.0.0.1:8545" || "$RPC_URL" == "http://localhost:8545" ]] && is_local=true

# Scenarios
SCENENAMES=(
  "happy"
  "frontrun_inflated_fail"
  "valid_attack"
  "reveal_other_attempt"
  "non_reveal_griefing"
  "double_reveal_attempt"
  "late_reveal"
  "replay_relayer_attempt"
)

REPLAYER_PK="0x9aa9c5543994100e969b1f934aa22f467b66a252d3ef5b56eaf00734ed7e0828"

declare -A SCENARIODATA=(
  ["happy"]="100ether 80ether 123 999 0 false 0"
  ["frontrun_inflated_fail"]="100ether 120ether 200 201 1 true 0"
  ["valid_attack"]="100ether 200ether 301 302 0 false 0"
  ["reveal_other_attempt"]="150ether 0ether 401 402 0 true $REPLAYER_PK"
  ["non_reveal_griefing"]="100ether 120ether 501 502 0 false 0"
  ["double_reveal_attempt"]="100ether 120ether 601 602 0 false 0"
  ["late_reveal"]="100ether 120ether 701 702 0 false 0"
  ["replay_relayer_attempt"]="100ether 0ether 801 802 0 true $REPLAYER_PK"
)

# Convert "100ether" to uint
to_uint() {
  local amount_eth
  amount_eth=$(echo "$1" | sed 's/ether//')
  python -c "print(int($amount_eth * 10**18))"
}

# Loop through scenarios
for name in "${SCENENAMES[@]}"; do
  echo "===================== Running scenario: $name ====================="

  read -r aBid atBid aNonce atNonce cheatInflate doCheat replayer_pk <<< "${SCENARIODATA[$name]}"

  export ALICE_BID=$(to_uint "$aBid")
  export ATTACKER_BID=$(to_uint "$atBid")
  export ALICE_NONCE="$aNonce"
  export ATTACKER_NONCE="$atNonce"
  export CHEAT_INFLATE="$cheatInflate"
  export REPLAYER_PK="$replayer_pk"

  echo "--- Deploying auction for scenario $name ---"
  $FORGE_BASE --sig "deploy()" --private-key "$DEPLOYER_PK" > >(tee "deploy_${name}.log") 2>&1

  DEPLOY_LOG_FILE="deploy_${name}.log"
  AUCTION_ADDR=$(grep "Deployed Auction" "$DEPLOY_LOG_FILE" | tail -n 1 | awk '{print $3}' | tr -d '\r\n')
  if [ -z "$AUCTION_ADDR" ]; then
echo "Failed to parse auction address from deploy output log."
cat "$DEPLOY_LOG_FILE"
  exit 1
fi

echo "Auction deployed: $AUCTION_ADDR"
  export AUCTION_ADDR

  echo "--- Commit phase ---"
env AUCTION_ADDR="$AUCTION_ADDR"  $FORGE_BASE --sig "commitBoth()" --private-key "$DEPLOYER_PK" 2>&1 | tee "commit_${name}.log"

  commitEndBlock=$(get_commit_end "$AUCTION_ADDR")
  revealEndBlock=$(get_reveal_end "$AUCTION_ADDR")
  currentBlock=$(get_block_number)

  echo "CommitEnd: $commitEndBlock, RevealEnd: $revealEndBlock, Current: $currentBlock"

  if (( currentBlock <= commitEndBlock )); then
    echo "Still in commit phase. Wait for block $((commitEndBlock+1)) to reveal."
    continue
  fi

  echo "Reveal phase open."

  if [ "$doCheat" = "true" ]; then
    echo "--- Attacker cheat attempt ---"
    $FORGE_BASE --sig "cheatReveal()" --private-key "$DEPLOYER_PK" 2>&1 | tee "cheat_${name}.log"
  fi

  case "$name" in
    "reveal_other_attempt")
      echo "--- Replayer attempt ---"
      $FORGE_BASE --sig "cheatReplayCall()" --private-key "$DEPLOYER_PK" 2>&1 | tee "replay_${name}.log"
      ;;
    "double_reveal_attempt")
      echo "--- Attacker double reveal ---"
      $FORGE_BASE --sig "attackerDoubleReveal()" --private-key "$DEPLOYER_PK" 2>&1 | tee "double_reveal_${name}.log"
      ;;
    "non_reveal_griefing")
      echo "--- Griefing: reveal Alice only ---"
      $FORGE_BASE --sig "revealAliceOnly()" --private-key "$DEPLOYER_PK" 2>&1 | tee "reveal_${name}.log"
      ;;
    "late_reveal")
      echo "--- Late reveal attempt ---"
      $FORGE_BASE --sig "revealBoth()" --private-key "$DEPLOYER_PK" 2>&1 | tee "reveal_${name}.log" || true
      ;;
    *)
      echo "--- Reveal both ---"
      $FORGE_BASE --sig "revealBoth()" --private-key "$DEPLOYER_PK" 2>&1 | tee "reveal_${name}.log"
      ;;
  esac

  currentBlock=$(get_block_number)
  if (( currentBlock <= revealEndBlock )); then
    echo "Still in reveal phase. Wait for block $((revealEndBlock+1)) to finalize."
    continue
  fi

  echo "--- Finalize ---"
  $FORGE_BASE --sig "finalize()" --private-key "$DEPLOYER_PK" 2>&1 | tee "finalize_${name}.log"

  echo "--- Status ---"
  $FORGE_BASE --sig "status()" --private-key "$DEPLOYER_PK" 2>&1 | tee "status_${name}.log"

  echo "Scenario $name completed. Logs: deploy_${name}.log commit_${name}.log cheat_${name}.log reveal_${name}.log finalize_${name}.log status_${name}.log"
  echo ""
  sleep 2
done

echo "All scenarios completed."
