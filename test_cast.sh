#!/usr/bin/env bash

# This script tests the Python-based workaround for the broken 'cast --to-uint256' function.

# Helper function - WORKAROUND using Python's string concatenation (safe and precise)
to_uint() {
    # Expects input like "100ether"
    local amount_eth
    
    # 1. Strip the "ether" suffix
    # The output of sed is captured into amount_eth
    amount_eth=$(echo "$1" | sed 's/ether//')
    
    # 2. Use Python to build the string: "100" + "0" * 18
    #    We use escaped double quotes inside the function to allow Bash to substitute $amount_eth.
    python -c "print(\"$amount_eth\" + \"0\" * 18)"
}

echo "--- Testing 100ether ---"
# Capture the output of the function into result_a
result_a=$(to_uint "100ether")
echo "Result A (Expected 1000...): $result_a"

echo "--- Testing 80ether ---"
# Capture the output of the function into result_b
result_b=$(to_uint "80ether")
echo "Result B (Expected 800...): $result_b"

echo "Test complete."
