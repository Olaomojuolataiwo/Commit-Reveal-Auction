# flashbot_helper.py
from web3 import Web3
from flashbots import flashbot
from eth_account import Account

class FlashbotHelper:
    def __init__(self, rpc_url: str, relay_url: str, searcher_privkey: str):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.searcher = Account.from_key(searcher_privkey)

        # Attach flashbots middleware
        flashbot(self.w3, self.searcher, endpoint_uri=relay_url)

    def send_bundle(self, frontrun_tx: bytes, victim_tx: bytes, backrun_tx: bytes):
        block = self.w3.eth.block_number + 1

        bundle = [
            {"signed_transaction": frontrun_tx},
            {"signed_transaction": victim_tx},
            {"signed_transaction": backrun_tx},
        ]

        result = self.w3.flashbots.send_bundle(
            bundle, target_block_number=block
        )
        print(f"📤 Bundle sent to Flashbots for block {block}")

        receipt = result.wait()
        if receipt:
            print(f"Bundle included in block {receipt.blockNumber}")
        else:
            print("Bundle not included")
