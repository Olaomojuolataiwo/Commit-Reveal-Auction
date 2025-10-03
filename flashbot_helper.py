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

    def send_bundle(self, *signed_tx_hexes, target_block_offset: int = 1):
        """
        Accepts raw signed tx hex strings (varargs) and sends a flashbots bundle
        targeting current_block + target_block_offset. Returns the send_bundle result object
        (so caller can call .wait() or check inclusion).
        """
        block = self.w3.eth.block_number + target_block_offset

        bundle = [{"signed_transaction": tx} for tx in signed_tx_hexes]

        result = self.w3.flashbots.send_bundle(bundle, target_block_number=block)
        print(f"  📤 Bundle sent to Flashbots for block {block}")

        # don't wait here for too long — caller will decide how to wait/handle
        # but return the result object for the orchestrator to inspect/wait on.
        return result
