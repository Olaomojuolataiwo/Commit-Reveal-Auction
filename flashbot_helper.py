# flashbot_helper.py
from web3 import Web3
from flashbots import flashbot
from eth_account import Account
from typing import List, Union

class FlashbotHelper:
    def __init__(self, rpc_url: str, relay_url: str, searcher_privkey: str):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.searcher = Account.from_key(searcher_privkey)

        # Attach flashbots middleware
        flashbot(self.w3, self.searcher, endpoint_uri=relay_url)

    def send_bundle(self, signed_transactions: List[Union[bytes, str]], target_block_number: int):
        """
        Accepts a list of raw signed transactions (bytes or hex string) and sends a flashbots bundle
        targeting a specific block number.

        The returned result object includes a crucial .wait() method used by the caller
        to confirm bundle inclusion.
        """
        # The web3-flashbots library expects a list of dictionaries:
        bundle = [{"signed_transaction": tx} for tx in signed_transactions]

        result = self.w3.flashbots.send_bundle(bundle, target_block_number=target_block_number)
        print(f"    Bundle sent to Flashbots for block {target_block_number}")

        return result
