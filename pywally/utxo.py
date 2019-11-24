from pywally.address import scriptpubkey_to_address


class Utxo(object):
    """Unspent transaction output"""

    def __init__(self, txid: bytes, vout: int, height: int, amount: int, scriptpubkey: bytes):
        self.txid = txid
        self.vout = vout
        self.height = height
        self.amount = amount
        self.scriptpubkey = scriptpubkey

    # TODO: add type?
    def address(self) -> str:
        try:
            return scriptpubkey_to_address(self.scriptpubkey)
        except ValueError:
            return ''
