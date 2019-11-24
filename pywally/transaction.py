import wallycore as wally

from typing import Dict


class TransactionError(Exception):
    pass


class InvalidTransaction(TransactionError):
    pass


class InvalidIndexError(TransactionError):
    pass


class Transaction(object):

    def __init__(self, tx=None, version: int = wally.WALLY_TX_VERSION_2, nlocktime: int = 0):
        self.tx = tx if tx else wally.tx_init(version, nlocktime, 0, 0)

    def version(self) -> int:
        return wally.tx_get_version(self.tx)

    def nlocktime(self) -> int:
        return wally.tx_get_locktime(self.tx)

    @classmethod
    def from_bytes(cls, b: bytes, use_witness: bool = False):
        flags = wally.WALLY_TX_FLAG_USE_WITNESS if use_witness else 0
        try:
            return cls(tx=wally.tx_from_bytes(b, flags))
        except ValueError:
            raise InvalidTransaction

    @classmethod
    def from_hex(cls, h: str, use_witness: bool = False):
        flags = wally.WALLY_TX_FLAG_USE_WITNESS if use_witness else 0
        try:
            return cls(tx=wally.tx_from_hex(h, flags))
        except ValueError:
            raise InvalidTransaction

    def to_bytes(self, use_witness: bool = False) -> bytes:
        flags = wally.WALLY_TX_FLAG_USE_WITNESS if use_witness else 0
        return wally.tx_to_bytes(self.tx, flags)

    def to_hex(self, use_witness: bool = False) -> str:
        flags = wally.WALLY_TX_FLAG_USE_WITNESS if use_witness else 0
        return wally.tx_to_hex(self.tx, flags)

    def num_inputs(self) -> int:
        return wally.tx_get_num_inputs(self.tx)

    def num_outputs(self) -> int:
        return wally.tx_get_num_outputs(self.tx)

    def add_input(self, txid: bytes, vout: int, sequence: int):
        """Add an unsigned input"""

        wally.tx_add_raw_input(self.tx, txid, vout, sequence, None, None, 0)

    def add_output(self, scriptpubkey: bytes, satoshi: int):
        wally.tx_add_raw_output(self.tx, satoshi, scriptpubkey, 0)

    def remove_input(self, i: int):
        if i > self.num_inputs() - 1:
            raise InvalidIndexError
        wally.tx_remove_input(self.tx, i)

    def remove_output(self, i: int):
        if i > self.num_outputs() - 1:
            raise InvalidIndexError
        wally.tx_remove_output(self.tx, i)

    def input_to_dict(self, i: int) -> Dict:
        if i > self.num_inputs() - 1:
            raise InvalidIndexError
        return {
            'txid': wally.tx_get_input_txhash(self.tx, i),
            'vout': wally.tx_get_input_index(self.tx, i),
            'sequence': wally.tx_get_input_sequence(self.tx, i),
            'scriptsig': wally.tx_get_input_script(self.tx, i),
        }

    def output_to_dict(self, i: int) -> Dict:
        if i > self.num_outputs() - 1:
            raise InvalidIndexError
        return {
            'scriptpubkey': wally.tx_get_output_script(self.tx, i),
            'satoshi': wally.tx_get_output_satoshi(self.tx, i),
        }

    def sign(self, i: int, signer):
        """Fill i-th input fields with a signature and script made by a signer"""

        signer.sign(self.tx, i)

    def txid(self) -> bytes:
        """The transaction id"""

        return wally.sha256d(self.to_bytes())

    def hash(self) -> bytes:
        """The transaction hash (differs from txid for witness transactions)"""

        return wally.sha256d(self.to_bytes(use_witness=True))

    def size(self) -> int:
        """The serialized transaction size"""

        return wally.tx_get_length(self.tx, wally.WALLY_TX_FLAG_USE_WITNESS)

    def vsize(self) -> int:
        """The virtual transaction size (differs from size for witness transactions)"""

        return wally.tx_get_vsize(self.tx)

    def weight(self) -> int:
        """The transaction's weight (between vsize*4-3 and vsize*4)"""

        return wally.tx_get_weight(self.tx)
