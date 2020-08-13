import wallycore as wally

from pywally.output import Output
from pywally.key import PrivateKey, PublicKey


class Output2of2CSV(Output):
    """2of2 CSV output

    Can be satisfied by:
    1) user_key and server_key
    2) user_key and csv_blocks has passed
    """

    def __init__(self, user_pubkey: PublicKey, server_pubkey: PublicKey, csv_blocks: int):
        self.user_pubkey = user_pubkey
        self.server_pubkey = server_pubkey
        self.csv_blocks = csv_blocks

    def redeem_script(self) -> bytes:
        pubkeys_concat = self.server_pubkey.pub + self.user_pubkey.pub
        return wally.scriptpubkey_csv_2of2_then_1_from_bytes_opt(pubkeys_concat, self.csv_blocks, 0)


class P2WSH2of2CSV(Output2of2CSV):

    def witness_script(self) -> bytes:
        return self.redeem_script()

    def script_sig(self) -> bytes:
        return b''

    def scriptpubkey(self) -> bytes:
        return wally.witness_program_from_bytes(self.witness_script(), wally.WALLY_SCRIPT_SHA256)


class Signer2of2CSV(Output2of2CSV):
    """2of2 CSV signer

    If server_key is a PrivateKey, the signer will produce 2 signatures.
    Otherwise, if it is a PublicKey, it will include just the user signature
    and will assume csv_blocks has passed.
    """

    def __init__(self, user_privkey: PrivateKey, server_key: PublicKey, csv_blocks: int, amount: int = 0):
        self.user_privkey = user_privkey
        if isinstance(server_key, PrivateKey):
            self.server_privkey = server_key
            self.server_pubkey = server_key.pubkey()
        else:
            self.server_privkey = None
            self.server_pubkey = server_key
        self.amount = amount
        super().__init__(user_privkey.pubkey(), self.server_pubkey, csv_blocks)


class SignerP2WSH2of2CSV(Signer2of2CSV, P2WSH2of2CSV):

    def witness(self, signature_hash: bytes):
        """
        if self.server_privkey:
            server_sig = self.server_privkey.sign_compact(signature_hash)
            server_sig_der = wally.ec_sig_to_der(server_sig) + bytearray([wally.WALLY_SIGHASH_ALL])
            wally.tx_witness_stack_add(witness, server_sig_der)
        else:
            server_sig_der = None
 
        user_sig = self.user_privkey.sign_compact(signature_hash)
        user_sig_der = wally.ec_sig_to_der(user_sig) + bytearray([wally.WALLY_SIGHASH_ALL])

        witness = [server_sig_der, user_sig_der, self.witness_script()]
        
        return wally.tx_witness_stack_create(witness)
        """
        witness = wally.tx_witness_stack_init(3)

        if self.server_privkey:
            server_sig = self.server_privkey.sign_compact(signature_hash)
            server_sig_der = wally.ec_sig_to_der(server_sig) + bytearray([wally.WALLY_SIGHASH_ALL])
            wally.tx_witness_stack_add(witness, server_sig_der)
        else:
            wally.tx_witness_stack_add(witness, None)
            #wally.tx_witness_stack_add_dummy(witness, wally.WALLY_TX_DUMMY_NULL)

        user_sig = self.user_privkey.sign_compact(signature_hash)
        user_sig_der = wally.ec_sig_to_der(user_sig) + bytearray([wally.WALLY_SIGHASH_ALL])
        wally.tx_witness_stack_add(witness, user_sig_der)

        wally.tx_witness_stack_add(witness, self.witness_script())
        return witness

    def sign(self, tx, i: int):
        flags = wally.WALLY_TX_FLAG_USE_WITNESS
        signature_hash = wally.tx_get_btc_signature_hash(tx, i, self.witness_script(), self.amount, wally.WALLY_SIGHASH_ALL, flags)
        wally.tx_set_input_witness(tx, i, self.witness(signature_hash))
