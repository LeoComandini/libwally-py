import wallycore as wally

from typing import List

from pywally.key import (
    PublicKey,
    PrivateKey,
)
from pywally.output import (
    Output,
    P2PKH,
    P2WPKH,
    P2SHP2WPKH,
    Multisig,
    P2SHMultisig,
    P2WSHMultisig,
    P2SHP2WSHMultisig,
)


class Signer(Output):

    def __init__(self, privkey: PrivateKey, amount: int = 0):
        self.privkey = privkey
        self.amount = amount
        super().__init__(self.privkey.pubkey())


class SignerP2PKH(Signer, P2PKH):

    def script_sig(self, signature_hash: bytes) -> bytes:
        sig = self.privkey.sign_compact(signature_hash)
        return wally.scriptsig_p2pkh_from_sig(self.privkey.pub, sig, wally.WALLY_SIGHASH_ALL)

    def sign(self, tx, i):
        signature_hash = wally.tx_get_btc_signature_hash(tx, i, self.scriptpubkey(), 0, wally.WALLY_SIGHASH_ALL, 0)
        wally.tx_set_input_script(tx, i, self.script_sig(signature_hash))


class SignerP2WPKH(Signer, P2WPKH):

    def witness(self, signature_hash: bytes):
        sig = self.privkey.sign_compact(signature_hash)
        sig_der = wally.ec_sig_to_der(sig) + bytearray([wally.WALLY_SIGHASH_ALL])
        witness = wally.tx_witness_stack_init(2)
        wally.tx_witness_stack_add(witness, sig_der)
        wally.tx_witness_stack_add(witness, self.witness_script())
        return witness

    def sign(self, tx, i: int):
        flags = wally.WALLY_TX_FLAG_USE_WITNESS
        scriptcode = wally.scriptpubkey_p2pkh_from_bytes(self.witness_script(), wally.WALLY_SCRIPT_HASH160)
        signature_hash = wally.tx_get_btc_signature_hash(tx, i, scriptcode, self.amount, wally.WALLY_SIGHASH_ALL, flags)
        wally.tx_set_input_witness(tx, i, self.witness(signature_hash))


class SignerP2SHP2WPKH(SignerP2WPKH, P2SHP2WPKH):

    def sign(self, tx, i):
        super().sign(tx, i)
        wally.tx_set_input_script(tx, i, self.script_sig())


class SignerMultisig(Multisig):
    """NofM multisig signer

    The elements of keys should be PrivateKey or PublicKey, but at least N of
    them must be PrivateKey.

    Note that changing the order of keys, changes the scriptpubkey and address
    """

    def __init__(self, threshold: int, keys: List[PublicKey], amount: int = 0):
        privkeys = []
        pubkeys = []
        for k in keys:
            if isinstance(k, PrivateKey):
                privkeys.append(k)
                pubkeys.append(k.pubkey())
            else:
                privkeys.append(None)
                pubkeys.append(k)

        if sum(k is not None for k in privkeys) < threshold:
            raise InvalidMultisig('A signer must have at least threshold private key(s)')

        self.privkeys = privkeys
        self.amount = amount
        super().__init__(threshold, pubkeys)


class SignerP2SHMultisig(SignerMultisig, P2SHMultisig):

    def script_sig(self, signature_hash: bytes) -> bytes:
        # TODO: allow partial signing
        sigs_concat = bytearray()
        for privkey in self.privkeys:
            if privkey and len(sigs_concat) < self.threshold * wally.EC_SIGNATURE_LEN:
                sigs_concat.extend(privkey.sign_compact(signature_hash))

        sighashes = [wally.WALLY_SIGHASH_ALL for _ in range(self.threshold)]
        return wally.scriptsig_multisig_from_bytes(self.redeem_script(), sigs_concat, sighashes, 0)

    def sign(self, tx, i: int):
        signature_hash = wally.tx_get_btc_signature_hash(tx, i, self.redeem_script(), 0, wally.WALLY_SIGHASH_ALL, 0)
        wally.tx_set_input_script(tx, i, self.script_sig(signature_hash))


class SignerP2WSHMultisig(SignerMultisig, P2WSHMultisig):

    def witness(self, signature_hash: bytes):
        # TODO: allow partial signing
        witness = wally.tx_witness_stack_init(self.threshold + 2)
        wally.tx_witness_stack_add_dummy(witness, wally.WALLY_TX_DUMMY_NULL)
        num_sigs = 0
        for privkey in self.privkeys:
            if privkey and num_sigs < self.threshold:
                sig = privkey.sign_compact(signature_hash)
                sig_der = wally.ec_sig_to_der(sig) + bytearray([wally.WALLY_SIGHASH_ALL])
                wally.tx_witness_stack_add(witness, sig_der)
                num_sigs += 1

        wally.tx_witness_stack_add(witness, self.witness_script())
        return witness

    def sign(self, tx, i: int):
        flags = wally.WALLY_TX_FLAG_USE_WITNESS
        signature_hash = wally.tx_get_btc_signature_hash(tx, i, self.witness_script(), self.amount, wally.WALLY_SIGHASH_ALL, flags)
        wally.tx_set_input_witness(tx, i, self.witness(signature_hash))


class SignerP2SHP2WSHMultisig(SignerP2WSHMultisig, P2SHP2WSHMultisig):

    def sign(self, tx, i: int):
        super().sign(tx, i)
        wally.tx_set_input_script(tx, i, self.script_sig())
