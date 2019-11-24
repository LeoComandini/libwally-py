import wallycore as wally

from typing import List

from pywally.address import scriptpubkey_to_address
from pywally.key import PublicKey


class OutputError(Exception):
    pass


class InvalidMultisig(OutputError):
    pass


class Output(object):

    def __init__(self, pubkey: PublicKey):
        self.pubkey = pubkey
        # TODO: handle (or prevent) uncompressed pubkeys

    def scriptpubkey(self):
        raise NotImplementedError

    def address(self) -> str:
        return scriptpubkey_to_address(self.scriptpubkey())


class P2SH(Output):

    def redeem_script(self) -> bytes:
        raise NotImplementedError

    def scriptpubkey(self) -> bytes:
        return wally.scriptpubkey_p2sh_from_bytes(self.redeem_script(), wally.WALLY_SCRIPT_HASH160)


class P2PKH(Output):

    def scriptpubkey(self) -> bytes:
        return wally.scriptpubkey_p2pkh_from_bytes(self.pubkey.pub, wally.WALLY_SCRIPT_HASH160)


class P2WPKH(Output):

    def witness_script(self) -> bytes:
        return self.pubkey.pub

    def script_sig(self) -> bytes:
        return b''

    def scriptpubkey(self) -> bytes:
        return wally.witness_program_from_bytes(self.witness_script(), wally.WALLY_SCRIPT_HASH160)


class P2SHP2WPKH(P2SH, P2WPKH):

    def __init__(self, pubkey: PublicKey):
        self.pubkey = pubkey

    def script_sig(self) -> bytes:
        flags = wally.WALLY_SCRIPT_HASH160 | wally.WALLY_SCRIPT_AS_PUSH
        return wally.witness_program_from_bytes(self.witness_script(), flags)

    def redeem_script(self) -> bytes:
        return wally.witness_program_from_bytes(self.witness_script(), wally.WALLY_SCRIPT_HASH160)


class Multisig(Output):
    """NofM multisig output

    Note that changing the order of keys, changes the scriptpubkey and address
    """

    def __init__(self, threshold: int, pubkeys: List[PublicKey]):
        if threshold < 1 or threshold > len(pubkeys):
            raise InvalidMultisig
        self.threshold = threshold
        self.pubkeys = pubkeys


class P2SHMultisig(P2SH, Multisig):

    def redeem_script(self) -> bytes:
        pubkeys_concat = b''.join(pubkey.pub for pubkey in self.pubkeys)
        return wally.scriptpubkey_multisig_from_bytes(pubkeys_concat, self.threshold, 0)


class P2WSHMultisig(Multisig):

    def witness_script(self) -> bytes:
        pubkeys_concat = b''.join(pubkey.pub for pubkey in self.pubkeys)
        return wally.scriptpubkey_multisig_from_bytes(pubkeys_concat, self.threshold, 0)

    def script_sig(self) -> bytes:
        return b''

    def scriptpubkey(self) -> bytes:
        return wally.witness_program_from_bytes(self.witness_script(), wally.WALLY_SCRIPT_SHA256)


class P2SHP2WSHMultisig(P2SH, P2WSHMultisig):

    def script_sig(self) -> bytes:
        flags = wally.WALLY_SCRIPT_SHA256 | wally.WALLY_SCRIPT_AS_PUSH
        return wally.witness_program_from_bytes(self.witness_script(), flags)

    def redeem_script(self) -> bytes:
        return wally.witness_program_from_bytes(self.witness_script(), wally.WALLY_SCRIPT_SHA256)
