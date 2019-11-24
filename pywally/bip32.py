import wallycore as wally

from typing import List

import pywally
from pywally.key import (
    PrivateKey,
    PublicKey,
)
from pywally.bip39 import mnemonic_to_seed


class Bip32KeyError(Exception):
    pass


class InvalidiBip32Key(Bip32KeyError):
    pass


class InvalidBip32Path(Bip32KeyError):
    pass


class UnexpectedBip32Version(Bip32KeyError):
    pass


class Xpub(object):
    """Extended pubkey"""

    bip32_flag = wally.BIP32_FLAG_KEY_PUBLIC

    def __init__(self, extkey):
        # TODO: make sure it is a extkey
        self.extkey = extkey

    def _bip32_version(self) -> int:
        return pywally.params.BIP32_PUBKEY

    @classmethod
    def from_b58(cls, b58: str):
        try:
            extkey = wally.bip32_key_from_base58(b58)
        except ValueError:
            raise InvalidBip32Key
        self = cls(extkey)
        if self._bip32_version() != self.version():
            raise UnexpectedBip32Version
        return self

    @classmethod
    def from_bytes(cls, b: bytes):
        try:
            extkey = wally.bip32_key_unserialize(b)
        except ValueError:
            raise InvalidBip32Key
        self = cls(extkey)
        if self._bip32_version() != self.version():
            raise UnexpectedBip32Version
        return self

    def version(self) -> int:
        return wally.bip32_key_get_version(self.extkey)

    def pubkey(self) -> bytes:
        return PublicKey(wally.bip32_key_get_pub_key(self.extkey))

    def to_b58(self) -> str:
        return wally.bip32_key_to_base58(self.extkey, self.bip32_flag)

    def to_bytes(self) -> bytes:
        return wally.bip32_key_serialize(self.extkey, self.bip32_flag)

    def derive(self, path: List[int]):
        # TODO: investigate if it's worth to skip hash, for now remove so we
        #       can use bip32 test vectors
        # flags |= wally.BIP32_FLAG_SKIP_HASH
        flags = self.bip32_flag
        try:
            derived = wally.bip32_key_from_parent_path(self.extkey, path, flags)
        except ValueError:
            raise InvalidBip32Path
        return self.__class__(derived)


class Xprv(Xpub):
    """Extended private key"""

    bip32_flag = wally.BIP32_FLAG_KEY_PRIVATE

    def _bip32_version(self) -> int:
        return pywally.params.BIP32_PRIVKEY

    @classmethod
    def from_seed(cls, seed: bytes):
        """Create a xprv from a 128, 256, or 512 bit seed"""

        extkey = wally.bip32_key_from_seed(seed, pywally.params.BIP32_PRIVKEY, 0)
        return cls(extkey)

    @classmethod
    def from_mnemonic(cls, mnemonic: str, passphrase: str = None):
        """Create a xprv from a bip39 english mnemonic"""

        seed = mnemonic_to_seed(mnemonic, passphrase)
        return cls.from_seed(seed)

    def privkey(self) -> PrivateKey:
        return PrivateKey(wally.bip32_key_get_priv_key(self.extkey))

    def to_xpub(self) -> Xpub:
        # TODO: use bip32_key_strip_private_key
        xpub_bytes = wally.bip32_key_serialize(self.extkey, wally.BIP32_FLAG_KEY_PUBLIC)
        return Xpub.from_bytes(xpub_bytes)
