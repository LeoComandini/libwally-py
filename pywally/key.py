import wallycore as wally

import pywally


class ECKeyError(Exception):
    pass


class InvalidPrivateKey(ECKeyError):
    pass


class InvalidPublicKey(ECKeyError):
    pass


class InvalidWIFKey(InvalidPrivateKey):
    """May be invalid base58, invalid prefix, mismatching network, invalid
    private key, mismatching 'is_compressed' value
    """

    pass


class PublicKey(object):
    """secp256k1 public key"""

    def __init__(self, pub: bytes):
        try:
            wally.ec_public_key_verify(pub)
        except ValueError:
            raise InvalidPublicKey

        self.is_compressed = len(pub) == 33
        if not self.is_compressed:
            # wally guarantees that is a 65 bytes valid key
            self.pub = (b'\x03' if pub[-1] % 2 else b'\x02') + pub[1:33]
        else:
            self.pub = pub

    def verify_compact(self, h: bytes, sig: bytes) -> bool:
        """Verify a compact ECDSA signature for (hashed) message h"""

        try:
            wally.ec_sig_verify(self.pub, h, wally.EC_FLAG_ECDSA, sig)
        except ValueError:
            return False
        return True

    def uncompressed_pub(self) -> bytes:
        return wally.ec_public_key_decompress(self.pub)


class PrivateKey(PublicKey):
    """secp256k1 private key"""

    def __init__(self, prv: bytes):
        try:
            self.pub = wally.ec_public_key_from_private_key(prv)
        except ValueError:
            raise InvalidPrivateKey

        self.prv = prv

    def sign_compact(self, h: bytes) -> bytes:
        """Produce a compact ECDSA signature for (hashed) message h"""

        return wally.ec_sig_from_bytes(self.prv, h, wally.EC_FLAG_ECDSA | wally.EC_FLAG_GRIND_R)

    def to_wif(self, is_compressed: bool = True) -> str:
        """Convert to Wallet Import Format"""

        flags = wally.WALLY_WIF_FLAG_COMPRESSED if is_compressed else wally.WALLY_WIF_FLAG_UNCOMPRESSED
        return wally.wif_from_bytes(self.prv, pywally.params.WIF_PREFIX, flags)

    @classmethod
    def from_wif(cls, wif: str, is_compressed: bool = True):
        """Private key from a string in Wallet Import Format

        You may use 'wif_is_compressed(wif)' for 'is_compressed'
        """

        flags = wally.WALLY_WIF_FLAG_COMPRESSED if is_compressed else wally.WALLY_WIF_FLAG_UNCOMPRESSED
        try:
            return cls(wally.wif_to_bytes(wif, pywally.params.WIF_PREFIX, flags))
        except ValueError:
            raise InvalidWIFKey

    def pubkey(self):
        return PublicKey(self.pub)


def wif_is_compressed(wif: str) -> bool:
    try:
        return not wally.wif_is_uncompressed(wif)
    except ValueError:
        raise InvalidWIFKey
