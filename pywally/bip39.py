import wallycore as wally


class Bip39MnemonicError(Exception):
    pass


class InvalidEntropy(Bip39MnemonicError):
    pass


class InvalidMnemonic(Bip39MnemonicError):
    pass


def entropy_to_mnemonic(entropy: bytes) -> str:
    """Convert entropy bytes to a BIP39 english mnemonic

    Entropy can be 16, 20, 24, 28, 32, 36 or 40 bytes"""

    try:
        return wally.bip39_mnemonic_from_bytes(None, entropy)
    except ValueError:
        raise InvalidEntropy


def mnemonic_to_entropy(mnemonic: str) -> bytes:
    """Convert a BIP39 english mnemonic to entropy bytes"""

    try:
        wally.bip39_mnemonic_validate(None, mnemonic)
        buf = bytearray([0] * 40)
        written = wally.bip39_mnemonic_to_bytes(None, mnemonic, buf)
        return buf[:written]
    except ValueError:
        raise InvalidMnemonic


def mnemonic_to_seed(mnemonic: str, passphrase: str = None) -> bytes:
    """Derive a 512-bit seed from a BIP39 english mnemonic and passphrase"""

    try:
        wally.bip39_mnemonic_validate(None, mnemonic)
        _, seed = wally.bip39_mnemonic_to_seed512(mnemonic, passphrase)
        return seed
    except ValueError:
        raise InvalidMnemonic


def is_mnemonic_valid(mnemonic: str) -> bool:
    try:
        wally.bip39_mnemonic_validate(None, mnemonic)
        return True
    except ValueError:
        return False

# TODO: add function to provide better diagnostic of incorrect mnemonics
