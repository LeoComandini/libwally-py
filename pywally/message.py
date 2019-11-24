import wallycore as wally

import base64

from pywally.key import (
    PublicKey,
    PrivateKey,
)
from pywally.output import P2PKH


class InvalidRecoverableSignature(Exception):
    pass


def sign_message(privkey_wif: str, message: str) -> str:
    """Sign a message with a private key of a P2PKH address

    'privkey_wif' must be in WIF format, message and signature are formatted
    as 'signmessage' RPC does.
    """

    privkey = PrivateKey.from_wif(privkey_wif)
    h = wally.format_bitcoin_message(message.encode('ascii'), wally.BITCOIN_MESSAGE_FLAG_HASH)
    flags = wally.EC_FLAG_ECDSA | wally.EC_FLAG_RECOVERABLE
    recoverable_signature = wally.ec_sig_from_bytes(privkey.prv, h, flags)
    return base64.b64encode(recoverable_signature)


def verify_message(address: str, signature: str, message: str) -> str:
    """Sign a message with a private key of a P2PKH address

    'signature' must be a recoverable signature in base64.
    """

    h = wally.format_bitcoin_message(message.encode('ascii'), wally.BITCOIN_MESSAGE_FLAG_HASH)
    recoverable_sig = base64.b64decode(signature)
    try:
        pub = wally.ec_sig_to_public_key(h, recoverable_sig)
    except ValueError:
        raise InvalidRecoverableSignature

    return P2PKH(PublicKey(pub)).address() == address
