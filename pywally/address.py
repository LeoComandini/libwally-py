import wallycore as wally

import pywally


class AddressError(Exception):
    pass


class UnknownAddressForScriptpubkey(AddressError):
    pass


class InvalidAddress(AddressError):
    pass


NETWORKS = {
    'mainnet': wally.WALLY_NETWORK_BITCOIN_MAINNET,
    'testnet': wally.WALLY_NETWORK_BITCOIN_TESTNET,
    'regtest': wally.WALLY_NETWORK_BITCOIN_TESTNET,
}


def scriptpubkey_to_address(scriptpubkey: bytes) -> str:
    type_ = wally.scriptpubkey_get_type(scriptpubkey)
    if type_ == wally.WALLY_SCRIPT_TYPE_P2PKH or type_ == wally.WALLY_SCRIPT_TYPE_P2SH:
        network = NETWORKS[pywally.params.NAME]
        return wally.scriptpubkey_to_address(scriptpubkey, network)
    elif type_ == wally.WALLY_SCRIPT_TYPE_P2WPKH or type_ == wally.WALLY_SCRIPT_TYPE_P2WSH:
        return wally.addr_segwit_from_bytes(scriptpubkey, pywally.params.BECH32_HRP, 0)
    else:
        raise UnknownAddressForScriptpubkey


def address_to_scriptpubkey(address: str) -> bytes:
    try:
        network = NETWORKS[pywally.params.NAME]
        return wally.address_to_scriptpubkey(address, network)
    except ValueError:
        pass

    try:
        return wally.addr_segwit_to_bytes(address, pywally.params.BECH32_HRP, 0)
    except ValueError:
        pass

    raise InvalidAddress
