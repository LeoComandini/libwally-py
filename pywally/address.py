import wallycore as wally

import pywally


class AddressError(Exception):
    pass


class UnknownAddressForScriptpubkey(AddressError):
    pass


class InvalidAddress(AddressError):
    pass


def scriptpubkey_to_address(scriptpubkey: bytes) -> str:
    type_ = wally.scriptpubkey_get_type(scriptpubkey)
    if type_ == wally.WALLY_SCRIPT_TYPE_P2PKH:
        pubkeyhash = scriptpubkey[3:23]
        prefix = bytearray([pywally.params.P2PKH_PREFIX])
        return wally.base58check_from_bytes(prefix + pubkeyhash)
    elif type_ == wally.WALLY_SCRIPT_TYPE_P2SH:
        scripthash = scriptpubkey[2:22]
        prefix = bytearray([pywally.params.P2SH_PREFIX])
        return wally.base58check_from_bytes(prefix + scripthash)
    elif type_ == wally.WALLY_SCRIPT_TYPE_P2WPKH or \
            type_ == wally.WALLY_SCRIPT_TYPE_P2WSH:
        return wally.addr_segwit_from_bytes(scriptpubkey, pywally.params.BECH32_HRP, 0)
    else:
        raise UnknownAddressForScriptpubkey


def address_to_scriptpubkey(address: str) -> bytes:
    try:
        # flags = {
        #     'mainnet': wally.WALLY_NETWORK_BITCOIN_MAINNET,
        #     'testnet': wally.WALLY_NETWORK_BITCOIN_TESTNET,
        # }[pywally.params.NAME]
        # return wally.address_to_scriptpubkey(address, flags)
        decoded = wally.base58check_to_bytes(address)
        if len(decoded) != 21:
            raise InvalidAddress('Unexpected length')
        if decoded[0] == pywally.params.P2PKH_PREFIX:
            return wally.scriptpubkey_p2pkh_from_bytes(decoded[1:21], 0)
        elif decoded[0] == pywally.params.P2SH_PREFIX:
            return wally.scriptpubkey_p2sh_from_bytes(decoded[1:21], 0)
        else:
            raise InvalidAddress('Unexpected prefix')
    except ValueError:
        pass

    try:
        return wally.addr_segwit_to_bytes(address, pywally.params.BECH32_HRP, 0)
    except ValueError:
        pass

    raise InvalidAddress
