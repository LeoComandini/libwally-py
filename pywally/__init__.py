import wallycore as wally


__version__ = '0.0.1dev'


class MainParams(object):
    NAME = 'mainnet'

    P2PKH_PREFIX = wally.WALLY_ADDRESS_VERSION_P2PKH_MAINNET  # 0x00
    P2SH_PREFIX = wally.WALLY_ADDRESS_VERSION_P2SH_MAINNET  # 0x05

    WIF_PREFIX = wally.WALLY_ADDRESS_VERSION_WIF_MAINNET  # 0x80

    BIP32_PUBKEY = wally.BIP32_VER_MAIN_PUBLIC  # 0x0488b21e
    BIP32_PRIVKEY = wally.BIP32_VER_MAIN_PRIVATE  # 0x0488ade4

    BECH32_HRP = 'bc'


class TestNetParams(object):
    NAME = 'testnet'

    P2PKH_PREFIX = wally.WALLY_ADDRESS_VERSION_P2PKH_TESTNET  # 0x6f
    P2SH_PREFIX = wally.WALLY_ADDRESS_VERSION_P2SH_TESTNET  # 0xc4

    WIF_PREFIX = wally.WALLY_ADDRESS_VERSION_WIF_TESTNET  # 0xef

    BIP32_PUBKEY = wally.BIP32_VER_TEST_PUBLIC  # 0x043587cf
    BIP32_PRIVKEY = wally.BIP32_VER_TEST_PRIVATE  # 0x04358394

    BECH32_HRP = 'tb'


class RegTestParams(TestNetParams):
    NAME = 'regtest'

    BECH32_HRP = 'bcrt'


params = TestNetParams()


# This function was inspired by python-bitcoinlib
# https://github.com/petertodd/python-bitcoinlib/
def select_params(name: str):
    """Select the chain parameters to use

    Name is one of 'mainnet' or 'testnet'.

    Default chain is 'testnet'
    """

    global params
    if name == 'mainnet':
        params = MainParams()
    elif name == 'testnet':
        params = TestNetParams()
    elif name == 'regtest':
        params = RegTestParams()
    else:
        raise ValueError('Unknown chain {}'.format(name))
