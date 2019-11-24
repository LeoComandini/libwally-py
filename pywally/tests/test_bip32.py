import unittest
import wallycore as wally

import pywally
from pywally import select_params
from pywally.util import (
    h2b,
    b2h,
    harden,
)
from pywally.bip32 import (
    Xprv,
    Xpub,
    InvalidBip32Path,
)


class TestBip32(unittest.TestCase):

    def test_bip32(self):
        """BIP32 test vector"""
        select_params('mainnet')
        # https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-1
        seed = h2b('000102030405060708090a0b0c0d0e0f')
        M = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
        m = 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
        M_0H = 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw'
        m_0H = 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'
        M_0H_1 = 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ'
        m_0H_1 = 'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs'

        xprv = Xprv.from_seed(seed)
        self.assertEqual(xprv.to_b58(), m)

        xprv = Xprv.from_b58(m)
        xpub = Xpub.from_b58(M)

        self.assertEqual(xprv.to_b58(), m)
        self.assertEqual(xpub.to_b58(), M)

        # byte serialization
        self.assertEqual(Xprv.from_bytes(xprv.to_bytes()).to_b58(), m)
        self.assertEqual(Xpub.from_bytes(xpub.to_bytes()).to_b58(), M)

        # hardened derivation
        path = [harden(0)]
        xprv_0H = xprv.derive(path)
        self.assertRaises(InvalidBip32Path, xpub.derive, path)
        xpub_0H = xprv_0H.to_xpub()

        # note: test vector match only if hash computation is not skipped
        self.assertEqual(xprv_0H.to_b58(), m_0H)
        self.assertEqual(xpub_0H.to_b58(), M_0H)

        # non-hardened derivation
        path = [1]
        xprv_0H_1 = xprv_0H.derive(path)
        xpub_0H_1 = xpub_0H.derive(path)

        self.assertEqual(xprv_0H_1.to_b58(), m_0H_1)
        self.assertEqual(xpub_0H_1.to_b58(), M_0H_1)

        # mixed derivation
        path = [harden(0), 1]
        xprv_0H_1_mixed = xprv.derive(path)
        self.assertRaises(InvalidBip32Path, xpub.derive, path)

        self.assertEqual(xprv_0H_1.to_b58(), m_0H_1)
        select_params('testnet')

    def test_from_mnemonic(self):
        """Xprv from mnemonic"""
        select_params('mainnet')
        # https://github.com/trezor/python-mnemonic/blob/master/vectors.json
        mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        passphrase = 'TREZOR'
        m = 'xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF'

        xprv = Xprv.from_mnemonic(mnemonic, passphrase)
        self.assertEqual(xprv.to_b58(), m)
        select_params('testnet')
