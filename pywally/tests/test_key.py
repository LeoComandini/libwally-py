import unittest
import wallycore as wally

from pywally import select_params
from pywally.util import (
    h2b,
    b2h,
)
from pywally.key import (
    PublicKey,
    PrivateKey,
    InvalidPublicKey,
    InvalidPrivateKey,
    InvalidWIFKey,
    wif_is_compressed,
)


class TestKey(unittest.TestCase):

    def test_valid(self):
        """Valid keys"""
        prv = h2b('00' * 31 + '01')
        privkey = PrivateKey(prv)
        h = h2b('aa' * 32)
        sig = privkey.sign_compact(h)
        pubkey = privkey.pubkey()
        self.assertTrue(privkey.verify_compact(h, sig))
        self.assertTrue(pubkey.verify_compact(h, sig))

    def test_invalid(self):
        """Invalid keys"""
        prv_invalid = h2b('00' * 32)
        self.assertRaises(InvalidPrivateKey, PrivateKey, prv_invalid)

        pub_invalid = h2b('03' * 33)
        self.assertRaises(InvalidPublicKey, PublicKey, pub_invalid)

    def test_uncompressed(self):
        """Uncompressed keys"""
        pub_compressed = h2b('02' * 33)
        pubkey = PublicKey(pub_compressed)
        self.assertTrue(pubkey.is_compressed)
        pub_uncompressed = pubkey.uncompressed_pub()
        pubkey_from_uncompressed = PublicKey(pub_uncompressed)
        self.assertFalse(pubkey_from_uncompressed.is_compressed)
        self.assertEqual(pubkey_from_uncompressed.pub, pub_compressed)

    def test_wif(self):
        """WIF keys"""
        select_params('mainnet')
        # https://en.bitcoin.it/wiki/Wallet_import_format
        prv = h2b('0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d')
        # note that '(un)compressed' refers to the correspoding pubkey, not the
        # wif format, which suggests the opposite
        expected_wif_uncompressed = '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'
        expected_wif_compressed = 'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617'

        privkey = PrivateKey(prv)

        wif_uncompressed = privkey.to_wif(is_compressed=False)
        self.assertFalse(wif_is_compressed(wif_uncompressed))
        self.assertEqual(wif_uncompressed, expected_wif_uncompressed)
        self.assertRaises(InvalidWIFKey, privkey.from_wif, wif_uncompressed, is_compressed=True)
        prv_from_wif = privkey.from_wif(wif_uncompressed, is_compressed=False).prv
        self.assertEqual(prv_from_wif, prv)

        wif_compressed = privkey.to_wif(is_compressed=True)
        self.assertTrue(wif_is_compressed(wif_compressed))
        self.assertEqual(wif_compressed, expected_wif_compressed)
        self.assertRaises(InvalidWIFKey, privkey.from_wif, wif_compressed, is_compressed=False)
        prv_from_wif = privkey.from_wif(wif_compressed, is_compressed=True).prv
        self.assertEqual(prv_from_wif, prv)

        self.assertRaises(InvalidWIFKey, wif_is_compressed, '')
        select_params('testnet')
