import unittest

from pywally.bip39 import (
    entropy_to_mnemonic,
    mnemonic_to_entropy,
    mnemonic_to_seed,
    is_mnemonic_valid,
    InvalidEntropy,
    InvalidMnemonic,
)
from pywally.util import h2b


class TestBip39(unittest.TestCase):

    def test_valid(self):
        """Valid mnemonic"""
        # https://github.com/trezor/python-mnemonic/blob/master/vectors.json
        entropy = h2b('00000000000000000000000000000000')
        expected_mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        passphrase = 'TREZOR'
        expected_seed = h2b('c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab'
                            '7c81b2f001698e7463b04')

        mnemonic = entropy_to_mnemonic(entropy)
        self.assertTrue(is_mnemonic_valid(mnemonic))
        self.assertEqual(expected_mnemonic, mnemonic)
        self.assertEqual(entropy, mnemonic_to_entropy(mnemonic))
        seed = mnemonic_to_seed(mnemonic, passphrase)
        self.assertEqual(expected_seed, seed)

    def test_invalid(self):
        """"Invalid mnemonic"""
        # Invalid length
        entropy = h2b('0000000000000000000000000000000000')
        self.assertRaises(InvalidEntropy, entropy_to_mnemonic, entropy)

        # Bad checksum mnemonic
        mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon'
        self.assertFalse(is_mnemonic_valid(mnemonic))
        self.assertRaises(InvalidMnemonic, mnemonic_to_entropy, mnemonic)
        self.assertRaises(InvalidMnemonic, mnemonic_to_seed, mnemonic)
