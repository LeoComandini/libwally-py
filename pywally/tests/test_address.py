import unittest

from pywally.address import (
    address_to_scriptpubkey,
    scriptpubkey_to_address,
    InvalidAddress,
    UnknownAddressForScriptpubkey,
)
from pywally.util import h2b


class TestAddress(unittest.TestCase):

    def test_p2pkh(self):
        """P2PKH address"""
        address = 'mfWxJ45yp2SFn7UciZyNpvDKrzbhyfKrY8'
        scriptpubkey = h2b('76a914000000000000000000000000000000000000000088ac')

        self.assertEqual(address_to_scriptpubkey(address), scriptpubkey)
        self.assertEqual(scriptpubkey_to_address(scriptpubkey), address)

    def test_p2sh(self):
        """P2SH address"""
        address = '2MsFDzHRUAMpjHxKyoEHU3aMCMsVtMqs1PV'
        scriptpubkey = h2b('a914000000000000000000000000000000000000000087')

        self.assertEqual(address_to_scriptpubkey(address), scriptpubkey)
        self.assertEqual(scriptpubkey_to_address(scriptpubkey), address)

    def test_p2wpkh(self):
        """P2WPKH address"""
        address = 'tb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0l98cr'
        scriptpubkey = h2b('00140000000000000000000000000000000000000000')

        self.assertEqual(address_to_scriptpubkey(address), scriptpubkey)
        self.assertEqual(scriptpubkey_to_address(scriptpubkey), address)

    def test_p2wsh(self):
        """P2WSH address"""
        address = 'tb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsf778ym'
        scriptpubkey = h2b('00200000000000000000000000000000000000000000000000000000000000000001')

        self.assertEqual(address_to_scriptpubkey(address), scriptpubkey)
        self.assertEqual(scriptpubkey_to_address(scriptpubkey), address)

    def test_unknown(self):
        """Unknown address"""
        address = 'abcd'
        scriptpubkey = h2b('00')

        self.assertRaises(InvalidAddress, address_to_scriptpubkey, address)
        self.assertRaises(UnknownAddressForScriptpubkey, scriptpubkey_to_address, scriptpubkey)
