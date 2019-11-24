import unittest

from pywally import select_params
from pywally.address import UnknownAddressForScriptpubkey
from pywally.utxo import Utxo
from pywally.util import (
    h2b,
    h2b_rev
)


class TestUtxo(unittest.TestCase):

    def test_utxo(self):
        """Common UTXO types"""
        select_params('mainnet')
        # https://blockstream.info/tx/f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
        # P2PK
        txid = h2b_rev('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16')
        vout = 0
        height = 170
        amount = 1000000000
        scriptpubkey = h2b('4104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414'
                           'e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac')

        utxo = Utxo(txid, vout, height, amount, scriptpubkey)
        # No address for P2PKH
        self.assertRaises(UnknownAddressForScriptpubkey, utxo.address)

        # https://blockstream.info/tx/6f7cf9580f1c2dfb3c4d5d043cdbb128c640e3f20161245aa7372e9666168516
        # P2PKH
        txid = h2b_rev('6f7cf9580f1c2dfb3c4d5d043cdbb128c640e3f20161245aa7372e9666168516')
        vout = 0
        height = 728
        amount = 10000000000
        scriptpubkey = h2b('76a91412ab8dc588ca9d5787dde7eb29569da63c3a238c88ac')
        expected_address = '12higDjoCCNXSA95xZMWUdPvXNmkAduhWv'

        utxo = Utxo(txid, vout, height, amount, scriptpubkey)
        self.assertEqual(utxo.address(), expected_address)

        # https://blockstream.info/tx/40eee3ae1760e3a8532263678cdf64569e6ad06abc133af64f735e52562bccc8
        # P2SH
        txid = h2b_rev('40eee3ae1760e3a8532263678cdf64569e6ad06abc133af64f735e52562bccc8')
        vout = 0
        height = 272295
        amount = 990000
        scriptpubkey = h2b('a914e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a87')
        expected_address = '3P14159f73E4gFr7JterCCQh9QjiTjiZrG'

        utxo = Utxo(txid, vout, height, amount, scriptpubkey)
        self.assertEqual(utxo.address(), expected_address)
        select_params('testnet')
