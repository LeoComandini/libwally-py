import unittest

from pywally import select_params
from pywally.key import (
    PrivateKey,
)
from pywally.output import (
    P2PKH,
    P2SHMultisig,
    P2WPKH,
    P2SHP2WPKH,
    P2WSHMultisig,
    P2SHP2WSHMultisig,
)
from pywally.signer import (
    SignerP2PKH,
    SignerP2SHMultisig,
    SignerP2WPKH,
    SignerP2SHP2WPKH,
    SignerP2WSHMultisig,
    SignerP2SHP2WSHMultisig,
)
from pywally.transaction import (
    Transaction,
    InvalidTransaction,
    InvalidIndexError,
)
from pywally.util import (
    h2b,
    h2b_rev,
    b2h_rev,
)
from pywally.utxo import Utxo


class TestTransaction(unittest.TestCase):

    def test_pre_segwit(self):
        """Parsing a pre-segwit transaction"""
        # from https://blockstream.info/api/tx/f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16/hex
        txhex = \
            '0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25f' \
            'df3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00' \
            '000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5' \
            'c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf97444' \
            '64f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000'
        expected_inputs_to_dict = [
            {
                'txid': h2b_rev('0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9'),
                'vout': 0,
                'sequence': 0xffffffff,
                'scriptsig': h2b('47304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acd'
                                 'd12909d831cc56cbbac4622082221a8768d1d0901'),
            },
        ]
        expected_outputs_to_dict = [
            {
                'scriptpubkey': h2b('4104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b730'
                                    '3b8a0626f1baded5c72a704f7e6cd84cac'),
                'satoshi': 1000000000,
            },
            {
                'scriptpubkey': h2b('410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa'
                                    '9b8b64f9d4c03f999b8643f656b412a3ac'),
                'satoshi': 4000000000,
            },
        ]
        expected_txid = h2b_rev('f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16')
        expected_size = 275
        expected_weight = 1100
        expected_version = 1
        expected_nlocktime = 0

        # (de)serialization
        txbytes = h2b(txhex)
        self.assertEqual(Transaction.from_hex(txhex).to_hex(), txhex)
        self.assertEqual(Transaction.from_bytes(txbytes).to_bytes(), txbytes)

        self.assertRaises(InvalidTransaction, Transaction.from_hex, '00')
        self.assertRaises(InvalidTransaction, Transaction.from_bytes, b'\x00')

        tx = Transaction.from_hex(txhex)

        self.assertEqual(expected_version, tx.version())
        self.assertEqual(expected_nlocktime, tx.nlocktime())

        self.assertEqual(len(expected_inputs_to_dict), tx.num_inputs())
        self.assertEqual(len(expected_outputs_to_dict), tx.num_outputs())

        for i in range(tx.num_inputs()):
            self.assertEqual(expected_inputs_to_dict[i], tx.input_to_dict(i))

        for i in range(tx.num_outputs()):
            self.assertEqual(expected_outputs_to_dict[i], tx.output_to_dict(i))

        self.assertRaises(InvalidIndexError, tx.input_to_dict, tx.num_inputs())
        self.assertRaises(InvalidIndexError, tx.output_to_dict, tx.num_outputs())

        self.assertEqual(expected_txid, tx.txid())
        self.assertEqual(expected_txid, tx.hash())
        self.assertEqual(expected_size, tx.size())
        self.assertEqual(expected_size, tx.vsize())
        self.assertEqual(expected_weight, tx.weight())

    def test_e2e_p2pkh(self):
        """Simulated End-To-End P2PKH spending"""

        # keys
        prv = b'\x00' * 31 + b'\x01'
        privkey = PrivateKey(prv)
        pubkey = privkey.pubkey()

        # address
        output = P2PKH(pubkey)
        self.assertEqual(output.address(), 'mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r')

        # obtain utxo data from node (these were obtained from a regtest)
        txid = h2b_rev('a841e4f19aadc7380ff9c0275a725b93303a934a4290213315ce2e82abedc67d')
        vout = 1
        height = 150
        amount = 100000000
        scriptpubkey = h2b('76a914751e76e8199196d454941c45d1b3a323f1433bd688ac')

        self.assertEqual(scriptpubkey, output.scriptpubkey())
        utxo = Utxo(txid, vout, height, amount, scriptpubkey)
        self.assertEqual(output.address(), utxo.address())

        # create the signer
        signer = SignerP2PKH(PrivateKey(prv))
        self.assertEqual(signer.address(), output.address())
        self.assertEqual(signer.scriptpubkey(), scriptpubkey)
        self.assertEqual(signer.address(), utxo.address())

        # create a transaction spending utxo to the same address
        fee = 1000
        amount_send = amount - fee
        scriptpubkey_send = signer.scriptpubkey()

        tx = Transaction()
        tx.add_input(utxo.txid, utxo.vout, 0xffffffff)
        tx.add_output(scriptpubkey_send, amount_send)
        expected_unsigned_tx = \
            '02000000017dc6edab822ece15332190424a933a30935b725a27c0f90f38c7ad9af1e441a80100000000ffffffff0118ddf505000000001976a914751e76' \
            'e8199196d454941c45d1b3a323f1433bd688ac00000000'
        self.assertEqual(expected_unsigned_tx, tx.to_hex())

        # sign transaction
        tx.sign(0, signer)
        expected_signed_tx = \
            '02000000017dc6edab822ece15332190424a933a30935b725a27c0f90f38c7ad9af1e441a8010000006a4730440220520a1c1da7133ee956097b30e6e216' \
            'c4e9880223fd20f1b2a04aa1c3f0234991022022c1b64687b451b2955e22a9d5ec5b9c490a2d2f2b02662f9e00592b767ca8ba01210279be667ef9dcbbac' \
            '55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ffffffff0118ddf505000000001976a914751e76e8199196d454941c45d1b3a323f1433bd688' \
            'ac00000000'
        self.assertEqual(expected_signed_tx, tx.to_hex())

    def test_e2e_p2sh_multisig(self):
        """Simulated End-To-End P2SH-multisig-2of3 spending"""

        # keys
        threshold = 2
        prv1 = b'\x00' * 31 + b'\x01'
        prv2 = b'\x00' * 31 + b'\x02'
        prv3 = b'\x00' * 31 + b'\x03'

        all_privkeys = [PrivateKey(prv) for prv in [prv1, prv2, prv3]]
        pubkeys = [privkey.pubkey() for privkey in all_privkeys]

        # address
        output = P2SHMultisig(threshold, pubkeys)
        self.assertEqual(output.address(), '2MuFU6ZyBLtDNadMA6RnwJdXGWUSUaoKLeS')

        # obtain utxo data from node (these were obtained from a regtest)
        txid = h2b_rev('bbce7c8b6d31b5d0642a6a32324db6373cd8803baace9a8d8cfd71c62013f929')
        vout = 1
        height = 150
        amount = 100000000
        scriptpubkey = h2b('a91415fc0754e73eb85d1cbce08786fadb7320ecb8dc87')

        self.assertEqual(output.scriptpubkey(), scriptpubkey)
        utxo = Utxo(txid, vout, height, amount, scriptpubkey)
        self.assertEqual(output.address(), utxo.address())

        # create the signer
        keys = all_privkeys[:2] + pubkeys[2:]
        signer = SignerP2SHMultisig(threshold, keys)
        self.assertEqual(signer.address(), output.address())
        self.assertEqual(signer.scriptpubkey(), scriptpubkey)
        self.assertEqual(signer.address(), utxo.address())

        # create a transaction spending utxo to the same address
        fee = 1000
        amount_send = amount - fee
        scriptpubkey_send = signer.scriptpubkey()

        tx = Transaction()
        tx.add_input(utxo.txid, utxo.vout, 0xffffffff)
        tx.add_output(scriptpubkey_send, amount_send)
        expected_unsigned_tx = \
            '020000000129f91320c671fd8c8d9aceaa3b80d83c37b64d32326a2a64d0b5316d8b7ccebb0100000000ffffffff0118ddf5050000000017a91415fc075' \
            '4e73eb85d1cbce08786fadb7320ecb8dc8700000000'
        self.assertEqual(expected_unsigned_tx, tx.to_hex())

        # sign transaction
        tx.sign(0, signer)
        expected_signed_tx = \
            '020000000129f91320c671fd8c8d9aceaa3b80d83c37b64d32326a2a64d0b5316d8b7ccebb01000000fc0047304402205b1d5b004a9b26c418520f157fe' \
            'e65c23fbbbf658a0373abd9031dca2053ddd802204c5534b53c62ba3fc1261693c89c8be69329848d896b2b907edf0e6f428964bd0147304402207fab57' \
            '5c09044046585c8ed43837c371c126e3561443a2ec6e1091ad33a8c129022015acff1a2be06e955c71f573d769576ed49361462a7a0a87e622b6698962e' \
            '403014c6952210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c6047f9441ed7d6d3045406e95c07cd85c778e4b' \
            '8cef3ca7abac09b95c709ee52102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f953aeffffffff0118ddf505000000001' \
            '7a91415fc0754e73eb85d1cbce08786fadb7320ecb8dc8700000000'
        self.assertEqual(expected_signed_tx, tx.to_hex())

        # other set of signers can sign too (eg 1st and 3rd)
        keys = all_privkeys[:1] + pubkeys[1:2] + all_privkeys[-1:]
        signer_1_3 = SignerP2SHMultisig(threshold, keys)
        # override signature
        tx.sign(0, signer_1_3)
        expected_signed_tx_1_3 = \
            '020000000129f91320c671fd8c8d9aceaa3b80d83c37b64d32326a2a64d0b5316d8b7ccebb01000000fc0047304402205b1d5b004a9b26c418520f157fe' \
            'e65c23fbbbf658a0373abd9031dca2053ddd802204c5534b53c62ba3fc1261693c89c8be69329848d896b2b907edf0e6f428964bd01473044022048909e' \
            '2048a936a04e24c021328e303c5f95fd73e0fb5293181dffcfdda333eb022056ef026534e67a944b0f09f3c66794cec6c32d0527ff5ed93906e06c8ec3f' \
            '31d014c6952210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c6047f9441ed7d6d3045406e95c07cd85c778e4b' \
            '8cef3ca7abac09b95c709ee52102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f953aeffffffff0118ddf505000000001' \
            '7a91415fc0754e73eb85d1cbce08786fadb7320ecb8dc8700000000'
        self.assertEqual(expected_signed_tx_1_3, tx.to_hex())

    def test_e2e_p2wpkh(self):
        """Simulated End-To-End P2WPKH spending"""

        select_params('regtest')
        # keys
        prv = b'\x00' * 31 + b'\x01'
        privkey = PrivateKey(prv)
        pubkey = privkey.pubkey()

        # address
        output = P2WPKH(pubkey)
        self.assertEqual(output.address(), 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080')

        # obtain utxo data from node (these were obtained from a regtest)
        txid = h2b_rev('3bceceb578aa8134a7e687e75e1aadaac68e8e3f9a2b9e11bff2637eb22cc0ee')
        vout = 1
        height = 150
        amount = 100000000
        scriptpubkey = h2b('0014751e76e8199196d454941c45d1b3a323f1433bd6')

        self.assertEqual(scriptpubkey, output.scriptpubkey())
        utxo = Utxo(txid, vout, height, amount, scriptpubkey)
        self.assertEqual(output.address(), utxo.address())

        # create the signer
        signer = SignerP2WPKH(PrivateKey(prv), amount)
        self.assertEqual(signer.address(), output.address())
        self.assertEqual(signer.scriptpubkey(), scriptpubkey)
        self.assertEqual(signer.address(), utxo.address())

        # create a transaction spending utxo to the same address
        fee = 1000
        amount_send = amount - fee
        scriptpubkey_send = signer.scriptpubkey()

        tx = Transaction()
        tx.add_input(utxo.txid, utxo.vout, 0xffffffff)
        tx.add_output(scriptpubkey_send, amount_send)
        expected_unsigned_tx = \
            '0200000001eec02cb27e63f2bf119e2b9a3f8e8ec6aaad1a5ee787e6a73481aa78b5cece3b0100000000ffffffff0118ddf50500000000160014751e76e' \
            '8199196d454941c45d1b3a323f1433bd600000000'
        self.assertEqual(expected_unsigned_tx, tx.to_hex())

        # sign transaction
        tx.sign(0, signer)
        expected_signed_tx = \
            '02000000000101eec02cb27e63f2bf119e2b9a3f8e8ec6aaad1a5ee787e6a73481aa78b5cece3b0100000000ffffffff0118ddf50500000000160014751' \
            'e76e8199196d454941c45d1b3a323f1433bd60247304402200c83fde88be21526dd3504cbc091e39a8e20c61f8c8660e9aa4b164c68c7f6d002207e6376' \
            '51e95eba9efcddc9419bc80815cf188a3800cea12e4cdc14bb8139158801210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f' \
            '8179800000000'
        self.assertEqual(expected_signed_tx, tx.to_hex(use_witness=True))
        select_params('testnet')

    def test_e2e_p2sh_p2wpkh(self):
        """Simulated End-To-End P2SH-P2WPKH spending"""

        select_params('regtest')
        # keys
        prv = b'\x00' * 31 + b'\x01'
        privkey = PrivateKey(prv)
        pubkey = privkey.pubkey()

        # address
        output = P2SHP2WPKH(pubkey)
        self.assertEqual(output.address(), '2NAUYAHhujozruyzpsFRP63mbrdaU5wnEpN')

        # obtain utxo data from node (these were obtained from a regtest)
        txid = h2b_rev('b25cce9848fa30123e253759b7e667efb6c093d520ef8957b0bafa7e12d62485')
        vout = 0
        height = 150
        amount = 100000000
        scriptpubkey = h2b('a914bcfeb728b584253d5f3f70bcb780e9ef218a68f487')

        self.assertEqual(scriptpubkey, output.scriptpubkey())
        utxo = Utxo(txid, vout, height, amount, scriptpubkey)
        self.assertEqual(output.address(), utxo.address())

        # create the signer
        signer = SignerP2SHP2WPKH(PrivateKey(prv), amount)
        self.assertEqual(signer.address(), output.address())
        self.assertEqual(signer.scriptpubkey(), scriptpubkey)
        self.assertEqual(signer.address(), utxo.address())

        # create a transaction spending utxo to the same address
        fee = 1000
        amount_send = amount - fee
        scriptpubkey_send = signer.scriptpubkey()

        tx = Transaction()
        tx.add_input(utxo.txid, utxo.vout, 0xffffffff)
        tx.add_output(scriptpubkey_send, amount_send)
        expected_unsigned_tx = \
            '02000000018524d6127efabab05789ef20d593c0b6ef67e6b75937253e1230fa4898ce5cb20000000000ffffffff0118ddf5050000000017a914bcfeb72' \
            '8b584253d5f3f70bcb780e9ef218a68f48700000000'
        self.assertEqual(expected_unsigned_tx, tx.to_hex())

        # sign transaction
        tx.sign(0, signer)
        expected_signed_tx = \
            '020000000001018524d6127efabab05789ef20d593c0b6ef67e6b75937253e1230fa4898ce5cb20000000017160014751e76e8199196d454941c45d1b3a' \
            '323f1433bd6ffffffff0118ddf5050000000017a914bcfeb728b584253d5f3f70bcb780e9ef218a68f4870247304402201ddc9c9b627e5da2bd81228751' \
            '34f46dff2713d5d310850f468f6b98ead3ee2902206b2ea4e50d17c803eb0b6edb79de8b4a0e1c0c1a5c4f9feabefe2ab9b6dfd26401210279be667ef9d' \
            'cbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000'
        self.assertEqual(expected_signed_tx, tx.to_hex(use_witness=True))
        select_params('testnet')

    def test_e2e_p2wsh_multisig(self):
        """Simulated End-To-End P2WSH-multisig-2of3 spending"""

        select_params('regtest')
        # keys
        threshold = 2
        prv1 = b'\x00' * 31 + b'\x01'
        prv2 = b'\x00' * 31 + b'\x02'
        prv3 = b'\x00' * 31 + b'\x03'

        all_privkeys = [PrivateKey(prv) for prv in [prv1, prv2, prv3]]
        pubkeys = [privkey.pubkey() for privkey in all_privkeys]

        # address
        output = P2WSHMultisig(threshold, pubkeys)
        self.assertEqual(output.address(), 'bcrt1qztp0l0rwc8846ardl02fkyrrx43p96j47scz8l7qz3vnfteqc4eq3cu8hw')

        # obtain utxo data from node (these were obtained from a regtest)
        txid = h2b_rev('3367a61a77802774c76afcdb5e220013a541cc55fb82f3903ef7a077b718682b')
        vout = 1
        height = 150
        amount = 100000000
        scriptpubkey = h2b('002012c2ffbc6ec1cf5d746dfbd49b1063356212ea55f43023ffc0145934af20c572')

        self.assertEqual(output.scriptpubkey(), scriptpubkey)
        utxo = Utxo(txid, vout, height, amount, scriptpubkey)
        self.assertEqual(output.address(), utxo.address())

        # create the signer
        keys = all_privkeys[:2] + pubkeys[2:]
        signer = SignerP2WSHMultisig(threshold, keys, amount)
        self.assertEqual(signer.address(), output.address())
        self.assertEqual(signer.scriptpubkey(), scriptpubkey)
        self.assertEqual(signer.address(), utxo.address())

        # create a transaction spending utxo to the same address
        fee = 1000
        amount_send = amount - fee
        scriptpubkey_send = signer.scriptpubkey()

        tx = Transaction()
        tx.add_input(utxo.txid, utxo.vout, 0xffffffff)
        tx.add_output(scriptpubkey_send, amount_send)
        expected_unsigned_tx = \
            '02000000012b6818b777a0f73e90f382fb55cc41a51300225edbfc6ac7742780771aa667330100000000ffffffff0118ddf5050000000022002012c2ffb' \
            'c6ec1cf5d746dfbd49b1063356212ea55f43023ffc0145934af20c57200000000'
        self.assertEqual(expected_unsigned_tx, tx.to_hex())

        # sign transaction
        tx.sign(0, signer)
        expected_signed_tx = \
            '020000000001012b6818b777a0f73e90f382fb55cc41a51300225edbfc6ac7742780771aa667330100000000ffffffff0118ddf5050000000022002012c' \
            '2ffbc6ec1cf5d746dfbd49b1063356212ea55f43023ffc0145934af20c57204004730440220469b44477440b64a49500eb263ebdacd6532a2a802efc151' \
            'b3fe1319d705bf88022010fb1ade40a9f9ad868914a92f890b2e9efd2401a06245d239d1c4a6a7d2c2ac0147304402204b5372642f89dbe6ea90ec48e99' \
            '60a261420af6c474158ae380f2b7ad73797e00220204e3fa572f6a72bd7ce78509c51ba5ace2637644ee079651d6dc5ff9752abc1016952210279be667e' \
            'f9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee' \
            '52102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f953ae00000000'
        self.assertEqual(expected_signed_tx, tx.to_hex(use_witness=True))

        # other set of signers can sign too (eg 1st and 3rd)
        keys = all_privkeys[:1] + pubkeys[1:2] + all_privkeys[-1:]
        signer_1_3 = SignerP2WSHMultisig(threshold, keys, amount)
        # override signature
        tx.sign(0, signer_1_3)
        expected_signed_tx_1_3 = \
            '020000000001012b6818b777a0f73e90f382fb55cc41a51300225edbfc6ac7742780771aa667330100000000ffffffff0118ddf5050000000022002012c' \
            '2ffbc6ec1cf5d746dfbd49b1063356212ea55f43023ffc0145934af20c57204004730440220469b44477440b64a49500eb263ebdacd6532a2a802efc151' \
            'b3fe1319d705bf88022010fb1ade40a9f9ad868914a92f890b2e9efd2401a06245d239d1c4a6a7d2c2ac01473044022041b9e84820750e9765b5e7a203f' \
            '558f757a9f5ba8b79a1f66141f870316a0fe1022035d7f443daaf6a2729bf714719b1b0bcb63980d231c4e5a4ed0fd956cfb92747016952210279be667e' \
            'f9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee' \
            '52102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f953ae00000000'
        self.assertEqual(expected_signed_tx_1_3, tx.to_hex(use_witness=True))
        select_params('testnet')

    def test_e2e_p2shp2wsh_multisig(self):
        """Simulated End-To-End P2SH-P2WSH-multisig-2of3 spending"""

        select_params('regtest')
        # keys
        threshold = 2
        prv1 = b'\x00' * 31 + b'\x01'
        prv2 = b'\x00' * 31 + b'\x02'
        prv3 = b'\x00' * 31 + b'\x03'

        all_privkeys = [PrivateKey(prv) for prv in [prv1, prv2, prv3]]
        pubkeys = [privkey.pubkey() for privkey in all_privkeys]

        # address
        output = P2SHP2WSHMultisig(threshold, pubkeys)
        self.assertEqual(output.address(), '2NBbyaKyqn2AhMzSnQZrVPAW46KW1it9v7r')

        # obtain utxo data from node (these were obtained from a regtest)
        txid = h2b_rev('cc8c5def8f258a7054e606ba53b20244c412632528c742db42b3f70de11914e3')
        vout = 0
        height = 150
        amount = 100000000
        scriptpubkey = h2b('a914c95ef7c9117a56571c2ddc44e5fd8ba29d45989387')

        self.assertEqual(output.scriptpubkey(), scriptpubkey)
        utxo = Utxo(txid, vout, height, amount, scriptpubkey)
        self.assertEqual(output.address(), utxo.address())

        # create the signer
        keys = all_privkeys[:2] + pubkeys[2:]
        signer = SignerP2SHP2WSHMultisig(threshold, keys, amount)
        self.assertEqual(signer.address(), output.address())
        self.assertEqual(signer.scriptpubkey(), scriptpubkey)
        self.assertEqual(signer.address(), utxo.address())

        # create a transaction spending utxo to the same address
        fee = 1000
        amount_send = amount - fee
        scriptpubkey_send = signer.scriptpubkey()

        tx = Transaction()
        tx.add_input(utxo.txid, utxo.vout, 0xffffffff)
        tx.add_output(scriptpubkey_send, amount_send)
        expected_unsigned_tx = \
            '0200000001e31419e10df7b342db42c728256312c44402b253ba06e654708a258fef5d8ccc0000000000ffffffff0118ddf5050000000017a914c95ef7c' \
            '9117a56571c2ddc44e5fd8ba29d4598938700000000'
        self.assertEqual(expected_unsigned_tx, tx.to_hex())

        # sign transaction
        tx.sign(0, signer)
        expected_signed_tx = \
            '02000000000101e31419e10df7b342db42c728256312c44402b253ba06e654708a258fef5d8ccc000000002322002012c2ffbc6ec1cf5d746dfbd49b106' \
            '3356212ea55f43023ffc0145934af20c572ffffffff0118ddf5050000000017a914c95ef7c9117a56571c2ddc44e5fd8ba29d4598938704004730440220' \
            '5cb17ae6db374ed3df9b14829139f04bc6cd9e4ea06e3acb1e1329f15f19e75502207fd2c1a08b0f28c34b60fb8abee231553c2e98d4c5fab56557ad9f9' \
            '6a86a45b20147304402206e8c36b552ede9facc292ce626eb4d0857707f36b93e23f6bf39503feb50eae00220245fb8990277f64e1ecfad6467925b6c5d' \
            '79783e5786b7bd45191ffb11bf824e016952210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c6047f9441ed7d6' \
            'd3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee52102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f953ae00' \
            '000000'
        self.assertEqual(expected_signed_tx, tx.to_hex(use_witness=True))

        # other set of signers can sign too (eg 1st and 3rd)
        keys = all_privkeys[:1] + pubkeys[1:2] + all_privkeys[-1:]
        signer_1_3 = SignerP2SHP2WSHMultisig(threshold, keys, amount)
        # override signature
        tx.sign(0, signer_1_3)
        expected_signed_tx_1_3 = \
            '02000000000101e31419e10df7b342db42c728256312c44402b253ba06e654708a258fef5d8ccc000000002322002012c2ffbc6ec1cf5d746dfbd49b106' \
            '3356212ea55f43023ffc0145934af20c572ffffffff0118ddf5050000000017a914c95ef7c9117a56571c2ddc44e5fd8ba29d4598938704004730440220' \
            '5cb17ae6db374ed3df9b14829139f04bc6cd9e4ea06e3acb1e1329f15f19e75502207fd2c1a08b0f28c34b60fb8abee231553c2e98d4c5fab56557ad9f9' \
            '6a86a45b20147304402205ee619c2a08e7b963802bd8bcc8d9ca5a9750e469bf9501650f4be7cb753981a022029ee7dda9e4fb2f14dee62740d1e784a52' \
            '79bf513410fe5eef56abc4bfbbd392016952210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c6047f9441ed7d6' \
            'd3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee52102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f953ae00' \
            '000000'
        self.assertEqual(expected_signed_tx_1_3, tx.to_hex(use_witness=True))
        select_params('testnet')

    def test_e2e_mixed(self):
        """Simulated End-To-End mixed spending"""

        select_params('regtest')
        # keys
        threshold = 2
        prv1 = b'\x00' * 31 + b'\x01'
        prv2 = b'\x00' * 31 + b'\x02'
        prv3 = b'\x00' * 31 + b'\x03'

        all_privkeys = [PrivateKey(prv) for prv in [prv1, prv2, prv3]]
        pubkeys = [privkey.pubkey() for privkey in all_privkeys]

        # signlesig
        output = P2PKH(pubkeys[0])
        self.assertEqual(output.address(), 'mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r')

        txid = h2b_rev('57227d04c12267c96efa316b81c0f66b96b254760bc055a8479d411fbbf78ef7')
        vout = 2
        height = 150
        amount_ss = 100000000
        scriptpubkey = h2b('76a914751e76e8199196d454941c45d1b3a323f1433bd688ac')

        self.assertEqual(scriptpubkey, output.scriptpubkey())
        utxo_ss = Utxo(txid, vout, height, amount_ss, scriptpubkey)

        signer_ss = SignerP2PKH(all_privkeys[0])

        # multisig
        output = P2WSHMultisig(threshold, pubkeys)
        self.assertEqual(output.address(), 'bcrt1qztp0l0rwc8846ardl02fkyrrx43p96j47scz8l7qz3vnfteqc4eq3cu8hw')

        # obtain utxo data from node (these were obtained from a regtest)
        txid = h2b_rev('57227d04c12267c96efa316b81c0f66b96b254760bc055a8479d411fbbf78ef7')
        vout = 0
        height = 150
        amount_ms = 100000000
        scriptpubkey = h2b('002012c2ffbc6ec1cf5d746dfbd49b1063356212ea55f43023ffc0145934af20c572')

        self.assertEqual(output.scriptpubkey(), scriptpubkey)
        utxo_ms = Utxo(txid, vout, height, amount_ms, scriptpubkey)

        keys = all_privkeys[:2] + pubkeys[2:]
        signer_ms = SignerP2WSHMultisig(threshold, keys, amount_ms)

        # create a transaction spending both utxos to the same single sig address
        fee = 1000
        amount_send = amount_ss + amount_ms - fee
        scriptpubkey_send = signer_ss.scriptpubkey()

        tx = Transaction()
        tx.add_input(utxo_ss.txid, utxo_ss.vout, 0xffffffff)
        tx.add_input(utxo_ms.txid, utxo_ms.vout, 0xffffffff)
        tx.add_output(scriptpubkey_send, amount_send)
        expected_unsigned_tx = \
            '0200000002f78ef7bb1f419d47a855c00b7654b2966bf6c0816b31fa6ec96722c1047d22570200000000fffffffff78ef7bb1f419d47a855c00b7654b29' \
            '66bf6c0816b31fa6ec96722c1047d22570000000000ffffffff0118beeb0b000000001976a914751e76e8199196d454941c45d1b3a323f1433bd688ac00' \
            '000000'
        self.assertEqual(expected_unsigned_tx, tx.to_hex())

        # sign transaction
        tx.sign(0, signer_ss)
        tx.sign(1, signer_ms)
        expected_signed_tx = \
            '02000000000102f78ef7bb1f419d47a855c00b7654b2966bf6c0816b31fa6ec96722c1047d2257020000006a47304402200cc337a7eed7c209080683e2b' \
            '053d49254d80bd83dce2001d3f278a5247c8242022048f69a73b78f4033c30faafd7fe797cd1c85c1b3faf440786683241685d0f7ac01210279be667ef9' \
            'dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798fffffffff78ef7bb1f419d47a855c00b7654b2966bf6c0816b31fa6ec96722c1047d2' \
            '2570000000000ffffffff0118beeb0b000000001976a914751e76e8199196d454941c45d1b3a323f1433bd688ac00040047304402205cc5744b6dd00584' \
            '1012f6a800b02decbc16730196cd542ae6c0309d3756aace02207c1fced19ec704088342dcce2bdaf7c2c1f88268c3b1da7e7ce6ccc6d31181f10147304' \
            '4022026c9c4f5ead32262f01f033b3887b59fed8ddded912bb3e7f329d3076f3aedc8022013300fe03a62081857b6d0ab3eab3691e21b53ff36fee145ae' \
            '54128284b56b64016952210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c6047f9441ed7d6d3045406e95c07cd' \
            '85c778e4b8cef3ca7abac09b95c709ee52102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f953ae00000000'
        self.assertEqual(expected_signed_tx, tx.to_hex(use_witness=True))
        select_params('testnet')
