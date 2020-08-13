#!/usr/bin/env python3

import os

from pywally import select_params
from pywally.bip32 import Xprv
from pywally.bip39 import entropy_to_mnemonic
from pywally.key import PrivateKey
from pywally.output import P2WPKH
from pywally.extra_2of2_csv import P2WSH2of2CSV, SignerP2WSH2of2CSV
from pywally.util import harden, b2h, h2b, h2b_rev

from pywally.utxo import Utxo
from pywally.transaction import Transaction


select_params('regtest')


csv_blocks = 144

entropy = h2b("e2164174c2994b082adce2ebd15d69ee")
mnemonic = entropy_to_mnemonic(entropy)
master_xprv = Xprv.from_mnemonic(mnemonic)

user_path = [harden(1)]
master_user_xprv = master_xprv.derive(user_path)

server_path = [harden(2)]
master_server_xprv = master_xprv.derive(server_path)

path = [harden(0), 1]

user_derived_xprv = master_user_xprv.derive(path)
user_privkey = user_derived_xprv.privkey()
user_pubkey = user_privkey.pubkey()

server_derived_xprv = master_server_xprv.derive(path)
server_privkey = server_derived_xprv.privkey()
server_pubkey = server_privkey.pubkey()

output = P2WSH2of2CSV(user_pubkey, server_pubkey, csv_blocks)
address = output.address()

print(address)

txid = h2b_rev('129e1fa5778da5a207ed0af53c1f7d0e569fac163bf7d14c27e753d04b76c319')
vout = 0
amount = 100000000

#csv_blocks_passed = True
csv_blocks_passed = False

server_key = server_pubkey if csv_blocks_passed else server_privkey

signer = SignerP2WSH2of2CSV(user_privkey, server_key, csv_blocks, amount)

fee = 1000
amount_send = amount - fee
scriptpubkey_send = signer.scriptpubkey()

tx = Transaction()
sequence = csv_blocks if csv_blocks_passed else 0xffffffff
tx.add_input(txid, vout, sequence)
tx.add_output(scriptpubkey_send, amount_send)

tx.sign(0, signer)

print(tx.to_hex(use_witness=True))
