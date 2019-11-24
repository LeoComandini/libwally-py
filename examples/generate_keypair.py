#!/usr/bin/env python3

import os

from pywally import select_params
from pywally.key import PrivateKey
from pywally.util import b2h


# Generate a random keypair

select_params('testnet')

prv = os.urandom(32)
privkey = PrivateKey(prv)
pubkey = privkey.pubkey()

print('Private key')
print(' HEX: {}'.format(b2h(prv)))
print(' WIF: {}'.format(privkey.to_wif()))

print('Public key')
print(' HEX: {}'.format(b2h(pubkey.pub)))
