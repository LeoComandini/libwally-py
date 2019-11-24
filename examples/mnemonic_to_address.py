#!/usr/bin/env python3

import os

from pywally.bip32 import Xprv
from pywally.bip39 import entropy_to_mnemonic
from pywally.key import PrivateKey
from pywally.output import P2WPKH
from pywally.util import harden, b2h


# Generate a random mnemonic and derive its m/0'/1 key and P2WPKH address


entropy = os.urandom(16)
mnemonic = entropy_to_mnemonic(entropy)
master_xprv = Xprv.from_mnemonic(mnemonic)

path = [harden(0), 1]
derived_xprv = master_xprv.derive(path)
privkey = derived_xprv.privkey()
pubkey = privkey.pubkey()
output = P2WPKH(pubkey)
address = output.address()

print('Entropy (hex):     {}'.format(b2h(entropy)))
print('BIP39 mnemonic:    {}'.format(mnemonic))
print('Master xprv:       {}'.format(master_xprv.to_b58()))
print()
path_str = 'm/' + '/'.join(str(e) if e < harden(0) else (str(e % harden(0)) + "'") for e in path)
print('Path:              {}'.format(path_str))
print('Private key (hex): {}'.format(b2h(privkey.prv)))
print('Private key (WIF): {}'.format(privkey.to_wif()))
print('Public key:        {}'.format(b2h(pubkey.pub)))
print('Address (P2WPKH):  {}'.format(address))
