import base64
import unittest

from pywally.message import (
    sign_message,
    verify_message,
    InvalidRecoverableSignature,
)


class TestMessage(unittest.TestCase):

    def test_bitcoin_message(self):
        """Bitcoin message"""

        privkey_wif = 'cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA'
        address = 'mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r'
        message = 'my message'

        signature = sign_message(privkey_wif, message)
        self.assertTrue(verify_message(address, signature, message))
        self.assertFalse(verify_message('', signature, message))
        self.assertRaises(InvalidRecoverableSignature, verify_message, address, base64.b64encode(b'\x00' * 64), message)
        self.assertFalse(verify_message(address, signature, 'another message'))
