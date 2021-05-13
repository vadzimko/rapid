import binascii
import base58

from bitcoinutils.keys import PrivateKey, P2pkhAddress
from bitcoinutils.transactions import Transaction


class Id:
    def __init__(self, sk: str):
        self.private_key = PrivateKey(secret_exponent=int(sk, 16))
        self.public_key = self.private_key.get_public_key()
        self.address = self.public_key.get_address().to_string()
        self.p2pkh = P2pkhAddress(self.address).to_script_pub_key()
        # print(self.private_key.to_wif(), self.address)


def wif_to_private_key(wif: str):
    first_encode = base58.b58decode(wif)
    private_key_full = binascii.hexlify(first_encode)
    private_key = private_key_full[2:-10]
    return private_key.__str__()[2:-1]


def print_tx(tx: Transaction, name: str = '') -> None:
    print(f'{name}: {int(len(tx.serialize()) / 2)} Bytes')
    print(tx.serialize())
    print('----------------------------------')
