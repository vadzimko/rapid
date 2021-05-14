from bitcoinutils import setup
from bitcoinutils.keys import PublicKey
from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxInput, TxOutput

from helper import print_tx, Id


def getChannelLockScript(pubkey_left: PublicKey, pubkey_right: PublicKey) -> Script:
    return Script(['OP_2', pubkey_left.to_hex(), pubkey_right.to_hex(), 'OP_2', 'OP_CHECKMULTISIG'])


def createOpenChannelTx(tx_in_left: TxInput, tx_in_right: TxInput, amount_left: float, amount_right: float,
                        pubkey_left: PublicKey, pubkey_right: PublicKey) -> Transaction:

    script_pubkey = getChannelLockScript(pubkey_left, pubkey_right)
    tx_out = TxOutput(amount_left + amount_right, script_pubkey)

    tx = Transaction([tx_in_left, tx_in_right], [tx_out])
    return tx


def signOpenChannelTxLeft(tx: Transaction, left: Id) -> Transaction:
    signature = left.private_key.sign_input(tx, 0, left.p2pkh)
    tx.inputs[0].script_sig = Script([signature, left.public_key.to_hex()])
    return tx


def signOpenChannelTxRight(tx: Transaction, right: Id) -> Transaction:
    signature = right.private_key.sign_input(tx, 1, right.p2pkh)
    tx.inputs[1].script_sig = Script([signature, right.public_key.to_hex()])
    return tx


def getChannelStateScriptSigLeft(tx: Transaction, left_id: Id, right_pubkey: PublicKey, index: int = 0) -> str:
    signature = left_id.private_key.sign_input(tx, index, getChannelLockScript(left_id.public_key, right_pubkey))
    return signature


def getChannelStateScriptSigRight(tx: Transaction, right_id: Id, left_pubkey: PublicKey, index: int = 0) -> str:
    signature = right_id.private_key.sign_input(tx, index, getChannelLockScript(left_pubkey, right_id.public_key))
    return signature


def signChannelStateTx(tx: Transaction, signature_left: str, signature_right: str) -> Transaction:
    tx.inputs[0].script_sig = Script(['OP_0', signature_left, signature_right])
    return tx


def testChannel():
    setup.setup('testnet')
    id_left = Id('1aa60d2b1563c43e27531dd8392cfee695f733f1509ee80980948f09c6a6c59b')
    id_right = Id('a9de61e5047946133821216d7f5149f5d9c04326ce73a915cb2d6d678686f6b3')
    tx_input_left = TxInput('98ebd3a3455cc907f29919713fa1799a2d9d60168f5fb1ae94074b1a8078100e', 8)
    tx_input_right = TxInput('98ebd3a3455cc907f29919713fa1799a2d9d60168f5fb1ae94074b1a8078100e', 9)

    print(id_left.public_key)
    print(id_right.public_key)

    channel_tx = createOpenChannelTx(tx_input_left, tx_input_right, 1900, 1900, id_left.public_key, id_right.public_key)
    print_tx(channel_tx, 'chan')
    channel_tx = signOpenChannelTxLeft(channel_tx, id_left)
    print_tx(channel_tx, 'chan 1 sig')
    channel_tx = signOpenChannelTxRight(channel_tx, id_right)
    print_tx(channel_tx, 'chan 2 sig')
