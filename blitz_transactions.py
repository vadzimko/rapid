from bitcoinutils import setup
from bitcoinutils.constants import TYPE_RELATIVE_TIMELOCK
from bitcoinutils.keys import P2pkhAddress, PublicKey
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, Sequence
from bitcoinutils.script import Script
from bitcoinutils.utils import to_satoshis

from channel import createOpenChannelTx, signOpenChannelTxLeft, signOpenChannelTxRight, getChannelStateScriptSigLeft, getChannelStateScriptSigRight, signChannelStateTx
from helper import Id, print_tx
from typing import List


def getTxStateLockScript(T: int, delta: int, pubkey_pay_right: PublicKey,
                         pubkey_mulsig_left: PublicKey, pubkey_mulsig_right: PublicKey) -> Script:
    """
    tx_state lock script encodes possibilities to either refund locked coins to left or pay to right

    :param T: locked funds can pe paid after this time wherever right user wants
    :param delta: upper bound on time for transaction to be confirmed by the network
    :param pubkey_pay_right: public key owned by right user for payment after time T
    :param pubkey_mulsig_left: public key owned by left user for refund if enable-refund tx is published
    :param pubkey_mulsig_right: public key owned by right user for refund if enable-refund tx is published
    :return: tx_state lock script
    """

    # signature script:
    # - for refund (with enable-refund tx + ∆): "OP_0 <left_signature> <right_signature>"
    # - for payment (time() >= T): "<signature_right> <pubkey_right> OP_0 OP_0 OP_0 OP_0 OP_0 OP_0"
    lock_script = Script([
        'OP_2', pubkey_mulsig_left.to_hex(), pubkey_mulsig_right.to_hex(), 'OP_2', 'OP_CHECKMULTISIG',
        'OP_IF',
            delta, 'OP_CHECKSEQUENCEVERIFY', 'OP_DROP', 'OP_TRUE',  # check if refund and lock for ∆
        'OP_ELSE',
            T, 'OP_CHECKLOCKTIMEVERIFY', 'OP_DROP', 'OP_DUP', 'OP_HASH160', pubkey_pay_right.to_hash160(), 'OP_EQUALVERIFY', 'OP_CHECKSIG',  # check if payment
        'OP_ENDIF'
    ])

    return lock_script


def createTxState(tx_in: TxInput, pubkey_left: PublicKey, pubkey_right: PublicKey,
                  pubkey_pay_right: PublicKey,
                  pubkey_mulsig_left: PublicKey, pubkey_mulsig_right: PublicKey,
                  lock_val: float, left_val: float, right_val: float, T: int, delta: int) -> Transaction:

    """
    Move coins from left user balance to a new "lock" output.
    Before: 'a' coins to L, 'b' coins to R.
    After: 'a - c' coins to L, 'b' coins to R, 'c' coins locked.

    :param tx_in: reference to channel open transaction
    :param pubkey_left: public key owned by left user to receive his coins from channel
    :param pubkey_right: public key owned by right user to receive his coins from channel
    :param pubkey_pay_right: public key owned by right user for payment after time T
    :param pubkey_mulsig_left: public key owned by left user for refund if enable-refund tx is published
    :param pubkey_mulsig_right: public key owned by right user for refund if enable-refund tx is published
    :param lock_val: amount of coins to lock: 'c'
    :param left_val: coins or left user: 'a - c'
    :param right_val: coins or right user: 'b'
    :param T: locked funds can pe paid after this time wherever right user wants
    :param delta: upper bound on time for transaction to be confirmed by the network
    :return: tx_state
    """

    out_lock_script = getTxStateLockScript(T, delta, pubkey_pay_right, pubkey_mulsig_left, pubkey_mulsig_right)

    tx_out_lock = TxOutput(lock_val, out_lock_script)
    tx_out_left = TxOutput(left_val, P2pkhAddress(pubkey_left.get_address().to_string()).to_script_pub_key())
    tx_out_right = TxOutput(right_val, P2pkhAddress(pubkey_right.get_address().to_string()).to_script_pub_key())

    tx = Transaction([tx_in], [tx_out_lock, tx_out_left, tx_out_right])

    return tx


def getTxEROutputLockScript(pubkey: PublicKey, rel_timelock: int) -> Script:
    """
    Create lock script for output of enable-refund transaction

    :param pubkey: public key owned by corresponding payment participant
    :param rel_timelock: relative lock on outputs. Should be same for all outputs of transaction
    :return: lock script
    """

    seq = Sequence(TYPE_RELATIVE_TIMELOCK, rel_timelock)
    return Script([seq.for_script(), 'OP_CHECKSEQUENCEVERIFY', 'OP_DROP', 'OP_DUP', 'OP_HASH160', pubkey.to_hash160(), 'OP_EQUALVERIFY', 'OP_CHECKSIG'])


def createTxER(tx_in: TxInput, public_keys: List[PublicKey], rel_timelock, eps: float = 1) -> Transaction:
    """
    Transaction has <n> outputs with value <eps>, owned by payment participants

    :param tx_in: funding transaction
    :param public_keys: keys owned by payment participants
    :param rel_timelock: relative lock on outputs
    :param eps: value for each output
    :return: enable transaction
    """

    out_list = []
    for pubkey in public_keys:
        out_list.append(TxOutput(eps, getTxEROutputLockScript(pubkey, rel_timelock)))

    tx_er = Transaction([tx_in], out_list)
    return tx_er


def signTxER(tx_enable: Transaction, tx_in_owner: Id) -> Transaction:
    """
    Before the payment, users share unsigned version of enable-refund transaction.
    If user wants to publish it then he signs it

    :param tx_enable: enable-refund transaction to sign
    :param tx_in_owner: id that owns funding tx of this enable tx
    :return: signed enable-refund transaction
    """

    sig_sender = tx_in_owner.private_key.sign_input(tx_enable, 0, tx_in_owner.p2pkh)
    tx_enable.inputs[0].script_sig = Script([sig_sender, tx_in_owner.public_key.to_hex()])
    return tx_enable


def createTxRefund(tx_er_input: TxInput, tx_state_input: TxInput, id_er: Id, id_state_ref_left: Id, tx_state_lock_script: Script,
                   id_refund: Id, lock_coins: float, fee: float, eps: float, rel_lock: int) -> (Transaction, str):
    """
    Left user creates transaction for refund based on tx_state and tx_er, and signs it

    :param tx_er_input: enable-refund transaction output reference
    :param tx_state_input: tx_state locked output reference
    :param id_er: id that owns output of enable-refund transaction
    :param id_state_ref_left: id for signing spend of tx_state.out_lock by left user
    :param tx_state_lock_script: lock script of tx_state.out_lock (for creating a signature)
    :param id_refund: id that will own coins if transaction will be published
    :param lock_coins: coins locked in tx_state
    :param fee: coins paid to miners
    :param eps: coins from enable-refund transaction
    :param rel_lock: relative lock on tx_er_input (for creating a signature)
    :return: tx_refund, signed by left user
    """

    out_refund = TxOutput(lock_coins + eps - fee, id_refund.p2pkh)

    tx_refund = Transaction([tx_er_input, tx_state_input], [out_refund])

    er_in_lock_script = getTxEROutputLockScript(id_er.public_key, rel_lock)
    sig_er_in = id_er.private_key.sign_input(tx_refund, 0, er_in_lock_script)
    tx_er_input.script_sig = Script([sig_er_in, id_er.public_key.to_hex()])

    # should be also signed by right for 2/2 multisig
    sig_state_left = id_state_ref_left.private_key.sign_input(tx_refund, 1, tx_state_lock_script)

    return tx_refund, sig_state_left


def txRefundGetRightSignature(tx_refund: Transaction, id_state_ref_right: Id, tx_state_lock_script: Script) -> str:
    """
    Right user signs tx_refund ans send signature back to left

    :param tx_refund: refund transaction
    :param id_state_ref_right: id for signing spend of tx_state.out_lock by right user
    :param tx_state_lock_script: lock script of tx_state.out_lock (for creating a signature)
    :return: signature of tx_refund by right user
    """

    return id_state_ref_right.private_key.sign_input(tx_refund, 1, tx_state_lock_script)


def signTxRefundStateInput(tx_refund: Transaction, sig_left: str, sig_right: str) -> Transaction:
    """
    When left user receives signature for tx_refund from right user, he also creates ScriptSig for it

    :param tx_refund: refund transaction
    :param sig_left: signature of left user
    :param sig_right: signature of right user
    :return:
    """

    tx_refund.inputs[1].script_sig = Script(['OP_0', sig_left, sig_right])
    return tx_refund


def createTxPayAndSign(tx_state_input: TxInput, id_state_pay_right: Id, tx_state_lock_script: Script,
                    id_pay_receiver: Id, lock_coins: float, fee: float) -> Transaction:
    """
    Right can spend locked coins after time T wherever he wants

    :param tx_state_input: tx_state locked output reference
    :param id_state_pay_right: id for signing spend of tx_state.out_lock by right user
    :param tx_state_lock_script: lock script of tx_state.out_lock (for creating a signature)
    :param id_pay_receiver: id that will own coins if transaction will be published
    :param lock_coins: coins locked in tx_state
    :param fee: coins paid to miners
    :return: transaction for pay to right user, valid after time T
    """

    out_pay = TxOutput(lock_coins - fee, id_pay_receiver.p2pkh)
    tx_pay = Transaction([tx_state_input], [out_pay])

    signature = id_state_pay_right.private_key.sign_input(tx_pay, 0, tx_state_lock_script)
    tx_state_input.script_sig = Script([signature, id_state_pay_right.public_key.to_hex(), 'OP_0', 'OP_0', 'OP_0', 'OP_0', 'OP_0', 'OP_0'])

    return tx_pay


def main():
    setup.setup('testnet')
    eps = 200  # value owned by each participant in enable-refund transaction. Could be 1 satoshi
    delta = 10  # upper bound for tx to be confirmed
    T = 2100200  # funds for payment locked until this time
    t_channel = 35  # upper bound for closing a channel

    id_in_channel_left = Id('616c26241bb007883f13aff556bb07d28374b52b81aa675f30dcf35c04103da4')
    tx_in_channel_left = TxInput('14c5b01c28a133fb55c03cfd756d70ccdacbdc0229c4a96d49c65c25df53afb5', 0)
    id_in_channel_right = Id('f74b11ae3ca8d2c2d0424296f0de316198b4fda2ca984b5e3c6681abd2c72b2c')
    tx_in_channel_right = TxInput('14c5b01c28a133fb55c03cfd756d70ccdacbdc0229c4a96d49c65c25df53afb5', 1)

    id_channel_left = Id('e6ad38d70bf775e7e74bcd598e9282141dac09f79374565c3ebdf61e4f9ef4ed')
    id_channel_right = Id('a3dbcea1e46edecbd1da13231f385ebe7f2beea382e3f7227c4c00d21b7e8455')

    tx_channel = createOpenChannelTx(tx_in_channel_left, tx_in_channel_right, to_satoshis(0.000009), to_satoshis(0.000009),
                                  id_channel_left.public_key, id_channel_right.public_key)

    tx_channel = signOpenChannelTxLeft(tx_channel, id_in_channel_left)
    tx_channel = signOpenChannelTxRight(tx_channel, id_in_channel_right)
    print_tx(tx_channel, 'tx channel open')
    tx_channel_id = '7b2ff59b6070a70249fd3f06efd1e0944d69597e5871e72098304adae94e7316'

    id_er_in = Id('89270091320614b25f88b84497ff4e4a017cbf1d25c1462b1352ea44f45708db')
    tx_er_input = TxInput('14c5b01c28a133fb55c03cfd756d70ccdacbdc0229c4a96d49c65c25df53afb5', 3)

    id_er_u1 = Id('3223c869874bad6933f14d1bf3bc9354125641e0aef3484dcf313c24a18655c7')
    id_er_u2 = Id('ac54ff9bc498ac9fa15f1e76a670fa0acdc85316fb6a97fc161f3871ab59e3bd')
    id_er_u3 = Id('05b91a17dbe63db245c6a2ba84a9a2b01ed86b494b61cc2dad5a0a44fe6ddc0e')

    tx_er_rel_timelock = t_channel + 2 * delta

    tx_er = createTxER(tx_er_input, [id_er_u1.public_key, id_er_u2.public_key, id_er_u3.public_key], tx_er_rel_timelock, eps)
    signTxER(tx_er, id_er_in)
    print_tx(tx_er, 'tx_er, 3 out')

    tx_er_id = '1e3c3465793126d4115f49750fab61a66c20bfbece436016d00066730704969b'

    id_state_left = Id('ce7bca0ec8d38f945390e64627f4b669eca9afd2bae77d036421ce96b6767728')  # left can receive a - c coins
    id_state_right = Id('ad5813d9719179da0e561aa22295017559b247a3bb325ce438bc8247bf79962e')  # right can receive b coins
    id_refund_mulsig_left = Id('e34d37fdeb88addac291ae0fa084f33490d756d8298e7219b0d4f073616dd251')  # left will receive c coins if publish tx_refund (using tx_er output)
    id_refund_mulsig_right = Id('4d87652d513e0f7a5be51894b7fa862c8ca3ea8ef222f6b6ea7ed6a949f67672') # left will receive c coins if publish tx_refund (using tx_er output)
    id_pay_right = Id('0a08c11255f48d66b0d1dcab0e3b9479a7e1275d078663fde3dc9fd92355e784')  # right will receive c coins after T if publish tx_pay

    tx_state_in = TxInput(tx_channel_id, 0)
    state_lock_script = getTxStateLockScript(T, delta, id_pay_right.public_key,
                             id_refund_mulsig_left.public_key, id_refund_mulsig_right.public_key)

    lock_amount = to_satoshis(0.00000500)
    tx_state = createTxState(tx_state_in, id_state_left.public_key, id_state_right.public_key, id_pay_right.public_key,
                             id_refund_mulsig_left.public_key, id_refund_mulsig_right.public_key,
                             lock_amount, to_satoshis(0.00000300), to_satoshis(0.00000100), T, delta)

    sig_tx_state_left = getChannelStateScriptSigLeft(tx_state, id_channel_left, id_channel_right.public_key)
    sig_tx_state_right = getChannelStateScriptSigRight(tx_state, id_channel_right, id_channel_left.public_key)
    tx_state = signChannelStateTx(tx_state, sig_tx_state_left, sig_tx_state_right)
    print_tx(tx_state, 'tx state')
    tx_state_id = '229caba8498d320c60b78f347ad70ff8e324bd39a9318e3a94a788dc53f1516f'

    tx_er_for_refund_input = TxInput(tx_er_id, 0, sequence=Sequence(TYPE_RELATIVE_TIMELOCK, tx_er_rel_timelock).for_input_sequence())
    tx_state_lock_input = TxInput(tx_state_id, 0, sequence=Sequence(TYPE_RELATIVE_TIMELOCK, delta).for_input_sequence())

    id_refund_receiver = Id('e2bd3bf28c7e0994ef87a8d61b67f4f926ab2e315bc9f1e55da2394a594b4e66')    # new address for refund
    id_pay_receiver = Id('9d2b4722df4e870ef4fd6a7be03b39c9a056bf0562852018e0c995cbc0d5756c')       # new address for pay to right

    tx_refund, sig_left = createTxRefund(tx_er_for_refund_input, tx_state_lock_input, id_er_u1, id_refund_mulsig_left,
                                 state_lock_script, id_refund_receiver, lock_amount, to_satoshis(0.00000600), eps, tx_er_rel_timelock)

    sig_right = txRefundGetRightSignature(tx_refund, id_refund_mulsig_right, state_lock_script)
    tx_refund = signTxRefundStateInput(tx_refund, sig_left, sig_right)
    print_tx(tx_refund, 'tx refund')

    tx_pay = createTxPayAndSign(tx_state_lock_input, id_pay_right, state_lock_script, id_pay_receiver,
                                lock_amount, to_satoshis(0.00000600))
    print_tx(tx_pay, 'tx pay')


if __name__ == '__main__':
    main()