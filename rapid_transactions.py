from bitcoinutils.constants import TYPE_RELATIVE_TIMELOCK
from bitcoinutils.keys import P2pkhAddress, PublicKey
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, Sequence
from bitcoinutils.script import Script
from helper import Id
from typing import List


def getTxStateLockScript(T: int, delta: int, pubkey_pay_right: PublicKey,
                  pubkey_refund_mulsig_left: PublicKey, pubkey_refund_mulsig_right: PublicKey,
                  pubkey_pay_mulsig_left: PublicKey, pubkey_pay_mulsig_right: PublicKey) -> Script:
    """
    tx_state lock script encodes possibilities to either refund locked coins to left or pay to right

    :param T: locked funds can pe paid after this time wherever right user wants
    :param delta: upper bound on time for transaction to be confirmed by the network
    :param pubkey_pay_right: public key owned by right user for payment after time T
    :param pubkey_refund_mulsig_left: public key owned by left user for refund if enable-refund tx is published
    :param pubkey_refund_mulsig_right: public key owned by right user for refund if enable-refund tx is published
    :param pubkey_pay_mulsig_left: public key owned by left user for payment if enable-payment tx is published
    :param pubkey_pay_mulsig_right: public key owned by right user for payment if enable-payment tx is published
    :return: tx_state lock script
    """

    # signature script:
    # - for refund (with enable-refund tx + ∆): "OP_0 <left_signature> <right_signature>"
    # - for instantaneous payment (with enable-payment tx): "OP_0 <left_signature> <right_signature> OP_0 OP_0 OP_0"
    # - for payment (time() >= T): "<signature_right> <pubkey_right> OP_0 OP_0 OP_0 OP_0 OP_0 OP_0"
    lock_script = Script([
        'OP_2', pubkey_refund_mulsig_left.to_hex(), pubkey_refund_mulsig_right.to_hex(), 'OP_2', 'OP_CHECKMULTISIG',
        'OP_IF',
            delta, 'OP_CHECKSEQUENCEVERIFY', 'OP_DROP', 'OP_TRUE',  # check if refund and lock for ∆
        'OP_ELSE',
            'OP_2', pubkey_pay_mulsig_left.to_hex(), pubkey_pay_mulsig_right.to_hex(), 'OP_2', 'OP_CHECKMULTISIG', # check if inst payment
            'OP_IF',
                'OP_TRUE',
            'OP_ELSE',
                T, 'OP_CHECKLOCKTIMEVERIFY', 'OP_DROP', 'OP_DUP', 'OP_HASH160', pubkey_pay_right.to_hash160(), 'OP_EQUALVERIFY', 'OP_CHECKSIG',  # check if payment
            'OP_ENDIF',
        'OP_ENDIF'
    ])

    return lock_script


def createTxState(tx_in: TxInput, pubkey_left: PublicKey, pubkey_right: PublicKey,
                  pubkey_pay_right: PublicKey,
                  pubkey_refund_mulsig_left: PublicKey, pubkey_refund_mulsig_right: PublicKey,
                  pubkey_pay_mulsig_left: PublicKey, pubkey_pay_mulsig_right: PublicKey,
                  lock_val: float, left_val: float, right_val: float, T: int, delta: int) -> Transaction:

    """
    Move coins from left user balance to a new "lock" output.
    Before: 'a' coins to L, 'b' coins to R.
    After: 'a - c' coins to L, 'b' coins to R, 'c' coins locked.

    :param tx_in: reference to channel open transaction
    :param pubkey_left: public key owned by left user to receive his coins from channel
    :param pubkey_right: public key owned by right user to receive his coins from channel
    :param pubkey_pay_right: public key owned by right user for payment after time T
    :param pubkey_refund_mulsig_left: public key owned by left user for refund if enable-refund tx is published
    :param pubkey_refund_mulsig_right: public key owned by right user for refund if enable-refund tx is published
    :param pubkey_pay_mulsig_left: public key owned by left user for payment if enable-payment tx is published
    :param pubkey_pay_mulsig_right: public key owned by right user for payment if enable-payment tx is published
    :param lock_val: amount of coins to lock: 'c'
    :param left_val: coins or left user: 'a - c'
    :param right_val: coins or right user: 'b'
    :param T: locked funds can pe paid after this time wherever right user wants
    :param delta: upper bound on time for transaction to be confirmed by the network
    :return: tx_state
    """

    out_lock_script = getTxStateLockScript(T, delta, pubkey_pay_right, pubkey_refund_mulsig_left, pubkey_refund_mulsig_right, pubkey_pay_mulsig_left, pubkey_pay_mulsig_right)

    tx_out_lock = TxOutput(lock_val, out_lock_script)
    tx_out_left = TxOutput(left_val, P2pkhAddress(pubkey_left.get_address().to_string()).to_script_pub_key())
    tx_out_right = TxOutput(right_val, P2pkhAddress(pubkey_right.get_address().to_string()).to_script_pub_key())

    tx = Transaction([tx_in], [tx_out_lock, tx_out_left, tx_out_right])

    return tx


def getEnableTxOutputLockScript(pubkey: PublicKey, rel_timelock: int) -> Script:
    """
    Create lock script for output of enable-(payment/refund) transaction

    :param pubkey: public key owned by corresponding payment participant
    :param rel_timelock: relative lock on outputs. Should be same for all outputs of transaction
    :return: lock script
    """

    seq = Sequence(TYPE_RELATIVE_TIMELOCK, rel_timelock)
    return Script([seq.for_script(), 'OP_CHECKSEQUENCEVERIFY', 'OP_DROP', 'OP_DUP', 'OP_HASH160', pubkey.to_hash160(), 'OP_EQUALVERIFY', 'OP_CHECKSIG'])


def createEnableTx(tx_in: TxInput, public_keys: List[PublicKey], rel_timelock, eps: float = 1) -> Transaction:
    """
    Enable-refund and enable-payment transactions are constructed in the same way.
    Transaction has <n> outputs with value <eps>, owned by payment participants

    :param tx_in: funding transaction
    :param public_keys: keys owned by payment participants
    :param rel_timelock: relative lock on outputs
    :param eps: value for each output
    :return: enable transaction
    """

    out_list = []
    for pubkey in public_keys:
        out_list.append(TxOutput(eps, getEnableTxOutputLockScript(pubkey, rel_timelock)))

    tx_er = Transaction([tx_in], out_list)
    return tx_er


def signEnableTx(tx_enable: Transaction, tx_in_owner: Id) -> Transaction:
    """
    Before the payment, users share unsigned version of enable-(payment/refund) transaction.
    If user wants to publish it then he signs it

    :param tx_enable: enable-(payment/refund) transaction to sign
    :param tx_in_owner: id that owns funding tx of this enable tx
    :return: signed enable transaction
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

    er_in_lock_script = getEnableTxOutputLockScript(id_er.public_key, rel_lock)
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


def createTxInstPay(tx_ep_input: TxInput, tx_state_input: TxInput, id_state_inst_pay_left: Id, tx_state_lock_script: Script,
                    inst_pay_lock_script: Script, lock_coins: float, fee: float, eps: float) -> (Transaction, str):
    """
    Left user creates tx_inst_pay and signature for tx_state which funds this tx_inst_pay

    :param tx_ep_input: enable-payment transaction output reference
    :param tx_state_input: tx_state locked output reference
    :param id_state_inst_pay_left: id for signing spend of tx_state.out_lock by left user
    :param tx_state_lock_script: lock script of tx_state.out_lock (for creating a signature)
    :param inst_pay_lock_script: ScriptPubKey for new transactio, for example, p2pkh (to right user pubkey hash)
    :param lock_coins: coins locked in tx_state
    :param fee: coins paid to miners
    :param eps: coins from enable-refund transaction
    :return: tx for instant payment and signature of left user for it
    """

    out_inst_pay = TxOutput(lock_coins + eps - fee, inst_pay_lock_script)

    tx_inst_pay = Transaction([tx_ep_input, tx_state_input], [out_inst_pay])

    # should be also signed by right for 2/2 multisig
    sig_state_left = id_state_inst_pay_left.private_key.sign_input(tx_inst_pay, 0, tx_state_lock_script)

    return tx_inst_pay, sig_state_left


def signTxInstPayStateInput(tx_inst_pay: Transaction, sig_tx_state_left: str, id_ep_owner: Id,
                            id_state_inst_pay_right: Id, tx_state_lock_script: Script, rel_lock: int) -> Transaction:
    """
    Left user sends unsigned tx_inst_pay to right along with his signature for tx_state.
    Now right user can completely sign it and publish

    :param tx_inst_pay: tx for instant payment (created by left user)
    :param sig_tx_state_left: signature by left user for spending tx_spend.out_lock in this transaction
    :param id_ep_owner: id for signing spend of one of enable-payment tx outputs
    :param id_state_inst_pay_right: id for signing spend of tx_state.out_lock by right user
    :param tx_state_lock_script: lock script of tx_state.out_lock (for creating a signature)
    :param rel_lock: relative lock on tx_ep_input (for creating a signature)
    :return: signed transaction for instant payment if enable-payment transaction is published
    """

    ep_in_lock_script = getEnableTxOutputLockScript(id_ep_owner.public_key, rel_lock)
    sig_ep = id_ep_owner.private_key.sign_input(tx_inst_pay, 0, ep_in_lock_script)
    sig_tx_state_right = id_state_inst_pay_right.private_key.sign_input(tx_inst_pay, 1, tx_state_lock_script)

    tx_inst_pay.inputs[0].script_sig = Script([sig_ep, id_ep_owner.public_key.to_hex()])
    tx_inst_pay.inputs[1].script_sig = Script(['OP_0', sig_tx_state_left, sig_tx_state_right, 'OP_0', 'OP_0', 'OP_0'])

    return tx_inst_pay


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
