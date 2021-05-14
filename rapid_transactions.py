from bitcoinutils.constants import TYPE_RELATIVE_TIMELOCK
from bitcoinutils.keys import P2pkhAddress, PublicKey
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, Sequence
from bitcoinutils.script import Script
from helper import Id
from typing import List

# tx_state lock script encodes possibilities to either refund to left or pay to right
def getTxStateLockScript(T: int, delta: int, pubkey_pay_right: PublicKey,
                  pubkey_refund_mulsig_left: PublicKey, pubkey_refund_mulsig_right: PublicKey,
                  pubkey_pay_mulsig_left: PublicKey, pubkey_pay_mulsig_right: PublicKey) -> Script:

    # signature script:
    # - for refund (with enable-refund tx + 2∆): "OP_0 <left_signature> <right_signature>"
    # - for payment (time() >= T): "<signature_right> <pubkey_right> OP_0 OP_0 OP_0"
    # - for instantaneous payment (with enable-payment tx): "OP_0 <left_signature> <right_signature> OP_0 OP_0 OP_0 OP_0 OP_0 OP_0"
    lock_script = Script([
        'OP_2', pubkey_refund_mulsig_left.to_hex(), pubkey_refund_mulsig_right.to_hex(), 'OP_2', 'OP_CHECKMULTISIG',
        'OP_IF',
            delta, 'OP_CHECKSEQUENCEVERIFY', 'OP_DROP', 'OP_TRUE',  # check if refund and lock for 2∆
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


# move coins from left balance to new "lock" output
def createTxState(tx_in: TxInput, pubkey_left: PublicKey, pubkey_right: PublicKey,
                  pubkey_pay_right: PublicKey,  # pay after T wherever right in channel want
                  pubkey_refund_mulsig_left: PublicKey, pubkey_refund_mulsig_right: PublicKey, # mulsig for refund
                  pubkey_pay_mulsig_left: PublicKey, pubkey_pay_mulsig_right: PublicKey,  # mulsig for inst pay
                  lock_val: float, left_val: float, right_val: float, T: int, delta: int) -> Transaction:

    out_lock_script = getTxStateLockScript(T, delta, pubkey_pay_right, pubkey_refund_mulsig_left, pubkey_refund_mulsig_right, pubkey_pay_mulsig_left, pubkey_pay_mulsig_right)

    tx_out_lock = TxOutput(lock_val, out_lock_script)
    tx_out_left = TxOutput(left_val, P2pkhAddress(pubkey_left.get_address().to_string()).to_script_pub_key())
    tx_out_right = TxOutput(right_val, P2pkhAddress(pubkey_right.get_address().to_string()).to_script_pub_key())

    tx = Transaction([tx_in], [tx_out_lock, tx_out_left, tx_out_right])

    return tx


# funding transaction for enable-refund or enable-payment transactions.
def createTxInForEnableTx(tx_in: TxInput, id_sender: Id, id_receiver: Id, amount: float) -> Transaction:
    tx_out = TxOutput(amount, id_receiver.p2pkh)
    tx_er_in = Transaction([tx_in], [tx_out])

    sig_sender = id_sender.private_key.sign_input(tx_er_in, 0, id_sender.p2pkh)
    tx_in.script_sig = Script([sig_sender, id_sender.public_key.to_hex()])

    return tx_er_in


def getEnableTxOutputLockScript(pubkey: PublicKey, rel_timelock: int) -> Script:
    seq = Sequence(TYPE_RELATIVE_TIMELOCK, rel_timelock)
    return Script([seq.for_script(), 'OP_CHECKSEQUENCEVERIFY', 'OP_DROP', 'OP_DUP', 'OP_HASH160', pubkey.to_hash160(), 'OP_EQUALVERIFY', 'OP_CHECKSIG'])


# enable-refund and enable-payment transactions are constructed in the same way.
# Transaction has <n> outputs with value <eps>, owned by payment participants
def createEnableTx(tx_in: TxInput, public_keys: List[PublicKey], rel_timelock, eps: float = 1) -> Transaction:
    out_list = []
    for pubkey in public_keys:
        out_list.append(TxOutput(eps, getEnableTxOutputLockScript(pubkey, rel_timelock)))

    tx_er = Transaction([tx_in], out_list)
    return tx_er


# before the payment, users share unsigned version of enable-(payment/refund) transaction.
# if user wants to publish it then he signs it
def signEnableTx(tx_enable: Transaction, tx_in_owner: Id) -> Transaction:
    sig_sender = tx_in_owner.private_key.sign_input(tx_enable, 0, tx_in_owner.p2pkh)
    tx_enable.inputs[0].script_sig = Script([sig_sender, tx_in_owner.public_key.to_hex()])
    return tx_enable


# left creates tx_refund based on tx_state and tx_er, and signs it
def createTxRefund(tx_er_input: TxInput, tx_state_input: TxInput, id_er: Id, id_state_ref_left: Id, tx_state_lock_script: Script,
                   id_refund: Id, lock_coins: float, fee: float, eps: float, rel_lock: int) -> (Transaction, str):
    out_refund = TxOutput(lock_coins + eps - fee, id_refund.p2pkh)

    tx_refund = Transaction([tx_er_input, tx_state_input], [out_refund])

    er_in_lock_script = getEnableTxOutputLockScript(id_er.public_key, rel_lock)
    sig_er_in = id_er.private_key.sign_input(tx_refund, 0, er_in_lock_script)
    tx_er_input.script_sig = Script([sig_er_in, id_er.public_key.to_hex()])

    # should be also signed by right for 2/2 multisig
    sig_state_left = id_state_ref_left.private_key.sign_input(tx_refund, 1, tx_state_lock_script)

    return tx_refund, sig_state_left


# right signs tx_refund ans send signature back to left
def txRefundGetRightSignature(tx_refund: Transaction, id_state_ref_right: Id, tx_state_lock_script: Script) -> str:
    # signed 2/2 multisig by second party
    return id_state_ref_right.private_key.sign_input(tx_refund, 1, tx_state_lock_script)


# when left receives signature for tx_refund from right, he also creates ScriptSig for it
def signTxRefundStateInput(tx_refund: Transaction, sig_left: str, sig_right: str) -> Transaction:
    tx_refund.inputs[1].script_sig = Script(['OP_0', sig_left, sig_right])
    return tx_refund


# left creates tx_inst_pay and signature for tx_state which funds this tx_inst_pay
def createTxInstPay(tx_ep_input: TxInput, tx_state_input: TxInput, id_state_inst_pay_left: Id, tx_state_lock_script: Script,
                    id_inst_pay: Id, lock_coins: float, fee: float, eps: float) -> (Transaction, str):
    out_inst_pay = TxOutput(lock_coins + eps - fee, id_inst_pay.p2pkh)

    tx_inst_pay = Transaction([tx_ep_input, tx_state_input], [out_inst_pay])

    # should be also signed by right for 2/2 multisig
    sig_state_left = id_state_inst_pay_left.private_key.sign_input(tx_inst_pay, 0, tx_state_lock_script)

    return tx_inst_pay, sig_state_left


# left sends unsigned tx_inst_pay to right along with his signature for tx_state. 
# Now right can completely sign it and publish
def signTxInstPayStateInput(tx_inst_pay: Transaction, sig_tx_state_left: str, id_ep_owner: Id,
                            id_state_inst_pay_right: Id, tx_state_lock_script: Script, rel_lock: int) -> Transaction:

    ep_in_lock_script = getEnableTxOutputLockScript(id_ep_owner.public_key, rel_lock)
    sig_ep = id_ep_owner.private_key.sign_input(tx_inst_pay, 0, ep_in_lock_script)
    sig_tx_state_right = id_state_inst_pay_right.private_key.sign_input(tx_inst_pay, 1, tx_state_lock_script)

    tx_inst_pay.inputs[0].script_sig = Script([sig_ep, id_ep_owner.public_key.to_hex()])
    tx_inst_pay.inputs[1].script_sig = Script(['OP_0', sig_tx_state_left, sig_tx_state_right, 'OP_0', 'OP_0', 'OP_0'])

    return tx_inst_pay


# right can spend locked coins after time T wherever he wants
def createTxPayAndSign(tx_state_input: TxInput, id_state_pay_right: Id, tx_state_lock_script: Script,
                    id_pay_receiver: Id, lock_coins: float, fee: float) -> Transaction:

    out_pay = TxOutput(lock_coins - fee, id_pay_receiver.p2pkh)
    tx_pay = Transaction([tx_state_input], [out_pay])

    signature = id_state_pay_right.private_key.sign_input(tx_pay, 0, tx_state_lock_script)
    tx_state_input.script_sig = Script([signature, id_state_pay_right.public_key.to_hex(), 'OP_0', 'OP_0', 'OP_0', 'OP_0', 'OP_0', 'OP_0'])

    return tx_pay
