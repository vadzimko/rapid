from bitcoinutils.utils import to_satoshis

from rapid_transactions import *
from channel import *
from helper import Id, print_tx, wif_to_private_key


def main():
    setup.setup('testnet')
    eps = 200  # value owned by each participant in enable-(payment/refund) transaction. Could be 1 satoshi
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
    # publish tx_channel -> https://live.blockcypher.com/btc-testnet/tx/7b2ff59b6070a70249fd3f06efd1e0944d69597e5871e72098304adae94e7316/
    tx_channel_id = '7b2ff59b6070a70249fd3f06efd1e0944d69597e5871e72098304adae94e7316'

    id_ep_in = Id('f2b019b04121adca7b6541a08761454b14ffd705248a51e7f3b6cfbf64f2b26b')
    tx_ep_input = TxInput('14c5b01c28a133fb55c03cfd756d70ccdacbdc0229c4a96d49c65c25df53afb5', 2)
    id_er_in = Id('89270091320614b25f88b84497ff4e4a017cbf1d25c1462b1352ea44f45708db')
    tx_er_input = TxInput('14c5b01c28a133fb55c03cfd756d70ccdacbdc0229c4a96d49c65c25df53afb5', 3)

    id_er_u1 = Id('3223c869874bad6933f14d1bf3bc9354125641e0aef3484dcf313c24a18655c7')
    id_er_u2 = Id('ac54ff9bc498ac9fa15f1e76a670fa0acdc85316fb6a97fc161f3871ab59e3bd')
    id_er_u3 = Id('05b91a17dbe63db245c6a2ba84a9a2b01ed86b494b61cc2dad5a0a44fe6ddc0e')

    id_ep_u1 = Id('d0f7165a36f496ff7599add67e7152869ee0e515bab290c4b77a559623034c82')
    id_ep_u2 = Id('d869d0308b94a12c6831576d7c55231a59cdace9a46b2ea32d83a035dbb9b4fb')
    id_ep_u3 = Id('2dcd22336e478779c8b5e8788c52ee359d5de5d3ef0cc33eb669e6e616bfa95d')

    tx_er_rel_timelock = t_channel + 2 * delta
    tx_ep_rel_timelock = t_channel

    tx_er = createEnableTx(tx_er_input, [id_er_u1.public_key], tx_er_rel_timelock, eps)
    tx_er_input.script_sig = Script([id_er_in.private_key.sign_input(tx_er, 0, id_er_in.p2pkh), id_er_in.public_key.to_hex()])
    print_tx(tx_er, 'tx_er, 1 out')
    # 195 bytes
    tx_er = createEnableTx(tx_er_input, [id_er_u1.public_key, id_er_u2.public_key], tx_er_rel_timelock, eps)
    tx_er_input.script_sig = Script([id_er_in.private_key.sign_input(tx_er, 0, id_er_in.p2pkh), id_er_in.public_key.to_hex()])
    print_tx(tx_er, 'tx_er, 2 out')
    # 233 bytes
    tx_er = createEnableTx(tx_er_input, [id_er_u1.public_key, id_er_u2.public_key, id_er_u3.public_key], tx_er_rel_timelock, eps)
    tx_er_input.script_sig = Script([id_er_in.private_key.sign_input(tx_er, 0, id_er_in.p2pkh), id_er_in.public_key.to_hex()])
    print_tx(tx_er, 'tx_er, 3 out')
    # 271 bytes. enable-refund tx size in bytes = 157 + 38 * outs_number

    tx_ep = createEnableTx(tx_ep_input, [id_ep_u1.public_key, id_ep_u2.public_key, id_ep_u3.public_key], tx_ep_rel_timelock, eps)
    tx_ep_input.script_sig = Script([id_ep_in.private_key.sign_input(tx_ep, 0, id_ep_in.p2pkh), id_ep_in.public_key.to_hex()])
    print_tx(tx_ep, 'tx_ep, 3 out')
    # same as enable-refund

    # publish tx_er -> https://live.blockcypher.com/btc-testnet/tx/1e3c3465793126d4115f49750fab61a66c20bfbece436016d00066730704969b/
    tx_er_id = '1e3c3465793126d4115f49750fab61a66c20bfbece436016d00066730704969b'
    # publish tx_ep -> https://live.blockcypher.com/btc-testnet/tx/19c04e7bb09cbbd6f18ed4bff18a6c0d7491ddf5119ff1e70b2cfdbc4455612c/
    tx_ep_id = '19c04e7bb09cbbd6f18ed4bff18a6c0d7491ddf5119ff1e70b2cfdbc4455612c'

    id_state_left = Id('ce7bca0ec8d38f945390e64627f4b669eca9afd2bae77d036421ce96b6767728')  # left can receive a - c coins
    id_state_right = Id('ad5813d9719179da0e561aa22295017559b247a3bb325ce438bc8247bf79962e')  # right can receive b coins
    id_refund_mulsig_left = Id('e34d37fdeb88addac291ae0fa084f33490d756d8298e7219b0d4f073616dd251')  # left will receive c coins if publish tx_refund (using tx_er output)
    id_refund_mulsig_right = Id('4d87652d513e0f7a5be51894b7fa862c8ca3ea8ef222f6b6ea7ed6a949f67672') # left will receive c coins if publish tx_refund (using tx_er output)
    id_pay_mulsig_left = Id('0a08c11255f48d66b0d1dcab0e3b9479a7e1275d078663fde3dc9fd92355e784')   # right will receive c coins if publish tx_inst_pay (using tx_ep output)
    id_pay_mulsig_right = Id('0a08c11255f48d66b0d1dcab0e3b9479a7e1275d078663fde3dc9fd92355e784')  # right will receive c coins if publish tx_inst_pay (using tx_ep output)
    id_pay_right = Id('0a08c11255f48d66b0d1dcab0e3b9479a7e1275d078663fde3dc9fd92355e784')  # right will receive c coins after T if publish tx_pay

    tx_state_in = TxInput(tx_channel_id, 0)
    state_lock_script = getTxStateLockScript(T, delta, id_pay_right.public_key,
                             id_refund_mulsig_left.public_key, id_refund_mulsig_right.public_key,
                             id_pay_mulsig_left.public_key, id_pay_mulsig_right.public_key)

    lock_amount = to_satoshis(0.00000500)
    tx_state = createTxState(tx_state_in, id_state_left.public_key, id_state_right.public_key, id_pay_right.public_key,
                             id_refund_mulsig_left.public_key, id_refund_mulsig_right.public_key,
                             id_pay_mulsig_left.public_key, id_pay_mulsig_right.public_key,
                             lock_amount, to_satoshis(0.00000300), to_satoshis(0.00000100), T, delta)

    sig_tx_state_left = getChannelStateScriptSigLeft(tx_state, id_channel_left, id_channel_right.public_key)
    sig_tx_state_right = getChannelStateScriptSigRight(tx_state, id_channel_right, id_channel_left.public_key)
    tx_state = signChannelStateTx(tx_state, sig_tx_state_left, sig_tx_state_right)
    print_tx(tx_state, 'tx state')
    # 457 bytes
    # publish tx_state -> https://live.blockcypher.com/btc-testnet/tx/229caba8498d320c60b78f347ad70ff8e324bd39a9318e3a94a788dc53f1516f/
    tx_state_id = '229caba8498d320c60b78f347ad70ff8e324bd39a9318e3a94a788dc53f1516f'

    tx_er_for_refund_input = TxInput(tx_er_id, 0)
    tx_ep_for_refund_input = TxInput(tx_ep_id, 0)
    tx_state_lock_input = TxInput(tx_state_id, 0)

    id_refund_receiver = Id('e2bd3bf28c7e0994ef87a8d61b67f4f926ab2e315bc9f1e55da2394a594b4e66')    # new address for refund
    id_pay_receiver = Id('9d2b4722df4e870ef4fd6a7be03b39c9a056bf0562852018e0c995cbc0d5756c')       # new address for pay to right
    id_inst_pay_receiver = Id('6f76abd9416387f1e34e66a8fa3f13c73a601617e6851ccc6200cca7957443c3')  # new address for inst pay to right

    tx_refund, sig_left = createTxRefund(tx_er_for_refund_input, tx_state_lock_input, id_er_u1, id_refund_mulsig_left,
                                 state_lock_script, id_refund_receiver, lock_amount, to_satoshis(0.00000400), eps)

    sig_right = txRefundGetRightSignature(tx_refund, id_refund_mulsig_right, state_lock_script)
    tx_refund = signTxRefundStateInput(tx_refund, sig_left, sig_right)
    print_tx(tx_refund, 'tx refund')
    # 379 bytes todo: real publish when rellock finish and fix
    # publish tx_state -> https://live.blockcypher.com/btc-testnet/tx/229caba8498d320c60b78f347ad70ff8e324bd39a9318e3a94a788dc53f1516f/
    tx_state_id = '229caba8498d320c60b78f347ad70ff8e324bd39a9318e3a94a788dc53f1516f'

    tx_pay = createTxPayAndSign(tx_state_lock_input, id_pay_right, state_lock_script, id_pay_receiver,
                                lock_amount, to_satoshis(0.00000400))
    print_tx(tx_pay, 'tx pay')
    # 198 bytes

    tx_inst_pay, sig_state_left = createTxInstPay(tx_ep_for_refund_input, tx_state_lock_input, id_pay_mulsig_left, state_lock_script,
                                  id_inst_pay_receiver, lock_amount, to_satoshis(0.00000400), eps)
    tx_inst_pay = signTxInstPayStateInput(tx_inst_pay, sig_state_left, id_ep_u1, id_pay_mulsig_right, state_lock_script)
    print_tx(tx_inst_pay, 'tx inst pay')
    # 382 bytes


def split_funds():
    setup.setup('testnet')
    id_in = Id('a8fac854dc0fea70c7a7fe94bbf013195c7eef83e2052b01a55d8cf5f08cfa53')
    tx_input = TxInput('98ebd3a3455cc907f29919713fa1799a2d9d60168f5fb1ae94074b1a8078100e', 4)

    id1 = Id('616c26241bb007883f13aff556bb07d28374b52b81aa675f30dcf35c04103da4')
    id2 = Id('f74b11ae3ca8d2c2d0424296f0de316198b4fda2ca984b5e3c6681abd2c72b2c')
    id3 = Id('f2b019b04121adca7b6541a08761454b14ffd705248a51e7f3b6cfbf64f2b26b')
    id4 = Id('89270091320614b25f88b84497ff4e4a017cbf1d25c1462b1352ea44f45708db')
    out1 = TxOutput(to_satoshis(0.0000115), id1.p2pkh)
    out2 = TxOutput(to_satoshis(0.0000115), id2.p2pkh)
    out3 = TxOutput(to_satoshis(0.0000115), id3.p2pkh)
    out4 = TxOutput(to_satoshis(0.0000115), id4.p2pkh)

    tx = Transaction([tx_input], [out1, out2, out3, out4])
    sign = id_in.private_key.sign_input(tx, 0, id_in.p2pkh)
    tx_input.script_sig = Script([sign, id_in.public_key.to_hex()])
    print_tx(tx)


if __name__ == '__main__':
    # print(wif_to_private_key('cVBTEB2s94WftLPmCvH7iJoEcCZBEZthNnADJGUwQtGfMNGBEAyC'))
    main()
    split_funds()


