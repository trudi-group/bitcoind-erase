#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from os import path

import json
import sys

import utils


def main():

    with open(sys.argv[1]) as config_fp:
        config = json.load(config_fp)

    # { blockhash -> { txid -> [ outpoint_index ] }
    data_dir = path.expanduser(config['bitcoind_data_dir'])
    mode = config['chain']  # mainnet / testnet / regtest ...
    erase_target = config['erase']

    input("Please make sure the corresponding bitcoind instance is stopped (Press Enter.)")

    if check(erase_target, data_dir, mode):
        print("No unwanted transaction outputs are stored locally. Have a nice day.")
    else:
        print("Some unwanted transaction outputs are stored locally.")
        input("Will erase locally, editing bitcoind data files. (Press Enter.)")
        interactive_erase(erase_target, data_dir, mode)


def check(erase_target, data_dir: str, mode: str) -> bool:
    """ Check whether desired data is erased

    :erase_target { blockhash -> { txid -> [ outpoint_index ] }
    :param data_dir: path to bitcoind data dir
    :param mode: the target chain/network (mainnet / testnet / regtest)
    :return: true if erased, false if not
    """
    block_hashes = erase_target.keys()
    if not utils.are_blks_erased(block_hashes, data_dir, mode):
        return False

    utxos = get_target_utxos(erase_target)
    if not utils.are_utxos_erased(utxos, data_dir, mode):
        return False

    return True


def interactive_erase(erase_target, data_dir: str, mode: str, print_function=print, input_function=input):
    """ Erase outputs with user interaction.

    :erase_target { blockhash -> { txid -> [ outpoint_index ] }
    :param data_dir: path to bitcoind data dir
    :param mode: the target chain/network (mainnet / testnet / regtest)
    """
    utxos = get_target_utxos(erase_target)
    block_hashes = erase_target.keys()

    print_function("Replacing target UTXOs with 'anyone-can-spend' outputs.")
    utils.erase_utxos(utxos, data_dir, mode)

    print_function("Getting height to prune to.")
    prune_height = max([utils.get_min_height_to_prune_to(x, data_dir, mode) for x in block_hashes])

    input_function(
            "Please edit your node's configuration to enable pruning (\"prune=1\") and start your node. " +
            "(Press Enter when ready.)"
            )

    print_function("Pruning blk files.")
    utils.prune_up_to(prune_height, path.join(data_dir, 'bitcoin.conf'), mode)

    print_function("Erasure complete! (Your node is still running.)")


def get_target_utxos(erase_target):

    utxos = []
    for block in erase_target.values():
        for txid in block.keys():
            for index in block[txid]:
                utxos.append((txid, index))
    return utxos


if __name__ == "__main__":
    main()
