#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import json
import sys

import utils


def main():

    with open(sys.argv[1]) as config_fp:
        config = json.load(config_fp)

    # { blockhash -> { txid -> [ outpoint_index ] }
    data_dir = config['bitcoind_data_dir']
    mode = config['chain']  # mainnet / testnet / regtest ...
    erase_target = config['erase']

    if check(erase_target, data_dir, mode):
        print("No unwanted transaction outputs are stored locally. Have a nice day.")
    else:
        print("Some unwanted transaction outputs are stored locally.")
        print("ERASE!")


def check(erase_target, data_dir, mode):
    """ Check if desired data is erased

    :erase_target: TODO
    :returns: TODO

    """
    block_hashes = erase_target.keys()
    if not utils.check_if_blks_erased(block_hashes, data_dir, mode):
        return False

    utxos = get_target_utxos(erase_target)
    if not utils.check_if_utxos_erased(utxos, data_dir, mode):
        return False

    return True


def get_target_utxos(erase_target):

    utxos = []
    for block in erase_target.values():
        for txid in block.keys():
            for index in block[txid]:
                utxos.append((txid, index))
    return utxos


if __name__ == "__main__":
    main()
