#!/usr/bin/env python3
# Copyright (c) 2017-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A functional test for erasing transactions locally

The module-level docstring should include a high-level description of
what the test is doing. It's the first thing people see when they open
the file and should give the reader information about *what* the test
is testing and *how* it's being tested
"""
# Imports should be in PEP8 ordering (std library first, then third party
# libraries then local imports).

# Avoid wildcard * imports if possible
from test_framework.test_framework import BitcoinTestFramework
from test_framework.messages import (
    CInv,
    msg_getdata,
)
from test_framework.mininode import (
    P2PInterface,
)
from test_framework.util import (
    assert_equal,
    assert_raises,
    assert_raises_rpc_error,
    bytes_to_hex_str,
    connect_nodes_bi,
    hash256,
    hex_str_to_bytes,
    sync_blocks,
)

# FIXME this uglyness
import sys
sys.path.append('.')
from utils import erase_utxo


# P2PInterface is a class containing callbacks to be executed when a P2P
# message is received from the node-under-test. Subclass P2PInterface and
# override the on_*() methods if you need custom behaviour.
# class BaseNode(P2PInterface):

class ErasureTest(BitcoinTestFramework):
    # Each functional test is a subclass of the BitcoinTestFramework class.

    # Override the set_test_params(), add_options(), setup_chain(), setup_network()
    # and setup_nodes() methods to customize the test setup as required.

    def set_test_params(self):
        """Override test parameters for your individual test.

        This method must be overridden and num_nodes must be exlicitly set."""
        self.num_nodes = 3
        # erasure does not yet work for segwit outputs
        self.extra_args = [["-addresstype=legacy"]]*3

    def run_test(self):
        """Main test logic"""

        self.log.info("Starting test!")
        [n0, n1, n2] = self.nodes  # n2 is the erasing node

        self.log.info("Build a \"bad\" transaction.")

        bad_data = 'n42MaFLwantedToTestThisKYP112MM9jE'
        tx_bad = n0.createrawtransaction([], {bad_data: 0.001})
        (tx_bad, txid_bad) = fund_sign_send(n0, tx_bad)  # also adds inputs and change output
        tx_bad_vouts = n0.decoderawtransaction(tx_bad)['vout']

        self.log.info("Add tx to a block, mine a few blocks on top.")
        block_height_bad = n0.getblockcount()
        # right now, significantly lower nblocks will cause pruning not to work
        block_hash_bad = int(n0.generate(nblocks=300)[0], 16)
        self.sync_all()

        self.log.info("Assert that node 2 serves the tx via RPC.")
        assert_equal(bytes_to_hex_str(hash256(hex_str_to_bytes(n2.getrawtransaction(txid_bad)))), txid_bad)

        self.log.info("Assert that node 2 serves the block with the tx via P2P.")
        n2.add_p2p_connection(P2PInterface())
        n2.p2p.send_message(msg_getdata(inv=[CInv(2, block_hash_bad)]))
        n2.p2p.wait_for_block(block_hash_bad, timeout=1)

        self.log.info("Mark tx as bad/erased at node 2.")
        self.stop_node(2)

        chainstate_dir = n2.datadir + '/regtest/chainstate/'

        for index in range(len(tx_bad_vouts)):
            erase_utxo(txid_bad, index, chainstate_dir)
        # TODO tell node to prune blk files

        self.start_node(2)
        connect_nodes_bi(self.nodes, 0, 2)

        self.log.info("Assert that tx can't be obtained from node 2 via RPC (getrawtransaction) anymore.")
        assert_raises_rpc_error(-5, None, n2.getrawtransaction, txid_bad)

        self.log.info("Assert that the tx's block can't be obtained from node 2 via P2P anymore.")
        n2.add_p2p_connection(P2PInterface())
        n2.p2p.send_message(msg_getdata(inv=[CInv(2, block_hash_bad)]))
        assert_raises(AssertionError, n2.p2p.wait_for_block, block_hash_bad, timeout=1)

        self.log.info("Assert that node 2 accepts new blocks.")
        n0.generate(nblocks=1)
        sync_blocks(self.nodes, timeout=1)

        self.log.info("Spend one output of the bad tx, include that in block.")
        tx_bad_vout = [x for x in n0.listunspent() if x['txid'] == txid_bad][0]
        tx_ok = n0.createrawtransaction([tx_bad_vout], {n1.getnewaddress(): 0.5})
        (tx_ok, txid_ok) = fund_sign_send(n0, tx_ok)
        n0.generate(nblocks=1)

        self.log.info("Assert that node 2 accepts the resulting transaction and block.")
        sync_blocks(self.nodes, timeout=1)
        assert_equal(bytes_to_hex_str(hash256(hex_str_to_bytes(n2.getrawtransaction(txid_ok)))), txid_ok)

        self.log.info("Wait for all nodes to sync again, just in case. Should complete immediately.")
        self.sync_all()


def fund_sign_send(node, tx):
        tx = node.fundrawtransaction(tx)['hex']
        tx = node.signrawtransactionwithwallet(tx)["hex"]
        txid = node.sendrawtransaction(tx)
        return (tx, txid)


if __name__ == '__main__':
    ErasureTest().main()
