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
    append_config,
    assert_equal,
    assert_raises,
    assert_raises_rpc_error,
    bytes_to_hex_str,
    connect_nodes_bi,
    mine_large_block,
    hash256,
    hex_str_to_bytes,
    sync_blocks,
    sync_mempools,
)

# FIXME this uglyness
import sys
sys.path.append('.')
import tool


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

        self.log.info("Generate a few blocks upfront to make sure pruning kicks in.")
        # On pruning, we must have a chain longer than PruneAfterHeight and bigger than 550 MiB.
        mine_large_blocks(n0, nblocks=200)
        self.nodes[0].generate(nblocks=200)

        self.log.info("Build a \"bad\" transaction.")
        bad_data = 'n42MaFLwantedToTestThisKYP112MM9jE'
        tx_bad = n1.createrawtransaction([], {bad_data: 0.001})
        (tx_bad, txid_bad) = fund_sign_send(n1, tx_bad)  # also adds inputs and change output
        tx_bad_vouts = n1.decoderawtransaction(tx_bad)['vout']

        self.log.info("Add tx to a block, mine a few big blocks on top.")
        self.sync_all()
        block_hash_bad = n0.generate(nblocks=1)[0]
        # significantly lower nblocks might cause pruning not to work (needs changes to bitcoind pruning logic)
        mine_large_blocks(n0, nblocks=300)
        self.nodes[0].generate(nblocks=300)
        self.sync_all()

        erase_target = {block_hash_bad: {txid_bad: list(range(len(tx_bad_vouts)))}}

        self.log.info("Assert that node 2 serves the tx via RPC.")
        assert_equal(bytes_to_hex_str(hash256(hex_str_to_bytes(n2.getrawtransaction(txid_bad)))), txid_bad)

        self.log.info("Assert that node 2 serves the block with the tx via P2P.")
        n2.add_p2p_connection(P2PInterface())
        n2.p2p.send_message(msg_getdata(inv=[CInv(2, int(block_hash_bad, 16))]))
        n2.p2p.wait_for_block(int(block_hash_bad, 16), timeout=1)

        self.log.info("Stopping node 2.")
        self.stop_node(2)

        self.log.info("Assert that UTXOs not erased according to tool.")
        assert_equal(tool.check(erase_target, n2.datadir, 'regtest'), False)

        def react_to_ui_request(request):
            assert("enable pruning" in request)
            self.log.info("Configuring node 2 to enable pruning.")
            append_config(n2.datadir, ["prune=1"])

            assert("start your node" in request)
            self.log.info("Starting node 2.")
            self.start_node(2)
            connect_nodes_bi(self.nodes, 0, 2)

        self.log.info("Erasing using tool.")
        tool.interactive_erase(erase_target, n2.datadir, 'regtest', self.log.info, react_to_ui_request)

        self.log.info("Assert that the tx's block can't be obtained from node 2 via P2P anymore.")
        n2.add_p2p_connection(P2PInterface())
        n2.p2p.send_message(msg_getdata(inv=[CInv(2, int(block_hash_bad, 16))]))
        assert_raises(AssertionError, n2.p2p.wait_for_block, int(block_hash_bad, 16), timeout=1)

        self.log.info("Assert that tx is different now when obtained from node 2 via RPC.")
        assert_raises_rpc_error(-5, None, n2.getrawtransaction, txid_bad)

        self.log.info("Assert that node 2 accepts new blocks.")
        n0.generate(nblocks=1)
        sync_blocks(self.nodes, timeout=1)

        self.log.info("Spend one output of the bad tx, include that in block.")
        tx_bad_vout = [x for x in n1.listunspent() if x['txid'] == txid_bad][0]
        tx_ok = n1.createrawtransaction([tx_bad_vout], {n0.getnewaddress(): 0.5})
        (tx_ok, txid_ok) = fund_sign_send(n1, tx_ok)
        sync_mempools([n0, n1])
        n0.generate(nblocks=1)

        self.log.info("Assert that node 2 accepts the resulting transaction and block.")
        sync_blocks(self.nodes, timeout=1)
        assert_equal(bytes_to_hex_str(hash256(hex_str_to_bytes(n2.getrawtransaction(txid_ok)))), txid_ok)

        self.log.info("Wait for all nodes to sync again, just in case. Should complete immediately.")
        self.sync_all()

        self.log.info("Stopping node 2 (again).")
        self.stop_node(2)

        self.log.info("Assert that UTXOs are erased according to tool.")
        assert_equal(tool.check(erase_target, n2.datadir, 'regtest'), True)


def mine_large_blocks(node, nblocks):

    utxo_cache = []

    for i in range(nblocks):
        mine_large_block(node, utxo_cache)


# perhaps useful in the future (e.g., for fuzz testing)
def generate_nonempty_blocks(nodes, nblocks=500):
    txes_per_block = 10

    for i in range(nblocks):
        for j in range(txes_per_block):
            (s, r) = random.sample(nodes, k=2)
            amount = random.randint(1, 1000) / 1000.
            s.sendtoaddress(r.getnewaddress(), amount)
        random.choice(nodes).generate(nblocks=1)
        sync_blocks(nodes)


def fund_sign_send(node, tx):
    tx = node.fundrawtransaction(tx)['hex']
    tx = node.signrawtransactionwithwallet(tx)["hex"]
    txid = node.sendrawtransaction(tx)
    return (tx, txid)


if __name__ == '__main__':
    ErasureTest().main()
