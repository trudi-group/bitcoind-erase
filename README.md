# Functionality-Preserving Local Erasure from bitcoind nodes (PoC)

This is a proof-of-concept implementation as part of a research paper:

M. Florian, S. Beaucamp, S. Henningsen and B. Scheuermann, "Erasing Data from Blockchain Nodes", to be presented at *IEEE Security & Privacy on the Blockchain (IEEE S&B) 2019*.

Paper abstract:

> It is a common narrative that blockchains are immutable and so it is technically impossible to erase data stored on them. For legal and ethical reasons, however, individuals and organizations might be compelled to erase locally stored data, be it encoded on a blockchain or not. The common assumption for blockchain networks like Bitcoin is that forcing nodes to erase data contained on the blockchain is equal to permanently restricting them from participating in the system in a full-node role. Challenging this belief, in this paper, we propose and demonstrate a pragmatic approach towards functionality-preserving local erasure (FPLE). FPLE enables full nodes to erase infringing or undesirable data while continuing to store and validate most of the blockchain. We describe a general FPLE approach for UTXO-based (i.e., Bitcoin-like) cryptocurrencies and present a lightweight proof-of-concept tool for safely erasing transaction data from the local storage of Bitcoin Core nodes. Erasing nodes continue to operate in tune with the network even when erased transaction outputs become relevant for validating subsequent blocks. Using only our basic proof-of-concept implementation, we are already able to safely comply with a significantly larger range of erasure requests than, to the best of our knowledge, any other full node operator so far.

## What does this do exactly?

For an informative overview best see our paper.

## Requirements (possibly incomplete)

```
pip3 install plyvel python-bitcoinlib
```

## Tests

```
tests/run.sh
```

## Use with an actual bitcoind

**This is a proof-of-concept for research purposes! Use at your own risk!**

Also, aspects like UI, documentation and error handling are not currently end-user-ready.

If you still want to go there:

```
./tool.py config.json
```

With `config.json` structured like the provided `example_config.json` (see also the docstrings in `tool.py`).

## Are you actually interested in using something like this?

We'd love to hear from you and are happy to help with developing a production-ready solution! Contact [us](https://weizenbaum-institut.de/en/research/rg17/)!
