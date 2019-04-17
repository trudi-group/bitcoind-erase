# some functions originally from https://github.com/sr-gi/bitcoin_tools

import glob
from os import path
import re

import plyvel

import bitcoin
import bitcoin.rpc


NSPECIALSCRIPTS = 6  # nSpecialScripts from bitcoind's src/compressor.h

"""
Management of UTXOs in chainstate db
"""


def get_utxo(txid_string: str, index: int, fin_name: str) -> (bytes, bytes):
    """
    Gets a UTXO from the chainstate identified by a given transaction id and index.
    If the requested UTXO does not exist, return None.

    (inspired from https://github.com/sr-gi/bitcoin_tools)

    :param txid_string: Transaction ID that identifies the UTXO you are looking for.
    :param index: Index that identifies the specific output.
    :param fin_name: Name of the LevelDB folder
    :return: An (outpoint, coin) pair representing the requested UTXO
    """
    outpoint = build_utxo_outpoint(txid_string, index)

    # Open the LevelDB
    db = plyvel.DB(fin_name, compression=None)

    coin = db.get(outpoint)

    if coin is not None:
        coin = deobfuscate_with_db(db, coin)

    db.close()

    return (outpoint, coin)


def put_utxo(coin: bytes, txid_string: str, index: int, fin_name: str):
    """
    Puts a UTXO into the chainstate under a given transaction id and index.

    (inspired from https://github.com/sr-gi/bitcoin_tools)

    :param coin: Serialized coin to put
    :param txid_string: Transaction ID that identifies the UTXO you are looking for.
    :param index: Index that identifies the specific output.
    :param fin_name: Name of the LevelDB folder
    """
    outpoint = build_utxo_outpoint(txid_string, index)

    # Open the LevelDB
    db = plyvel.DB(fin_name, compression=None)

    coin = obfuscate_with_db(db, coin)

    db.put(outpoint, coin)

    db.close()


"""
Erasure of UTXOs (i.e., replacing them with an "anyone can spend" outputs to
avoid forks on potential future blocks that spend from them)
"""


def erase_utxos(utxos, data_dir: str, mode: str = 'testnet'):
    """
    Erase multiple UTXOs from chainstate database.

    :param utxos: txid:index pairs to be erased.
    :param data_dir: path to bitcoind data dir
    :param mode: the target chain/network (mainnet / testnet / regtest)
    """
    chainstate_dir = path.join(data_dir, mode2dir(mode), 'chainstate')

    for (txid_string, index) in utxos:
        erase_utxo(txid_string, index, chainstate_dir)


def are_utxos_erased(utxos, data_dir: str, mode: str = 'testnet') -> bool:
    """
    Check if list of UTXOs are erased from chainstate database.

    :param utxos: txid:index pairs to be erased.
    :param data_dir: path to bitcoind data dir
    :param mode: the target chain/network (mainnet / testnet / regtest)
    :returns: whether all utxos are erased
    """
    chainstate_dir = path.join(data_dir, mode2dir(mode), 'chainstate')

    return all(is_utxo_erased(*x, chainstate_dir) for x in utxos)


def erase_utxo(txid_string: str, index: int, fin_name: str):
    """
    Erase one UTXO, represented by a txid:index pair, from the chainstate database.
    (Replacing it with an "anyone can spend" output to avoid forks on blocks
    spending from that output.)

    :param txid_string: Transaction ID that identifies the UTXO to be erased.
    :param index: Index that identifies the specific output.
    :param fin_name: Name of the LevelDB folder
    """
    (outpoint, coin) = get_utxo(txid_string, index, fin_name)
    if coin:
        new_coin = make_anyone_can_spend(coin)
        put_utxo(new_coin, txid_string, index, fin_name)


def is_utxo_erased(txid_string: str, index: int, fin_name: str) -> bool:
    """
    Check if one UTXO, represented by a txid:index pair, is erased from the
    chainstate database.

    :param txid_string: Transaction ID that identifies the UTXO to be erased.
    :param index: Index that identifies the specific output.
    :param fin_name: Name of the LevelDB folder
    :returns: whether the utxo is erased
    """
    (outpoint, coin) = get_utxo(txid_string, index, fin_name)
    if not coin:
        return True
    else:
        return (coin == make_anyone_can_spend(coin))


"""
Management of block data
"""


def prune_up_to(height: int, btc_conf_file: str, mode: str = 'testnet'):
    """Tell bitcoind to prune up to given block height (via RPC call).

    :param height: block height to prune to
    :param btc_conf_file: path to bitcoind config file
    :param mode: the target chain/network (mainnet / testnet / regtest)
    """
    bitcoin.SelectParams(mode)

    proxy = bitcoin.rpc.Proxy(btc_conf_file=btc_conf_file)

    # TODO if fails, shows meaningful error message? (that user needs to turn on prune, e.g.)
    proxy.call('pruneblockchain', height)


def get_min_height_to_prune_to(block_hash_string: str, data_dir: str, mode: str = 'testnet') -> int:
    """Get minimum height to prune to in order for the block identified by
    block_hash_string to be physically erased from disk.

    :param block_hash_string: hash of the block
    :param data_dir: path to bitcoind data dir
    :param mode: the target chain/network (mainnet / testnet / regtest)
    :return: minimum height to prune to, or 0 if block not found
    """
    fin_name = path.join(data_dir, mode2dir(mode), 'blocks', 'index')

    blk_n = get_blk_n_from_block_data(get_block_index_entry(block_hash_string, fin_name))
    return get_blk_max_block_height(blk_n, fin_name) if blk_n else 0


def are_blks_erased(block_hashes, data_dir: str, mode: str = 'testnet') -> bool:
    """Check if the blk files containing the given blocks are physically erased
    from disk.

    :param block_hashes: block hashes to check
    :param data_dir: path to bitcoind data dir
    :param mode: the target chain/network (mainnet / testnet / regtest)
    :return: whether blk files are already pruned
    """
    # FIXME crashes if block_hash unknown (really?)
    highest_bad_blk_n = get_heighest_bad_blk_n(block_hashes, data_dir, mode)

    blocks_path = path.join(data_dir, mode2dir(mode), 'blocks')

    lowest_stored_files = [sorted(glob.glob(path.join(blocks_path, regexp)))[0] for regexp in ['blk*.dat', 'rev*.dat']]
    lowest_stored_blk_n = all([int(re.findall(r'\d+', x)[0]) for x in lowest_stored_files])

    return lowest_stored_blk_n > highest_bad_blk_n


def get_heighest_bad_blk_n(block_hashes, data_dir: str, mode: str = 'testnet') -> int:
    """Get the largest .blk file number containing an unwanted block.

    :param block_hashes: block hashes of unwanted blocks
    :param data_dir: path to bitcoind data dir
    :param mode: the target chain/network (mainnet / testnet / regtest)
    :return: number of a blk file (like 12345 in .bitcoin/blocks/blk12345.dat)
    """
    fin_name = path.join(data_dir, mode2dir(mode), 'blocks', 'index')
    return max(map(lambda x: get_blk_n_from_block_data(get_block_index_entry(x, fin_name)), block_hashes))


def get_block_index_entry(block_hash_string: str, fin_name: str) -> bytes:
    """Get block infos from the block index database

    :param block_hash_string: hash of the block
    :param fin_name: Name of the LevelDB folder for the block index database
    :return: a raw block index entry
    """
    block_hash = bytes.fromhex(block_hash_string)[::-1]  # block hash is little-endian hex string

    prefix = b'b'
    key = prefix + block_hash

    # Open the LevelDB
    db = plyvel.DB(fin_name, compression=None)  # Change with path to chainstate

    block_info = db.get(key)

    db.close()

    return block_info


def get_blk_n_from_block_data(data: bytes) -> int:
    """Parse block infos from the block index database to get the .blk file
    number where the block is stored.

    s.a. bitcoind's src/chain.h

    :param data: a raw block index entry
    :return: number of a blk file (like 12345 in .bitcoin/blocks/blk12345.dat)
    """
    nversion, offset = parse_b128(data)
    nheight, offset = parse_b128(data, offset)
    nstatus, offset = parse_b128(data, offset)
    if not nstatus:
        return None
    ntx, offset = parse_b128(data, offset)
    nfile, offset = parse_b128(data, offset)
    return b128_decode(nfile)


def get_blk_max_block_height(blk_n, fin_name) -> int:
    """Get the highest block number stored in the .blk file with the given number.

    :param blk_n: number of a blk file (like 12345 in .bitcoin/blocks/blk12345.dat)
    :returns: a block height

    """
    prefix = b'f'
    key = prefix + blk_n.to_bytes(4, byteorder='little')

    # Open the LevelDB
    db = plyvel.DB(fin_name, compression=None)
    blk_data = db.get(key)
    db.close()

    if not blk_data:
        return 0

    # parse data directly
    nBlocks, offset = parse_b128(blk_data)
    nSize, offset = parse_b128(blk_data, offset)
    nUndoSize, offset = parse_b128(blk_data, offset)
    nHeightFirst, offset = parse_b128(blk_data, offset)
    nHeightLast, offset = parse_b128(blk_data, offset)

    return b128_decode(nHeightLast)


"""
General helpers
"""


def mode2dir(mode):
    return {
            'mainnet': '.',
            'testnet': 'testnet3',
            'regtest': 'regtest',
            }[mode]


"""
Lower-level parsing and altering
"""


def build_utxo_outpoint(txid_string: str, index: int) -> bytes:
    prefix = b'C'
    txid = bytes.fromhex(txid_string)[::-1]  # TXIDs are little-endian hex strings
    return prefix + txid + b128_encode(index)


def obfuscate_with_key(o_key: bytes, data: bytes) -> bytes:
    return deobfuscate_with_key(o_key, data)


def obfuscate_with_db(db: plyvel.DB, data: bytes) -> bytes:
    return deobfuscate_with_db(db, data)


def deobfuscate_with_db(db: plyvel.DB, data: bytes) -> bytes:

    # Load obfuscation key (if it exists)
    o_key = db.get((bytes.fromhex('0e00') + b'obfuscate_key'))

    # If the key exists, the leading byte indicates the length of the key (8 byte by default). If there is no key,
    # 8-byte zeros are used (since the key will be XORed with the given values).
    if o_key is not None:
        o_key = o_key[1:]

    return deobfuscate_with_key(o_key, data)


def deobfuscate_with_key(o_key: bytes, data: bytes):
    """
    De-obfuscate data from the chainstate DB.

    :param o_key: Key used to obfuscate the given data (extracted from the chainstate).
    :param data: Obfuscated data.
    :return: The de-obfuscated data.
    """

    if not o_key:
        return data

    l_data = len(data)
    l_o_key = len(o_key)

    # Get the extended obfuscation key by concatenating the obfuscation key with itself until it is as large as the
    # data to be de-obfuscated.
    extended_key = (o_key * (int(l_data / l_o_key) + 1))[:l_data]

    r = bytes([v ^ k for (v, k) in zip(data, extended_key)])

    assert len(data) == len(r)

    return r


def make_anyone_can_spend(coin: bytes) -> bytes:
    code, offset = parse_b128(coin)
    value, offset = parse_b128(coin, offset)

    new_coin = coin[:offset]

    new_out_type = (1 + NSPECIALSCRIPTS)
    op_true = 0x51

    new_coin += b128_encode(new_out_type) + b128_encode(op_true)

    return new_coin


def extract_script(coin: bytes) -> bytes:

    # Once all the outpoint data has been parsed, we can proceed with the data encoded in the coin, that is, block
    # height, whether the transaction is coinbase or not, value, script type and script.
    # We start by decoding the first b128 VARINT of the provided data, that may contain 2*Height + coinbase
    code, offset = parse_b128(coin)

    # The next value in the sequence corresponds to the utxo value, the amount of Satoshi hold by the utxo. Data is
    # encoded as a B128 VARINT, and compressed using the equivalent to txout_compressor.
    value, offset = parse_b128(coin, offset)

    # Finally, we can obtain the data type by parsing the last B128 VARINT
    out_type, offset = parse_b128(coin, offset)
    out_type = b128_decode(out_type)

    if out_type in [0, 1]:
        data_size = 20
    elif out_type in [2, 3, 4, 5]:
        data_size = 33  # (1 byte for the type + 32 bytes of data)
        offset -= 2
    # Finally, if another value is found, it represents the length of the following data, which is uncompressed.
    else:
        data_size = out_type - NSPECIALSCRIPTS  # If the data is not compacted, the out_type corresponds
        # to the data size adding the number os special scripts (nSpecialScripts).

    # And the remaining data corresponds to the script.
    script = coin[offset:]

    # Assert that the script hash the expected length
    assert len(script) == data_size

    return script


def is_opreturn(script: bytes) -> bool:
    """
    Checks whether a given script is an OP_RETURN one.

    Warning: there should NOT be any OP_RETURN output in the UTXO set.

    :param script: The script to be checked.
    :return: True if the script is an OP_RETURN, False otherwise.
    """
    op_return_opcode = 0x6a
    return script[0] == op_return_opcode


def is_native_segwit(script: bytes) -> bool:
    """
    Checks whether a given output script is a native SegWit type.

    :param script: The script to be checked.
    :return: tuple, (True, segwit type) if the script is a native SegWit, (False, None) otherwise
    """
    if len(script) == 22 and script[:2] == bytes.fromhex("0014"):
        return True, "P2WPKH"

    if len(script) == 34 and script[:2] == bytes.fromhex("0020"):
        return True, "P2WSH"

    return False, None


def parse_b128(b128_data: bytes, offset: int = 0) -> (bytes, int):
    """ Parses serialized (UTXO) data to extract a base-128 varint.

    (originally from https://github.com/sr-gi/bitcoin_tools)

    :param b128_data: Serialized b128_data from which the varint will be parsed.
    :param offset: Offset where the beginning of the varint if located in the b128_data.
    :return: The extracted varint, and the offset of the byte located right after it.
    """
    data = bytes()
    more_bytes = True

    while more_bytes:
        data += b128_data[offset:offset+1]
        more_bytes = b128_data[offset] & 0x80  # MSB b128 Varints have set the bit 128 for every byte but the last one,
        # indicating that there is an additional byte following the one being analyzed. If bit 128 of the byte
        # being read is not set, we are analyzing the last byte, otherwise, we should continue reading.
        offset += 1

    return data, offset


def b128_encode(n: int) -> bytes:
    """ Performs the MSB base-128 encoding of a given value. Used to store variable integers (varints) in the LevelDB.
    The code is a port from the Bitcoin Core C++ source. Notice that the code is not exactly the same since the original
    one reads directly from the LevelDB.

    The encoding is used to store Satoshi amounts into the Bitcoin LevelDB (chainstate). Before encoding, values are
    compressed using txout_compress.

    The encoding can also be used to encode block height values into the format use in the LevelDB, however, those are
    encoded not compressed.

    Explanation can be found in:
        https://github.com/bitcoin/bitcoin/blob/v0.13.2/src/serialize.h#L307L329
    And code:
        https://github.com/bitcoin/bitcoin/blob/v0.13.2/src/serialize.h#L343#L358

    (originally from https://github.com/sr-gi/bitcoin_tools)

    :param n: Value to be encoded.
    :return: The base-128 encoded value
    """
    l = 0
    tmp = []

    while True:
        tmp.append(n & 0x7F)
        if l != 0:
            tmp[l] |= 0x80
        if n <= 0x7F:
            break
        n = (n >> 7) - 1
        l += 1

    tmp.reverse()
    return bytes(tmp)


def b128_decode(data: bytes) -> int:
    """ Performs the MSB base-128 decoding of a given value. Used to decode variable integers (varints) from the LevelDB.
    The code is a port from the Bitcoin Core C++ source. Notice that the code is not exactly the same since the original
    one reads directly from the LevelDB.

    The decoding is used to decode Satoshi amounts stored in the Bitcoin LevelDB (chainstate). After decoding, values
    are decompressed using txout_decompress.

    The decoding can be also used to decode block height values stored in the LevelDB. In his case, values are not
    compressed.

    Original code can be found in:
        https://github.com/bitcoin/bitcoin/blob/v0.13.2/src/serialize.h#L360#L372

    (originally from https://github.com/sr-gi/bitcoin_tools)

    :param data: The base-128 encoded value to be decoded.
    :return: The decoded value
    """
    n = 0
    i = 0
    while True:
        d = data[i]
        n = n << 7 | d & 0x7F
        if d & 0x80:
            n += 1
            i += 1
        else:
            return n


def txout_compress(n: int) -> int:
    """ Compresses the Satoshi amount of a UTXO to be stored in the LevelDB. Code is a port from the Bitcoin Core C++
    source:
        https://github.com/bitcoin/bitcoin/blob/v0.13.2/src/compressor.cpp#L133#L160

    (originally from https://github.com/sr-gi/bitcoin_tools)

    :param n: Satoshi amount to be compressed.
    :return: The compressed amount of Satoshis.
    """
    if n == 0:
        return 0
    e = 0
    while ((n % 10) == 0) and e < 9:
        n /= 10
        e += 1

    if e < 9:
        d = (n % 10)
        assert (1 <= d <= 9)
        n /= 10
        return 1 + (n * 9 + d - 1) * 10 + e
    else:
        return 1 + (n - 1) * 10 + 9


def txout_decompress(x: int) -> int:
    """ Decompresses the Satoshi amount of a UTXO stored in the LevelDB. Code is a port from the Bitcoin Core C++
    source:
        https://github.com/bitcoin/bitcoin/blob/v0.13.2/src/compressor.cpp#L161#L185

    (originally from https://github.com/sr-gi/bitcoin_tools)

    :param x: Compressed amount to be decompressed.
    :return: The decompressed amount of satoshi.
    """
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x /= 10
    if e < 9:
        d = (x % 9) + 1
        x /= 9
        n = x * 10 + d
    else:
        n = x + 1
    while e > 0:
        n *= 10
        e -= 1
    return n
