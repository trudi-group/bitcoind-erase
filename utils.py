# some functions originally from https://github.com/sr-gi/bitcoin_tools

from os import path

import plyvel

from binascii import hexlify, unhexlify  # TODO still need these?
from bitcoin.core import lx, x

import bitcoin
import bitcoin.rpc


NSPECIALSCRIPTS = 6  # nSpecialScripts from bitcoind's src/compressor.h


def txout_compress(n):
    """ Compresses the Satoshi amount of a UTXO to be stored in the LevelDB. Code is a port from the Bitcoin Core C++
    source:
        https://github.com/bitcoin/bitcoin/blob/v0.13.2/src/compressor.cpp#L133#L160

    :param n: Satoshi amount to be compressed.
    :type n: int
    :return: The compressed amount of Satoshis.
    :rtype: int
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


def txout_decompress(x):
    """ Decompresses the Satoshi amount of a UTXO stored in the LevelDB. Code is a port from the Bitcoin Core C++
    source:
        https://github.com/bitcoin/bitcoin/blob/v0.13.2/src/compressor.cpp#L161#L185

    :param x: Compressed amount to be decompressed.
    :type x: int
    :return: The decompressed amount of satoshi.
    :rtype: int
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


def b128_encode(n):
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

    The MSB of every byte (x)xxx xxxx encodes whether there is another byte following or not. Hence, all MSB are set to
    one except from the very last. Moreover, one is subtracted from all but the last digit in order to ensure a
    one-to-one encoding. Hence, in order decode a value, the MSB is changed from 1 to 0, and 1 is added to the resulting
    value. Then, the value is multiplied to the respective 128 power and added to the rest.

    Examples:

        - 255 = 807F (0x80 0x7F) --> (1)000 0000 0111 1111 --> 0000 0001 0111 1111 --> 1 * 128 + 127 = 255
        - 4294967296 (2^32) = 8EFEFEFF (0x8E 0xFE 0xFE 0xFF 0x00) --> (1)000 1110 (1)111 1110 (1)111 1110 (1)111 1111
            0000 0000 --> 0000 1111 0111 1111 0111 1111 1000 0000 0000 0000 --> 15 * 128^4 + 127*128^3 + 127*128^2 +
            128*128 + 0 = 2^32


    :param n: Value to be encoded.
    :type n: int
    :return: The base-128 encoded value
    :rtype: hex str
    """

    l = 0
    tmp = []
    data = ""

    while True:
        tmp.append(n & 0x7F)
        if l != 0:
            tmp[l] |= 0x80
        if n <= 0x7F:
            break
        n = (n >> 7) - 1
        l += 1

    tmp.reverse()
    for i in tmp:
        data += format(i, '02x')
    return data


def b128_decode(data):
    """ Performs the MSB base-128 decoding of a given value. Used to decode variable integers (varints) from the LevelDB.
    The code is a port from the Bitcoin Core C++ source. Notice that the code is not exactly the same since the original
    one reads directly from the LevelDB.

    The decoding is used to decode Satoshi amounts stored in the Bitcoin LevelDB (chainstate). After decoding, values
    are decompressed using txout_decompress.

    The decoding can be also used to decode block height values stored in the LevelDB. In his case, values are not
    compressed.

    Original code can be found in:
        https://github.com/bitcoin/bitcoin/blob/v0.13.2/src/serialize.h#L360#L372

    Examples and further explanation can be found in b128_encode function.

    :param data: The base-128 encoded value to be decoded.
    :type data: hex str
    :return: The decoded value
    :rtype: int
    """

    n = 0
    i = 0
    while True:
        d = int(data[2 * i:2 * i + 2], 16)
        n = n << 7 | d & 0x7F
        if d & 0x80:
            n += 1
            i += 1
        else:
            return n


def parse_b128(utxo, offset=0):
    """ Parses a given serialized UTXO to extract a base-128 varint.

    :param utxo: Serialized UTXO from which the varint will be parsed.
    :type utxo: hex str
    :param offset: Offset where the beginning of the varint if located in the UTXO.
    :type offset: int
    :return: The extracted varint, and the offset of the byte located right after it.
    :rtype: hex str, int
    """

    data = utxo[offset:offset+2]
    offset += 2
    more_bytes = int(data, 16) & 0x80  # MSB b128 Varints have set the bit 128 for every byte but the last one,
    # indicating that there is an additional byte following the one being analyzed. If bit 128 of the byte being read is
    # not set, we are analyzing the last byte, otherwise, we should continue reading.
    while more_bytes:
        data += utxo[offset:offset+2]
        more_bytes = int(utxo[offset:offset+2], 16) & 0x80
        offset += 2

    return data, offset


def make_anyone_can_spend(coin):
    code, offset = parse_b128(coin)
    value, offset = parse_b128(coin, offset)

    new_coin = coin[:offset]

    new_out_type = (1 + NSPECIALSCRIPTS)
    op_true = 0x51

    new_coin += b128_encode(new_out_type) + b128_encode(op_true)

    return new_coin


def extract_script(coin):

    # Once all the outpoint data has been parsed, we can proceed with the data encoded in the coin, that is, block
    # height, whether the transaction is coinbase or not, value, script type and script.
    # We start by decoding the first b128 VARINT of the provided data, that may contain 2*Height + coinbase
    code, offset = parse_b128(coin)
    code = b128_decode(code)

    # The next value in the sequence corresponds to the utxo value, the amount of Satoshi hold by the utxo. Data is
    # encoded as a B128 VARINT, and compressed using the equivalent to txout_compressor.
    data, offset = parse_b128(coin, offset)

    # Finally, we can obtain the data type by parsing the last B128 VARINT
    out_type, offset = parse_b128(coin, offset)
    out_type = b128_decode(out_type)

    if out_type in [0, 1]:
        data_size = 40  # 20 bytes
    elif out_type in [2, 3, 4, 5]:
        data_size = 66  # 33 bytes (1 byte for the type + 32 bytes of data)
        offset -= 2
    # Finally, if another value is found, it represents the length of the following data, which is uncompressed.
    else:
        data_size = (out_type - NSPECIALSCRIPTS) * 2  # If the data is not compacted, the out_type corresponds
        # to the data size adding the number os special scripts (nSpecialScripts).

    # And the remaining data corresponds to the script.
    script = coin[offset:]

    # Assert that the script hash the expected length
    assert len(script) == data_size

    return script


def get_blk_n_from_block_data(data):
    """TODO: Docstring for decode_block_data.

    :data: TODO
    :returns: TODO

    """
    height, offset = parse_b128(data)
    status, offset = parse_b128(data, offset)
    if not status:
        return None
    ntx, offset = parse_b128(data, offset)
    nfile, offset = parse_b128(data, offset)
    return b128_decode(nfile)


def get_blk_max_block_height(blk_n, fin_name):
    """TODO: Docstring for get_blk_max_block_height.

    :blk_n: TODO
    :returns: TODO

    """
    prefix = b'f'
    key = prefix + blk_n.to_bytes(4, byteorder='little')

    # Open the LevelDB
    db = plyvel.DB(fin_name, compression=None)

    data = hexlify(db.get(key))

    db.close()

    # parse data directly
    nBlocks, offset = parse_b128(data)
    nSize, offset = parse_b128(data, offset)
    nUndoSize, offset = parse_b128(data, offset)
    nHeightFirst, offset = parse_b128(data, offset)
    nHeightLast, offset = parse_b128(data, offset)

    return b128_decode(nHeightLast)


def decode_utxo(coin, outpoint):
    """
    Decodes a LevelDB serialized UTXO for Bitcoin core v 0.15 onwards. The serialized format is defined in the Bitcoin
    Core source code as outpoint:coin.

    Outpoint structure is as follows: key | tx_hash | index.

    Where the key corresponds to b'C', or 43 in hex. The transaction hash in encoded in Little endian, and the index
    is a base128 varint. The corresponding Bitcoin Core source code can be found at:

    https://github.com/bitcoin/bitcoin/blob/ea729d55b4dbd17a53ced474a8457d4759cfb5a5/src/txdb.cpp#L40-L53

    On the other hand, a coin if formed by: code | value | out_type | script.

    Where code encodes the block height and whether the tx is coinbase or not, as 2*height + coinbase, the value is
    a txout_compressed base128 Varint, the out_type is also a base128 Varint, and the script is the remaining data.
    The corresponding Bitcoin Core soruce code can be found at:

    https://github.com/bitcoin/bitcoin/blob/6c4fecfaf7beefad0d1c3f8520bf50bb515a0716/src/coins.h#L58-L64

    :param coin: The coin to be decoded (extracted from the chainstate)
    :type coin: str
    :param outpoint: The outpoint to be decoded (extracted from the chainstate)
    :type outpoint: str
    :return; The decoded UTXO.
    :rtype: dict
    """

    # First we will parse all the data encoded in the outpoint, that is, the transaction id and index of the utxo.
    # Check that the input data corresponds to a transaction.
    assert outpoint[:2] == '43'
    # Check the provided outpoint has at least the minimum length (1 byte of key code, 32 bytes tx id, 1 byte index)
    assert len(outpoint) >= 68
    # Get the transaction id (LE) by parsing the next 32 bytes of the outpoint.
    tx_id = outpoint[2:66]
    # Finally get the transaction index by decoding the remaining bytes as a b128 VARINT
    tx_index = b128_decode(outpoint[66:])

    # Once all the outpoint data has been parsed, we can proceed with the data encoded in the coin, that is, block
    # height, whether the transaction is coinbase or not, value, script type and script.
    # We start by decoding the first b128 VARINT of the provided data, that may contain 2*Height + coinbase
    code, offset = parse_b128(coin)
    code = b128_decode(code)
    height = code >> 1
    coinbase = code & 0x01

    # The next value in the sequence corresponds to the utxo value, the amount of Satoshi hold by the utxo. Data is
    # encoded as a B128 VARINT, and compressed using the equivalent to txout_compressor.
    data, offset = parse_b128(coin, offset)
    amount = txout_decompress(b128_decode(data))

    # Finally, we can obtain the data type by parsing the last B128 VARINT
    out_type, offset = parse_b128(coin, offset)
    out_type = b128_decode(out_type)

    if out_type in [0, 1]:
        data_size = 40  # 20 bytes
    elif out_type in [2, 3, 4, 5]:
        data_size = 66  # 33 bytes (1 byte for the type + 32 bytes of data)
        offset -= 2
    # Finally, if another value is found, it represents the length of the following data, which is uncompressed.
    else:
        data_size = (out_type - NSPECIALSCRIPTS) * 2  # If the data is not compacted, the out_type corresponds
        # to the data size adding the number os special scripts (nSpecialScripts).

    # And the remaining data corresponds to the script.
    script = coin[offset:]

    # Assert that the script hash the expected length
    assert len(script) == data_size

    # And to conclude, the output can be encoded. We will store it in a list for backward compatibility with the
    # previous decoder
    out = {'amount': amount, 'out_type': out_type, 'data': script}

    # Even though there is just one output, we will identify it as outputs for backward compatibility with the previous
    # decoder.
    return {'tx_id': tx_id, 'index': tx_index, 'coinbase': coinbase, 'out': out, 'height': height}


def decompress_script(compressed_script, script_type):
    """ Takes CScript as stored in leveldb and returns it in uncompressed form
    (de)compression scheme is defined in bitcoin/src/compressor.cpp

    :param compressed_script: raw script bytes hexlified (data in decode_utxo)
    :type compressed_script: str
    :param script_type: first byte of script data (out_type in decode_utxo)
    :type script_type: int
    :return: the decompressed CScript
    :rtype: str
    """

    if script_type == 0:
        if len(compressed_script) != 40:
            raise Exception("Compressed script has wrong size")
        script = OutputScript.P2PKH(compressed_script, hash160=True)

    elif script_type == 1:
        if len(compressed_script) != 40:
            raise Exception("Compressed script has wrong size")
        script = OutputScript.P2SH(compressed_script)

    elif script_type in [2, 3]:
        if len(compressed_script) != 66:
            raise Exception("Compressed script has wrong size")
        script = OutputScript.P2PK(compressed_script)

    elif script_type in [4, 5]:
        if len(compressed_script) != 66:
            raise Exception("Compressed script has wrong size")
        prefix = format(script_type - 2, '02')
        script = OutputScript.P2PK(get_uncompressed_pk(prefix + compressed_script[2:]))

    else:
        assert len(compressed_script) / 2 == script_type - NSPECIALSCRIPTS
        script = OutputScript.from_hex(compressed_script)

    return script.content


def check_multisig(script, std=True):
    """
    Checks whether a given script is a multisig one. By default, only standard multisig script are accepted.

    :param script: The script to be checked.
    :type script: str
    :param std: Whether the script is standard or not.
    :type std: bool
    :return: True if the script is multisig (under the std restrictions), False otherwise.
    :rtype: bool
    """

    if std:
        # Standard bare Pay-to-multisig only accepts up to 3-3.
        r = range(81, 83)
    else:
        # m-of-n combination is valid up to 20.
        r = range(84, 101)

    if int(script[:2], 16) in r and script[2:4] in ["21", "41"] and script[-2:] == "ae":
        return True
    else:
        return False


def check_multisig_type(script):
    """
    Checks whether a given script is a multisig one. If it is multisig, return type (m and n values).

    :param script: The script to be checked.
    :type script: str
    :return: "multisig-m-n" or False
    """

    if len(OutputScript.deserialize(script).split()) > 2:
        m = OutputScript.deserialize(script).split()[0]
        n = OutputScript.deserialize(script).split()[-2]
        op_multisig = OutputScript.deserialize(script).split()[-1]

        if op_multisig == "OP_CHECKMULTISIG" and script[2:4] in ["21", "41"]:
            return "multisig-" + str(m) + "-" + str(n)

    return False


def check_opreturn(script):
    """
    Checks whether a given script is an OP_RETURN one.

    Warning: there should NOT be any OP_RETURN output in the UTXO set.

    :param script: The script to be checked.
    :type script: str
    :return: True if the script is an OP_RETURN, False otherwise.
    :rtype: bool
    """
    op_return_opcode = 0x6a
    return int(script[:2], 16) == op_return_opcode


def check_native_segwit(script):
    """
    Checks whether a given output script is a native SegWit type.

    :param script: The script to be checked.
    :type script: str
    :return: tuple, (True, segwit type) if the script is a native SegWit, (False, None) otherwise
    :rtype: tuple, first element boolean
    """

    if len(script) == 22*2 and script[:4] == "0014":
        return True, "P2WPKH"

    if len(script) == 34*2 and script[:4] == "0020":
        return True, "P2WSH"

    return False, None


def get_utxo(tx_id, index, fin_name):
    """
    Gets a UTXO from the chainstate identified by a given transaction id and index.
    If the requested UTXO does not exist, return None.

    :param tx_id: Transaction ID that identifies the UTXO you are looking for.
    :type tx_id: str
    :param index: Index that identifies the specific output.
    :type index: int
    :param fin_name: Name of the LevelDB folder (chainstate by default)
    :type fin_name: str
    :return: A outpoint:coin pair representing the requested UTXO
    :rtype: (str, str)
    """

    prefix = b'C'
    outpoint = prefix + lx(tx_id) + x(b128_encode(index))

    # Open the LevelDB
    db = plyvel.DB(fin_name, compression=None)  # Change with path to chainstate

    # Load obfuscation key (if it exists)
    o_key = db.get((unhexlify('0e00') + b'obfuscate_key'))

    # If the key exists, the leading byte indicates the length of the key (8 byte by default). If there is no key,
    # 8-byte zeros are used (since the key will be XORed with the given values).
    if o_key is not None:
        o_key = hexlify(o_key)[2:]

    coin = db.get(outpoint)

    if coin is not None and o_key is not None:
        coin = deobfuscate_value(o_key, hexlify(coin))

    db.close()

    return (outpoint, coin)


def get_block_index_entry(block_hash, fin_name):
    """
    TODO
    """

    prefix = b'b'
    key = prefix + lx(block_hash)

    # Open the LevelDB
    db = plyvel.DB(fin_name, compression=None)  # Change with path to chainstate

    block_info = db.get(key)

    db.close()

    return block_info


# TODO refactor significant code duplication
def put_utxo(coin, tx_id, index, fin_name):
    """
    Puts a UTXO into the chainstate under a given transaction id and index.

    :param coin: Serialized coin to put
    :type coin: bytes
    :param tx_id: Transaction ID that identifies the UTXO you are looking for.
    :type tx_id: str
    :param index: Index that identifies the specific output.
    :type index: int
    :param fin_name: Name of the LevelDB folder (chainstate by default)
    :type fin_name: str
    :return:
    :rtype:
    """

    prefix = b'C'
    outpoint = prefix + lx(tx_id) + x(b128_encode(index))

    # Open the LevelDB
    db = plyvel.DB(fin_name, compression=None)  # Change with path to chainstate

    # Load obfuscation key (if it exists)
    o_key = db.get((unhexlify('0e00') + b'obfuscate_key'))

    # If the key exists, the leading byte indicates the length of the key (8 byte by default). If there is no key,
    # 8-byte zeros are used (since the key will be XORed with the given values).
    if o_key is not None:
        o_key = hexlify(o_key)[2:]

    coin = deobfuscate_value(o_key, hexlify(coin))

    db.put(outpoint, x(coin))

    db.close()

    return (outpoint, coin)


def erase_utxo(tx_id, index, fin_name):
    """
    Erase UTXO from chainstate database.

    TODO

    :param tx_id: Transaction ID that identifies the UTXO you are looking for.
    :type tx_id: str
    :param index: Index that identifies the specific output.
    :type index: int
    :param fin_name: Name of the LevelDB folder (chainstate by default)
    :type fin_name: str
    :return:
    :rtype:
    """

    # TODO refactor significant code duplication + make cleaner in general
    (outpoint, coin) = get_utxo(tx_id, index, fin_name)
    new_coin = make_anyone_can_spend(coin)
    put_utxo(x(new_coin), tx_id, index, fin_name)


def deobfuscate_value(obfuscation_key, value):
    """
    De-obfuscate a given value parsed from the chainstate.

    :param obfuscation_key: Key used to obfuscate the given value (extracted from the chainstate).
    :type obfuscation_key: str
    :param value: Obfuscated value.
    :type value: str
    :return: The de-obfuscated value.
    :rtype: str.
    """

    l_value = len(value)
    l_obf = len(obfuscation_key)

    # Get the extended obfuscation key by concatenating the obfuscation key with itself until it is as large as the
    # value to be de-obfuscated.
    if l_obf < l_value:
        extended_key = (obfuscation_key * (int(l_value / l_obf) + 1))[:l_value]
    else:
        extended_key = obfuscation_key[:l_value]

    r = format(int(value, 16) ^ int(extended_key, 16), 'x')

    # In some cases, the obtained value could be 1 byte smaller than the original, since the leading 0 is dropped off
    # when the formatting.
    if len(r) == l_value-1:
        r = r.zfill(l_value)

    assert len(value) == len(r)

    return r


def get_min_height_to_prune_to(block_hash, data_dir, mode='testnet'):
    """TODO: Docstring for get_min_height_to_prune_to.

    :data_dir: TODO
    :mode: TODO
    :returns: TODO

    """
    fin_name = path.join(data_dir, mode, 'blocks', 'index')

    blk_n = get_blk_n_from_block_data(hexlify(get_block_index_entry(block_hash, fin_name)))
    return get_blk_max_block_height(blk_n, fin_name)


def check_if_blks_erased(block_hashes, data_dir, mode='testnet'):

    # FIXME crashes if block_hash unknown
    highest_bad_blk_n = get_heighest_bad_blk_n(block_hashes, data_dir, mode)
    highest_bad_blk_n = str(highest_bad_blk_n).zfill(5)

    unwanted_files = [
            path.join(data_dir, mode, 'blocks', 'blk%s.dat' % highest_bad_blk_n),
            path.join(data_dir, mode, 'blocks', 'rev%s.dat' % highest_bad_blk_n),
            ]

    return min(not path.isfile(f) for f in unwanted_files)


def check_if_utxos_erased(utxos, data_dir, mode='testnet'):

    return min(check_if_utxo_erased(x, data_dir, mode) for x in utxos)


def check_if_utxo_erased(utxo, data_dir, mode='testnet'):

    (tx_id, index) = utxo
    fin_name = path.join(data_dir, mode, 'chainstate')

    (outpoint, coin) = get_utxo(tx_id, index, fin_name)
    if not coin:
        return True
    else:
        return (coin == make_anyone_can_spend(coin))


def get_heighest_bad_blk_n(block_hahes, data_dir, mode='testnet'):

    fin_name = path.join(data_dir, mode, 'blocks', 'index')
    return max(map(lambda x: get_blk_n_from_block_data(hexlify(get_block_index_entry(x, fin_name))), block_hahes))


def prune_up_to(height, btc_conf_file, mode='testnet'):

    bitcoin.SelectParams(mode)

    proxy = bitcoin.rpc.Proxy(btc_conf_file=btc_conf_file)

    # TODO if fails, shows meaningful error message? (that user needs to turn on prune, e.g.)
    proxy.call('pruneblockchain', height)
