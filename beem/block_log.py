# This Python file uses the following encoding: utf-8
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from mmap import mmap, PROT_READ
import os
import struct
from datetime import datetime
from binascii import hexlify, unhexlify
from collections import OrderedDict
import sys
from beem.block import Block
from beembase.operationids import getOperationNameForId
from beembase.signedtransactions import Signed_Transaction
from beem.utils import formatTimeString
from beem.instance import shared_steem_instance

operations = {
    # vote
    0: OrderedDict([('voter', 'string'), ('author', 'string'),
                    ('permlink', 'string'), ('weight', 'uint16')]),
    # comment
    1: OrderedDict([('parent_author', 'string'), ('parent_permlink', 'string'),
                    ('author', 'string'), ('permlink', 'string'),
                    ('title', 'string'), ('body', 'string'),
                    ('json_metadata', 'string')]),
    # transfer
    2: OrderedDict([('from', 'string'), ('to', 'string'), ('amount', 'amount'),
                    ('memo', 'string')]),
    # transfer_to_vesting
    3: OrderedDict([('from', 'string'), ('to', 'string'),
                    ('amount', 'amount')]),
    # withdraw_vesting
    4: OrderedDict([('account', 'string'), ('vesting_shares', 'amount')]),
    # limit_order_create
    5: OrderedDict([('owner', 'string'), ('orderid', 'uint32'),
                    ('amount_to_sell', 'amount'),
                    ('min_to_receive', 'amount'),
                    ('fill_or_kill', 'bool'),
                    ('expiration', 'timestamp')]),
    # limit_order_cancel
    6: OrderedDict([('owner', 'string'), ('orderid', 'uint32')]),
    # feed_publish
    7: OrderedDict([('publisher', 'string'),
                    ('exchange_rate', 'exchange_rate')]),
    # convert
    8: OrderedDict([('owner', 'string'), ('requestid', 'uint32'),
                    ('amount', 'amount')]),
    # account_create
    9: OrderedDict([('fee', 'amount'), ('creator', 'string'),
                   ('new_account_name', 'string'), ('owner', 'permission'),
                   ('active', 'permission'), ('posting', 'permission'),
                   ('memo_key', 'pubkey'), ('json_metadata', 'string')]),
    # account_update
    10: OrderedDict([('account', 'string'), ('owner', 'optpermission'),
                     ('active', 'optpermission'), ('posting', 'optpermission'),
                     ('memo_key', 'pubkey'), ('json_metadata', 'string')]),
    # witness_update
    11: OrderedDict([('owner', 'string'), ('url', 'string'),
                     ('block_signing_key', 'pubkey'), ('props', 'props'),
                     ('fee', 'amount')]),
    # account_witness_vote
    12: OrderedDict([('account', 'string'), ('witness', 'string'),
                     ('approve', 'bool')]),
    # account_witness_proxy
    13: OrderedDict([('account', 'string'), ('proxy', 'string')]),
    # POW
    14: OrderedDict([('worker_account', 'string'), ('block_id', 'hex20'),
                     ('nonce', 'uint64'), ('worker', 'pubkey'),
                     ('input', 'hex32'), ('signature', 'hex65'),
                     ('work', 'hex32'), ('props', 'props')]),
    # custom
    15: OrderedDict([('required_auths', ['string']), ('id', 'uint16'),
                     ('data', 'hex')]),
    # 16: report_over_production
    # delete_comment
    17: OrderedDict([('author', 'string'), ('permlink', 'string')]),
    # custom_json
    18: OrderedDict([('required_auths', ['string']),
                     ('required_posting_auths', ['string']),
                     ('id', 'string'), ('json', 'string')]),
    # comment_options
    19: OrderedDict([('author', 'string'), ('permlink', 'string'),
                     ('max_accepted_payout', 'amount'),
                     ('percent_steem_dollars', 'uint16'),
                     ('allow_votes', 'bool'),
                     ('allow_curation_rewards', 'bool'),
                     ('extensions', ['comment_options_extension'])]),
    # set_withdraw_vesting_route
    20: OrderedDict([('from_account', 'string'), ('to_account', 'string'),
                     ('percent', 'uint16'), ('auto_vest', 'bool')]),
    # 21: limit_order_create2
    # 22: challenge_authority
    # 23: prove_authority
    # request_account_recovery
    24: OrderedDict([('recovery_account', 'string'),
                     ('account_to_recover', 'string'),
                     ('new_owner_authority', 'permission'),
                     ('extensions', ['string'])]),
    # recover_account
    25: OrderedDict([('account_to_recover', 'string'),
                     ('new_owner_authority', 'permission'),
                     ('recent_owner_authority', 'permission'),
                     ('extensions', ['string'])]),
    # change_recovery_account
    26: OrderedDict([('account_to_recover', 'string'),
                     ('new_recovery_account', 'string'),
                     ('extensions', ['string'])]),
    # escrow_transfer
    27: OrderedDict([('from', 'string'), ('to', 'string'),
                     ('sbd_amount', 'amount'), ('steem_amount', 'amount'),
                     ('escrow_id', 'uint32'), ('agent', 'string'),
                     ('fee', 'amount'), ('json_metadata', 'string'),
                     ('ratification_deadline', 'timestamp'),
                     ('escrow_expiration', 'timestamp')]),
    # escrow_dispute
    28: OrderedDict([('from', 'string'), ('to', 'string'), ('who', 'string'),
                    ('escrow_id', 'uint32')]),
    # escrow_release
    29: OrderedDict([('from', 'string'), ('to', 'string'), ('agent', 'string'),
                     ('who', 'string'), ('receiver', 'string'),
                     ('escrow_id', 'uint32'), ('sbd_amount', 'amount'),
                     ('steem_amount', 'amount')]),
    # pow2
    30: OrderedDict([('work', 'pow_work'), ('new_owner_key', 'optpubkey'),
                     ('props', 'props')]),
    # escrow_approve
    31: OrderedDict([('from', 'string'), ('to', 'string'), ('agent', 'string'),
                     ('who', 'string'), ('escrow_id', 'uint32'),
                     ('approve', 'bool')]),
    # transfer_to_savings
    32: OrderedDict([('from', 'string'), ('to', 'string'),
                     ('amount', 'amount'), ('memo', 'string')]),
    # transfer_from_savings
    33: OrderedDict([('from', 'string'), ('request_id', 'uint32'),
                     ('to', 'string'), ('amount', 'amount'),
                     ('memo', 'string')]),
    # cancel_transfer_from_savings
    34: OrderedDict([('from', 'string'), ('request_id', 'uint32')]),
    # custom_binary
    35: OrderedDict([('id', 'uint16'), ('data', 'hex')]),
    # decline_voting_rights
    # reset_account
    # set_reset_account
    # claim_reward_balance
    39: OrderedDict([('account', 'string'), ('reward_steem', 'amount'),
                     ('reward_sbd', 'amount'), ('reward_vests', 'amount')]),
    # delegate_vesting_shares
    40: OrderedDict([('delegator', 'string'), ('delegatee', 'string'),
                     ('vesting_shares', 'amount')]),
    # account_create_with_delegation
    41: OrderedDict([('fee', 'amount'), ('delegation', 'amount'),
                     ('creator', 'string'), ('new_account_name', 'string'),
                     ('owner', 'permission'), ('active', 'permission'),
                     ('posting', 'permission'), ('memo_key', 'pubkey'),
                     ('json_metadata', 'string'), ('extensions', ['string'])]),
}

class BlockReader(object):
    def __init__(self, data, offset=0, size=0, steem_instance=None,
                 timestamp_format='datetime', amount_format='string',
                 key_format='hex'):
        self.data = data
        self.size = size or len(data)
        self.offset = offset
        self.steem = steem_instance or shared_steem_instance()
        timestamp_formats = ['datetime', 'unix', 'string']
        if timestamp_format not in timestamp_formats:
            raise ValueError("timestamp_format most be one of %s" %
                             (timestamp_formats))
        self.timestamp_format = timestamp_format
        amount_formats = ['amount', 'string']
        if amount_format not in amount_formats:
            raise ValueError("amount_format most be one of %s" %
                             (amount_formats))
        self.amount_format = amount_format
        key_formats = ['hex', 'string', 'publickey']
        if key_format not in key_formats:
            raise ValueError("key_formats mist be one of %s" %
                             (key_formats))
        self.key_format = key_format

    def get(self, datatype, offset=None, length=0):
        if offset is not None:
            self.offset = offset
        # lists
        if isinstance(datatype, list):
            nentries = self.get('varint')
            entries = []
            for idx in range(nentries):
                entries.append(self.get(datatype[0]))
            return entries
        # optional fields
        if datatype.startswith('opt'):
            if not self.get('bool'):
                return None
            return self.get(datatype[3:])
        # uint8
        if datatype == 'uint8':
            offset = self.offset
            self.offset += 1
            return struct.unpack("<B", self.data[offset:offset + 1])[0]
        # uint16
        if datatype == 'uint16':
            offset = self.offset
            self.offset += 2
            return struct.unpack("<H", self.data[offset:offset + 2])[0]
        # uint32
        if datatype == 'uint32':
            offset = self.offset
            self.offset += 4
            return struct.unpack("<I", self.data[offset:offset + 4])[0]
        # uint64
        if datatype == 'uint64':
            offset = self.offset
            self.offset += 8
            return struct.unpack("<Q", self.data[offset:offset + 8])[0]
        # boolean
        if datatype == 'bool':
            return (self.get('uint8') != 0)
        # hexadecimal
        if datatype.startswith('hex'):
            if len(datatype) > 3:
                length = int(datatype[3:])
            if length == 0:
                length = self.get('varint')
            offset = self.offset
            self.offset += length
            return hexlify(self.data[offset:offset+length]).decode('utf-8')
        # timestamp
        if datatype == 'timestamp':
            unix_ts = self.get('uint32')
            if self.timestamp_format == 'unix':
                return unix_ts
            datetime_ts = datetime.utcfromtimestamp(unix_ts)
            if self.timestamp_format == 'datetime':
                return datetime_ts
            return formatTimeString(datetime_ts)
        # variable int
        if datatype == 'varint':
            i = 0
            varint = 0
            while True:
                bits = self.get('uint8')
                varint |= (bits & 0x7f) << (i * 7)
                i += 1
                if bits & 0x80 == 0:
                    break
            return varint
        # string
        if datatype == 'string':
            if not length:
                length = self.get('varint')
            offset = self.offset
            self.offset += length
            return self.data[offset:offset + length].decode('utf-8')
        # amount
        if datatype == 'amount':
            amount = self.get('uint64')
            precision = self.get('uint8')
            symbol = self.get('string', length=7)
            amount = amount / (10 ** precision)
            symbol = symbol.replace("\x00", "")
            if self.amount_format == 'dict':
                return {'amount': amount, 'asset': symbol}
            if self.amount_format == 'string':
                if precision == 6:
                    return "%.6f %s" % (amount, symbol)
                if precision == 3:
                    return "%.3f %s" % (amount, symbol)
            return Amount(amount, symbol, steem_instance=self.steem)
        # public keys
        if datatype == 'pubkey':
            key = self.get('hex33')
            if self.key_format == 'hex':
                return key
            pk = PublicKey(key, prefix=self.steem.prefix)
            if self.key_format == 'string':
                return repr(pk)
            return pk
        # key authorities
        if datatype == 'key_authority':
            return [self.get('pubkey'), self.get('uint16')]
        # account authorities
        if datatype == 'account_authority':
            return [self.get('string'), self.get('uint16')]
        # account permissions
        if datatype == 'permission':
            perm = {'account_auths': [], 'key_auths': []}
            perm['weight_threshold'] = self.get('uint32')
            num_account_auths = self.get('uint8')
            for idx in range(num_account_auths):
                perm['account_auths'].append(self.get('account_authority'))
            num_key_auths = self.get('uint8')
            for idx in range(num_key_auths):
                perm['key_auths'].append(self.get('key_authority'))
            return perm
        if datatype == 'pow_work':
            index = self.get('uint8')
            op = {'input': {}}
            op['input']['worker_account'] = self.get('string')
            op['input']['prev_block'] = self.get('hex20')
            op['input']['nonce'] = self.get('uint64')
            if index == 1:
                proof = {}
                proof['n'], offset = self.get('uint32')
                proof['k'], offset = self.get('uint32')
                proof['seed'], offset = self.get('hex32')
                ninputs = self.get('varint')
                proof['inputs'] = []
                for idx in range(ninputs):
                    value = self.get('uint32')
                    proof['inputs'].append(value)
                op['proof'] = proof
                op['prev_block'], offset = self.get('hex20')
            op['pow_summary'], offset = self.get('uint32')
            return op
        # witness properties
        if datatype == 'props':
            props = {}
            props['account_creation_fee'] = self.get('amount')
            props['maximum_block_size'] = self.get('uint32')
            props['sbd_interest_rate'] = self.get('uint16')
            return props
        # block extensions
        if datatype == 'block_extensions':
            ext_len = self.get('uint8')
            extensions = []
            for idx in range(ext_len):
                hf_format = self.get('uint8')
                major = self.get('uint8')
                minor = self.get('uint8')
                release = self.get('uint16')
                hf_version = "%d.%d.%d" % (major, minor, release)
                if hf_format == 1:
                    extensions.append([hf_format, hf_version])
                else:
                    hf_time, offset = self.get('timestamp')
                    extensions.append([hf_format, {'hf_version': hf_version,
                                                   'hf_time': hf_time}])
            return extensions
        # beneficiary entry
        if datatype == 'beneficiary':
            account = self.get('string')
            weight = self.get('uint16')
            return {'account': account, 'weight': weight}
        # comment_options_extension
        if datatype == 'comment_options_extension':
            ext_id = self.get('uint8')
            if ext_id != 0:
                raise ValueError("Unknown comment options extension type")
            beneficiaries = self.get(['beneficiary'])
            return [0, {'beneficiaries': beneficiaries}]
        # exchange rate
        if datatype ==  'exchange_rate':
            base = self.get('amount')
            quote = self.get('amount')
            return {'base': base, 'quote': quote}
        # unknown datatype
        raise ValueError("Invalid datatype %s" % (datatype))

    def get_operation(self, offset=None):
        if offset is not None:
            self.offset = offset
        op_id = self.get('uint8')
        op = {}
        if op_id not in operations:
            raise ValueError("Operation ID %d not implemented" % (op_id))
        for key in operations[op_id]:
            datatype = operations[op_id][key]
            value = self.get(datatype)
            if isinstance(datatype, str) and datatype.startswith('opt') and \
               value is None:
                # skip optional fields
                continue
            op[key] = value
        return [getOperationNameForId(op_id), op]

    def get_transaction(self, offset=None):
        if offset is not None:
            self.offset = offset
        trx = {}
        trx['ref_block_num'] = self.get('uint16')
        trx['ref_block_prefix'] = self.get('uint32')
        trx['expiration'] = self.get('timestamp')
        num_operations = self.get('varint')
        trx['operations'] = []
        for op_id in range(num_operations):
            op = self.get_operation()
            trx['operations'].append(op)
        trx['extensions'] = self.get(['string'])  # FIXME
        num_signatures = self.get('varint')
        trx['signatures'] = []
        for sig_idx in range(num_signatures):
            sig = self.get('hex', length=65)
            trx['signatures'].append(sig)
        return trx


    def get_block(self, offset=None):
        if offset is not None:
            self.offset = offset
        block = {}
        block['previous'] = self.get('hex', length=20)
        block_num = int(block['previous'][:8], 16) + 1
        block['block_num'] = block_num
        block['block_id'] = "%08x" % (block_num)
        block['timestamp'] = self.get('timestamp')
        block['witness'] = self.get('string')
        block['transaction_merkle_root'] = self.get('hex', length=20)
        block['extensions'] = self.get('block_extensions')
        block['witness_signature'] = self.get('hex', length=65)
        number_of_transactions = self.get('varint')
        block['transactions'] = []
        for trx_id in range(number_of_transactions):
            trx = self.get_transaction()
            block['transactions'].append(trx)
        block['transaction_ids'] = list(range(number_of_transactions))  # FIXME
        start_offset = self.get('uint64')
        return block



def getMMap(filename):
    fd = os.open(filename, os.O_RDONLY)
    memorymap = mmap(fd, 0, prot=PROT_READ)
    os.close(fd)
    return memorymap

class BlockLog(object):
    def __init__(self, filename, steem_instance=None):
        self.steem = steem_instance
        self.log = getMMap(filename)
        self.block_reader = BlockReader(self.log,
                                        steem_instance=steem_instance)

        index_filename = os.path.join(os.path.dirname(filename),
                                      'index_log')
        try:
            self.index = getMMap(index_filename)
        except FileNotFoundError:
            self.index = None
        self.offset = 0

    def get_block_by_offset(self, offset=None):
        return self.block_reader.get_block(offset)

    def get_block_by_number(self, block_num):
        if not self.index:
            raise

    def blocks(self, start=None, stop=None):
        while self.block_reader.offset < len(self.log):
            b = self.block_reader.get_block()
            if stop is not None and b['block_num'] > stop:
                return
            yield Block(b, steem_instance=self.steem)

    def stream(self, start=None, stop=None, opNames=[], raw_ops=False):
        for block in self.blocks(start=start, stop=stop):
            if 'transactions' not in block:
                continue
            for trx_num in range(len(block['transactions'])):
                if 'operations' not in block['transactions'][trx_num]:
                    continue
                for operation in block['transactions'][trx_num]['operations']:
                    op_type, op = operation
                    if not bool(opNames) or op_type in opNames:
                        trx_id = block["transaction_ids"][trx_num]
                        block_num = block.get("block_num")
                        timestamp = block.get("timestamp")
                        if raw_ops:
                            yield {"block_num": block_num, "trx_num":
                                   trx_num, "op": [op_type, op],
                                   "timestamp": timestamp}
                        else:
                            op['type'] = op_type
                            op['timestamp'] = timestamp
                            op['block_num'] = block_num
                            op['trx_num'] = trx_num
                            yield op
