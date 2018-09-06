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

operations = {
    # vote
    0: OrderedDict([('voter', 'string'), ('author', 'string'),
                    ('permlink', 'string'), ('weight', 'ushort')]),
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
    5: OrderedDict([('owner', 'string'), ('orderid', 'uint'),
                    ('amount_to_sell', 'amount'),
                    ('min_to_receive', 'amount'),
                    ('fill_or_kill', 'bool'),
                    ('expiration', 'timestamp')]),
    # limit_order_cancel
    6: OrderedDict([('owner', 'string'), ('orderid', 'uint')]),
    # feed_publish
    7: OrderedDict([('publisher', 'string'),
                    ('exchange_rate', 'exchange_rate')]),
    # convert
    8: OrderedDict([('owner', 'string'), ('requestid', 'uint'),
                    ('amount', 'amount')]),
    # account_create
    9: OrderedDict([('fee', 'amount'), ('creator', 'string'),
                   ('new_account_name', 'string'), ('owner', 'permission'),
                   ('active', 'permission'), ('posting', 'permission'),
                   ('memo_key', 'publickey'), ('json_metadata', 'string')]),
    # account_update
    10: OrderedDict([('account', 'string'), ('owner', 'optpermission'),
                     ('active', 'optpermission'), ('posting', 'optpermission'),
                     ('memo_key', 'publickey'), ('json_metadata', 'string')]),
    # witness_update
    11: OrderedDict([('owner', 'string'), ('url', 'string'),
                     ('block_signing_key', 'publickey'), ('props', 'props'),
                     ('fee', 'amount')]),
    # account_witness_vote
    12: OrderedDict([('account', 'string'), ('witness', 'string'),
                     ('approve', 'bool')]),
    # account_witness_proxy
    13: OrderedDict([('account', 'string'), ('proxy', 'string')]),
    # POW
    14: OrderedDict([('worker_account', 'string'), ('block_id', 'hex20'),
                     ('nonce', 'ull'), ('worker', 'publickey'),
                     ('input', 'hex32'), ('signature', 'hex65'),
                     ('work', 'hex32'), ('props', 'props')]),
    # custom
    15: OrderedDict([('required_auths', ['string']), ('id', 'ushort'),
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
                     ('percent_steem_dollars', 'ushort'),
                     ('allow_votes', 'bool'),
                     ('allow_curation_rewards', 'bool'),
                     ('extensions', ['comment_options_extension'])]),
    # set_withdraw_vesting_route
    20: OrderedDict([('from_account', 'string'), ('to_account', 'string'),
                     ('percent', 'ushort'), ('auto_vest', 'bool')]),
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
                     ('escrow_id', 'uint'), ('agent', 'string'),
                     ('fee', 'amount'), ('json_metadata', 'string'),
                     ('ratification_deadline', 'timestamp'),
                     ('escrow_expiration', 'timestamp')]),
    # escrow_dispute
    28: OrderedDict(['from', 'string'), ('to', 'string'), ('who', 'string'),
                    ('escrow_id', 'uint')]),
    # escrow_release
    29: OrderedDict([('from', 'string'), ('to', 'string'), ('agent', 'string'),
                     ('who', 'string'), ('receiver', 'string'),
                     ('escrow_id', 'uint'), ('sbd_amount', 'amount'),
                     ('steem_amount', 'amount')]),
    # pow2
    30: OrderedDict([('work', 'pow_work'), ('new_owner_key', 'optpublickey'),
                     ('props', 'props')]),
    # escrow_approve
    31: OrderedDict([('from', 'string'), ('to', 'string'), ('agent', 'string'),
                     ('who', 'string'), ('escrow_id', 'uint'),
                     ('approve', 'bool')]),
    # transfer_to_savings
    32: OrderedDict([('from', 'string'), ('to', 'string'),
                     ('amount', 'amount'), ('memo', 'string')]),
    # transfer_from_savings
    33: OrderedDict([('from', 'string'), ('request_id', 'uint'),
                     ('to', 'string'), ('amount', 'amount'),
                     ('memo', 'string')]),
    # cancel_transfer_from_savings
    34: OrderedDict([('from', 'string'), ('request_id', 'uint')]),
    # custom_binary
    35: OrderedDict([('id', 'ushort'), ('data', 'hex')]),
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
                     ('posting', 'permission'), ('memo_key', 'publickey'),
                     ('json_metadata', 'string'), ('extensions', ['string'])]),
}

def getMMap(filename):
    fd = os.open(filename, os.O_RDONLY)
    memorymap = mmap(fd, 0, prot=PROT_READ)
    fd.close()
    return memorymap

class BlockLog(object):
    def __init__(self, filename):
        self.log = getMMap(filename)
        index_filename = os.path.join(os.path.dirname(filename),
                                      'index_log')
        try:
            self.index = getMMap(index_filename)
        except FileNotFoundError:
            self.index = None
