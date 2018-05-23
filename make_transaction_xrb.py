#!/usr/bin/env python3
import binascii
import json
import struct

from decimal import Decimal
from pyblake2 import blake2b
from pyrai import xrb_account, pow_generate

# Usage:
# from make_transation_xrb import open_block, send_block, receive_block
#
# open_block(
#     source='FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
#     account='xrb_111111111111111111111111111111111111111111111111111111111111',
#     representative='xrb_111111111111111111111111111111111111111111111111111111111111',
# )

def hashmulti(*args):
  bh = blake2b(digest_size=32)
  for arg in args:
    bh.update(from_hex(arg))
  return bh.hexdigest()

def from_hex(hex):
  return binascii.unhexlify(hex)

def process_block_(pow_data, sign_hash, params):
  print('To sign = %s' % sign_hash)
  return sign_hash

def process_block(pow_data, sign_hash, params):
  print('To sign = %s' % sign_hash)
  print('Generating PoW...')
  params['work'] = pow_generate(pow_data)
  signature = input('signature:').strip()
  assert len(from_hex(signature)) == 64
  params['signature'] = signature

  print('Block data:')
  print(json.dumps(params))
  print('RPC command:')
  rpc = json.dumps({'action': 'process', 'block': json.dumps(params)})
  print(rpc)
  print('curl command:')
  print("curl -v -d '%s' 'http://172.18.0.6:7076/'" % rpc)
  return sign_hash


def open_block(source, account, representative):
  assert xrb_account(account) != False
  assert xrb_account(representative) != False
  assert len(from_hex(source)) == 32
  return process_block(
    xrb_account(account),
    hashmulti(source, xrb_account(representative), xrb_account(account)),
    {
      "type":           "open",
      "source":         source,
      "representative": representative,
      "account":        account,
    }
  )

def send_block(previous, destination, balance):
  assert len(from_hex(previous)) == 32
  assert xrb_account(destination) != False
  return process_block(
    previous,
    hashmulti(previous, xrb_account(destination), binascii.hexlify(balance.to_bytes(16, 'big'))),
    {
      "type":        "send",
      "previous":    previous,
      "balance":     binascii.hexlify(balance.to_bytes(16, 'big')).decode('ascii'),
      "destination": destination,
    }
  )

def receive_block(previous, source):
  assert len(from_hex(previous)) == 32
  assert len(from_hex(source)) == 32
  return process_block(
    previous,
    hashmulti(previous, source),
    {
      "type":     "receive",
      "previous": previous,
      "source":   source,
    }
  )

