# Part of web3check-tools
# MIT license
# Nicolas Bacca, 2025

import struct
import binascii
import sys

def parseDER(data, offset):
   if (data[offset] & 0x80) != 0:
      length = data[offset] & 0x7f
      if length > 4:
         raise Exception("Invalid DER length")
      tmp = b"\x00" * (4 - length)
      tmp = tmp + data[offset + 1 : offset + 1 + length]
      return (struct.unpack(">I", tmp)[0], offset + 1 + length)
   else:
      return (data[offset], offset + 1)

def encodeDER(value):
   # max() to have minimum length of 1
   value_bytes = value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big')
   if value >= 0x80:
      value_bytes = (0x80 | len(value_bytes)).to_bytes(1, 'big') + value_bytes
   return value_bytes


def parseTLV(data, offset):
   (tag, offset) = parseDER(data, offset)
   (length, offset) = parseDER(data, offset)
   return (tag, data[offset : offset + length], offset + length)

def parseTLVList(data):
   offset = 0
   result = {}
   while offset != len(data):
      (tag, value, offset) = parseTLV(data, offset)
      result[tag] = value
   return result

def encodeTLVList(list):
   result = b''
   for tag in list:
      result = result + encodeDER(tag) + encodeDER(len(list[tag])) + list[tag]
   return result

if __name__ == "__main__":
   result = parseTLVList(binascii.unhexlify(sys.argv[1]))
   print(result)

