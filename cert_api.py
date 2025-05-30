# Part of web3check-tools
# MIT license
# Nicolas Bacca, 2025

import requests
import json
import sys
import binascii
import struct
from secp256k1 import PublicKey
from dertlv import parseTLVList

DEFAULT_URL = "https://crypto-assets-service.api.ledger.com/v1/certificates"
DEFAULT_CLIENT_VERSION = "context-module/1.3.1"

# https://github.com/LedgerHQ/speculos/blob/master/src/bolos/os_signature.c
ROOT_CA_PUBLIC_KEY = binascii.unhexlify("04e6b35148bf556ca90bac3a4e85c0081e558124ceeb3c7d72f914100f8b2ad6509a552236a3486ef0af3a1ef87d865583a9a74d8e5db81edddc8776211e6c70ff")

# https://github.com/LedgerHQ/speculos/blob/master/src/bolos/os_pki.h
TAG_STRUCTURE_TYPE = 0x01
TAG_STRUCTURE_VERSION = 0x02
TAG_VALIDITY = 0x10
TAG_VALIDITY_INDEX = 0x11
TAG_CHALLENGE = 0x12
TAG_SIGNER_KEY_ID = 0x13
TAG_SIGN_ALGO_ID = 0x14
TAG_SIGNATURE = 0x15
TAG_TIME_VALIDITY = 0x16
TAG_TRUSTED_NAME = 0x20
TAG_PUBLIC_KEY_ID = 0x30
TAG_PUBLIC_KEY_USAGE = 0x31
TAG_PUBLIC_KEY_CURVE_ID = 0x32
TAG_COMPRESSED_PUBLIC_KEY = 0x33
TAG_PK_SIGN_ALGO_ID = 0x34
TAG_TARGET_DEVICE = 0x35
TAG_DEPTH = 0x36


TAGS = {
   TAG_STRUCTURE_TYPE : "structureType",
   TAG_STRUCTURE_VERSION : "structureVersion",
   TAG_VALIDITY : "validity",
   TAG_VALIDITY_INDEX : "validityIndex",
   TAG_CHALLENGE : "challenge",
   TAG_SIGNER_KEY_ID : "signerKeyId",
   TAG_SIGN_ALGO_ID : "signAlgoId",
   TAG_TIME_VALIDITY : "timeValidity",
   TAG_TRUSTED_NAME : "trustedName",
   TAG_PUBLIC_KEY_ID : "publicKeyId",
   TAG_PUBLIC_KEY_USAGE : "publicKeyUsage",
   TAG_PUBLIC_KEY_CURVE_ID : "publicKeyCurveId",
   TAG_COMPRESSED_PUBLIC_KEY : "compressedPublicKey",
   TAG_PK_SIGN_ALGO_ID : "pkSignAlgoId",
   TAG_TARGET_DEVICE : "targetDevice",
   TAG_DEPTH : "depth",
   TAG_SIGNATURE : "signature"
}

def _0x(data):
   if data[0:2] != "0x" and data[0:2] != "0X":
      return "0x" + data
   return data

def _transform(key, data):
   if key == TAG_STRUCTURE_TYPE or key == TAG_STRUCTURE_VERSION or key == TAG_SIGN_ALGO_ID or key == TAG_PUBLIC_KEY_USAGE or key == TAG_PUBLIC_KEY_CURVE_ID or key == TAG_PK_SIGN_ALGO_ID or key == TAG_TARGET_DEVICE or key == TAG_DEPTH:
      return struct.unpack(">B", data)[0]
   if key == TAG_SIGNER_KEY_ID or key == TAG_PUBLIC_KEY_ID:
      return struct.unpack(">H", data)[0]
   if key == TAG_COMPRESSED_PUBLIC_KEY:
      return binascii.hexlify(data).decode('utf-8')
   if key == TAG_VALIDITY or key == TAG_VALIDITY_INDEX or key == TAG_TIME_VALIDITY:
      return struct.unpack(">I", data)[0]
   if key == TAG_TRUSTED_NAME:
        return data.decode("utf-8")
   return data

def certQuery(certName, url=DEFAULT_URL, clientVersion=DEFAULT_CLIENT_VERSION):
   headers = { "x-ledger-client-version": clientVersion }
   url = url + "?output=descriptor&target_device=flex&latest=true&public_key_usage=tx_simu_signer&public_key_id=" + certName
   r = requests.get(url, headers=headers)
   result = json.loads(r.text)
   return result

def decodeDescriptor(descriptor):
   descriptor = parseTLVList(descriptor)
   descriptorDecoded = {}
   for key in descriptor:
      tag = TAGS[key] if key in TAGS else key
      descriptorDecoded[tag] = _transform(key, descriptor[key])
   return descriptorDecoded

def verifyResponse(response):
   descriptor = decodeDescriptor(binascii.unhexlify(response['descriptor']['data']))
   if descriptor['signerKeyId'] == 2 and descriptor['signAlgoId'] == 1:
      publicKey = PublicKey(ROOT_CA_PUBLIC_KEY, raw=True)
      signature = publicKey.ecdsa_deserialize(binascii.unhexlify(response['descriptor']['signatures']['prod']))
      result = publicKey.ecdsa_verify(binascii.unhexlify(response['descriptor']['data']), signature)
      return result
   return None   

if __name__ == "__main__":
   result = certQuery(sys.argv[1])
   print(result)
   if len(result) == 0:
      raise Exception("Unknown certificate")
   descriptor = decodeDescriptor(binascii.unhexlify(result[0]['descriptor']['data']))
   print(descriptor)
   print("Public key for " + descriptor['trustedName'] + " " + descriptor['compressedPublicKey'])
   verifyStatus = verifyResponse(result[0])
   if verifyStatus == None:
      print("Couldn't verify certificate")
   else:
      print("Certificate signature verified " + str(verifyStatus))   

