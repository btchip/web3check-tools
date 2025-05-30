# Part of web3check-tools
# MIT license
# Nicolas Bacca, 2025

import requests
import json
import sys
import binascii
import struct
import argparse
from secp256k1 import PublicKey
from Crypto.Util.asn1 import DerSequence 
from dertlv import parseTLVList, encodeTLVList
import cert_api

DEFAULT_URL = "https://web3checks-backend.api.ledger.com/v3/ethereum/scan/tx"
DEFAULT_CLIENT_ORIGIN = "origin-token"
DEFAULT_CLIENT_VERSION = "context-module/1.3.1"

# https://github.com/LedgerHQ/app-ethereum/blob/develop/src_features/provide_tx_simulation/cmd_get_tx_simulation.c
TAG_STRUCTURE_TYPE = 0x01
TAG_STRUCTURE_VERSION = 0x02
TAG_ADDRESS = 0x22
TAG_CHAINID = 0x23
TAG_TXHASH = 0x27
TAG_DOMAIN_HASH = 0x28
TAG_W3C_NORMALIZED_RISK = 0x80
TAG_W3C_NORMALIZED_CATEGORY = 0x81
TAG_W3C_PROVIDER_MSG = 0x82
TAG_W3C_TINY_URL = 0x83
TAG_W3C_SIMU_TYPE = 0x84
TAG_SIGNATURE = 0x15

TAGS = {
	TAG_STRUCTURE_TYPE : "structureType",
	TAG_STRUCTURE_VERSION : "structureVersion",
	TAG_ADDRESS : "address",
	TAG_CHAINID : "chainId",
	TAG_TXHASH : "txHash",
	TAG_DOMAIN_HASH : "domainHash",
	TAG_W3C_NORMALIZED_RISK : "w3cNormalizedRisk",
	TAG_W3C_NORMALIZED_CATEGORY : "w3cNormalizedCategory",
	TAG_W3C_PROVIDER_MSG : "w3cProviderMsg",
	TAG_W3C_TINY_URL : "w3cTinyUrl",
	TAG_W3C_SIMU_TYPE : "w3cSimuType",
	TAG_SIGNATURE : "signature"
}

# https://github.com/LedgerHQ/app-ethereum/blob/develop/src_features/provide_tx_simulation/cmd_get_tx_simulation.h
RISK = {
   0 : "Unknown",
   1 : "Benign",
   2 : "Warning",
   3 : "Malicious"
}

def _0x(data):
   if data[0:2] != "0x" and data[0:2] != "0X":
      return "0x" + data
   return data

def _transform(key, data):
   if key == TAG_STRUCTURE_TYPE or key == TAG_STRUCTURE_VERSION or key == TAG_W3C_NORMALIZED_RISK or key == TAG_W3C_NORMALIZED_CATEGORY or key == TAG_W3C_SIMU_TYPE:
      return struct.unpack(">B", data)[0]
   if key == TAG_ADDRESS or key == TAG_TXHASH:
   	  return "0x" + binascii.hexlify(data).decode('utf-8')
   if key == TAG_CHAINID:
      return struct.unpack(">Q", data)[0]
   if key == TAG_W3C_PROVIDER_MSG or key == TAG_W3C_TINY_URL:
   	  return data.decode("utf-8")
   return data

def call_txCheck(fromAddress, rawtx, chainId, url=DEFAULT_URL, clientOrigin=DEFAULT_CLIENT_ORIGIN, clientVersion=DEFAULT_CLIENT_VERSION):
   data = { "tx" : { "from": _0x(fromAddress), "raw": _0x(rawtx) }, "chain": int(chainId) }
   headers = { "x-ledger-client-origin": clientOrigin, "x-ledger-client-version": clientVersion }
   r = requests.post(url, data=json.dumps(data), headers=headers)
   result = json.loads(r.text)
   return result

def decodeDescriptor(descriptor):
   descriptor = parseTLVList(descriptor)
   descriptorDecoded = {}
   for key in descriptor:
      tag = TAGS[key] if key in TAGS else key
      descriptorDecoded[tag] = _transform(key, descriptor[key])
   return descriptorDecoded

def canonicalize(signature):
    SMAX = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
    ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    seq = DerSequence()
    seq.decode(signature)
    if seq[1] >= SMAX:
        seq[1] = ORDER - seq[1]
    return seq.encode()

def txCheck(fromAddress, rawtx, chainId, descriptorPublicKey=None, url=DEFAULT_URL, clientOrigin=DEFAULT_CLIENT_ORIGIN, clientVersion=DEFAULT_CLIENT_VERSION):
   result = call_txCheck(fromAddress, rawtx, chainId, url, clientOrigin, clientVersion)
   if not 'descriptor' in result:
      print(result)
      raise Exception("Invalid response")
   descriptor = decodeDescriptor(binascii.unhexlify(result['descriptor']))
   if descriptorPublicKey == None:
      certResult = cert_api.certQuery(result['public_key_id'])
      if len(result) == 0:
         raise Exception("Unknown certificate")
      certDescriptor = cert_api.decodeDescriptor(binascii.unhexlify(certResult[0]['descriptor']['data']))
      verifyStatus = cert_api.verifyResponse(certResult[0])
      if verifyStatus == None:
         raise Exception("Couldn't verify certificate")
      descriptorPublicKey = binascii.unhexlify(certDescriptor['compressedPublicKey'])
   unsignedDescriptor = parseTLVList(binascii.unhexlify(result['descriptor']))
   del unsignedDescriptor[TAG_SIGNATURE]
   unsignedDescriptor = encodeTLVList(unsignedDescriptor)
   publicKey = PublicKey(descriptorPublicKey, raw=True)
   signature = publicKey.ecdsa_deserialize(canonicalize(descriptor['signature']))
   result = publicKey.ecdsa_verify(unsignedDescriptor, signature)
   if not result:
      raise Exception("Couldn't verify response signature")
   return descriptor


if __name__ == "__main__":
   parser = argparse.ArgumentParser(description="Run a remote transaction check")
   parser.add_argument("--fromaddress", help="From Address (0x...)")
   parser.add_argument("--rawtx", help="Raw unsigned transaction")
   parser.add_argument("--chainid", help="Chain ID", type=int)
   parser.add_argument("--clientOrigin", help="Client Origin Token", default=DEFAULT_CLIENT_ORIGIN)
   parser.add_argument("--clientVersion", help="Client Version", default=DEFAULT_CLIENT_VERSION)
   parser.add_argument("--url", help="Service URL", default=DEFAULT_URL)
   parser.add_argument("--publicKey", help="Descriptor signature public key, overrides certificate")
   parser.add_argument("--verbose", help="Display additional information", action='store_true')

   args = parser.parse_args(sys.argv[1:])
   descriptor = txCheck(args.fromaddress, args.rawtx, args.chainid, args.publicKey, args.url, args.clientOrigin, args.clientVersion)
   if args.verbose:
      print(descriptor)
   riskLevel = descriptor['w3cNormalizedRisk']
   message = descriptor['w3cProviderMsg']
   print("Risk level : " + str(riskLevel) + " (" + RISK[riskLevel + 1] + ")")
   if len(message) != 0:
      print("Additional provider information : " + message)
   print("Information URL : " + descriptor['w3cTinyUrl'])
