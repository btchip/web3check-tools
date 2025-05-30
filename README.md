# web3check-tools

A collection of quick & dirty unofficial tools to interact with [Ledger Transaction Check](https://www.ledger.com/blog-transaction-check) service, giving you a risk score for an EVM transaction.

## Setup 

`pip install -r requirements.txt`

## Usage

`python txcheck_api.py --fromaddress 0xaddress ---rawtx unsignedRawTxHexEncoded --chainid 1 --clientOrigin origintoken`

Use a token provided to you by Ledger. Alternatively, you can use the following token for educational purposes and personal use

`curl -s https://raw.githubusercontent.com/LedgerHQ/ledger-live/refs/heads/develop/libs/live-signer-evm/src/DmkSignerEth.ts | grep originToken`

