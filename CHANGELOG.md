# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4]: 

fix: pad recovered x-coordinate to 32 bytes in getPubkeyFromSignature()

BN.toBuffer() returns the minimum bytes needed, stripping leading zeros.                                                                                                                                                 
For secp256k1 keys whose x-coordinate has a leading zero byte (~0.4% of
keys), the recovered coordx was 31 bytes while the card-supplied coordx                                                                                                                                                  
was 32 bytes, causing Buffer.equals() to always return false across all                                                                                                                                                  
4 recovery IDs and throwing "Unable to recover public key from signature".

Fix by using toBuffer('be', 32) to force fixed-width 32-byte output.                                                                                                                                                     
Affects all callers: parseBip32GetExtendedkey, parseGetAuthentikey,
parseGetPubkeyFromKeyslot, and parseInitiateSecureChannel.

Fixes KeeperCommunity/bitcoin-keeper#6914

## [0.1.3]: 

Patch error 0x9C01 in getExtendedKey()

This error occurs when the cache memory in the card is full.
We need to flush the card cache by sending the same command with the p2 flag set to 0x80.
This patch ensures the SW_NO_MEMORY_LEFT exception is caught and treated properly.

## [0.1.2]:

* add empty certificate check during certificate validation

## [0.1.1]:

* Update metadata in package.json
* Cache BIP32 master fingerprint for card
* In cardBip32GetXpub: change order of extended key export for the given path
* throw SatochipError instead of Error
* Rework Card authenticity validation: Use asn1js to parse certificate, extract signature and use elliptic to verify signature validity
* Remove '@peculiar/x509' & '@peculiar/webcrypto' as they do not work well in react-native and generate error during execution.

## [0.1.0]:

Initial Commit