# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.8]: 

feat: Satodime support and shared card core

- New `src/core/`: card-agnostic APDU transport, secure channel, error base
  class (`CardError`), commands shared by every applet (authentikey, label,
  PKI) and an abstract `BaseCard` (NFC session, SELECT, secure channel).
  `detectCardType()` selects each known applet AID.
- `SatochipCard` now extends `BaseCard`. Its public API is unchanged, and
  `SatochipCardError` now extends `CardError`. Old import paths
  (`src/satochip/apduSecure`, `src/satochip/SecureChannel`) re-export the core code.
- New `SatodimeCard` (`src/satodime/`): card and Satodime status, key slot
  status, vault public keys (checked against the authentikey), ownership
  (claim with SETUP, CVC secret, unlock-code check 0x54, transfer), on-card
  hash signing (0x5B, protocol >= 0.2), seal/unseal/reset/privkey/metadata.
  Unlock codes are HMAC-SHA1(unlock_secret, inner APDU up to the counter), as
  in pysatochip. Satodime status words 0x9C50-0x9C54 map to `SatodimeCardError`.

chore: move `typescript` from dependencies to devDependencies (it conflicted
with the consumer's TypeScript when the package is linked locally).

## [0.1.7]: 

fix: keep the authentikey candidates recovered from InitiateSecureChannel on legacy applets

For applets older than v0.16 (no authentikey coordx in the response), the
candidates recovered from the authentikey signature were discarded:
Array.concat() returns a new array, and its result was ignored. The list was
always empty, so the first later check (getExtendedKey, getAuthentikey)
accepted any key. The candidates are now kept, and later responses must be
signed by the same authentikey.

test: make `yarn test` work again
- remove babel.config.js: it is CommonJS in a "type": "module" package and
  uses a preset that is not installed; babel.config.json is used instead
  (apps compile the library with their own Metro babel config)
- run jest without --experimental-vm-modules, so babel-jest compiles the
  tests and sources to CommonJS
- stub the react-native and react-native-nfc-manager peer dependencies
- fix the stale crypto import in tests/lib.test.js
- add tests for the legacy authentikey candidates

## [0.1.6]: 

fix: parse the authentikey coordx returned by InitiateSecureChannel on applet v0.16+

Since applet v0.16, the InitiateSecureChannel response ends with
[coordx_size(2b) | authentikey_coordx]. The parser read the coordx without
skipping its 2-byte size, so authentikey recovery failed with "Unable to
recover public key from signature" ("Failed to establish secure channel").
The size is now read and checked (32 bytes). Responses from older applets,
which do not contain the field, are parsed as before.
Add tests/parser.test.js covering both response formats.

## [0.1.5]: 

fix: raise the Android NFC (IsoDep) transceive timeout to 5 s

Android's default IsoDep timeout (~618 ms) is shorter than the time Satochip
applet v0.16 needs to answer InitiateSecureChannel over NFC, so the command
failed with "transceive fail" ("Failed to establish secure channel").
startConnection() now calls NfcManager.setTimeout(5000) right after
requestTechnology() on Android. iOS is unaffected.

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