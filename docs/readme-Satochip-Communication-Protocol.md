# Satochip Communication Protocol

This document describes the APDU commands supported by the Satochip applet for secure hardware wallet operations. All commands use the CLA byte `0xB0` unless otherwise specified.

## Table of Contents

- [General Information](#general-information)
- [Card Management Commands](#card-management-commands)
- [PIN Management Commands](#pin-management-commands)
- [BIP32 Hierarchical Deterministic Wallet Commands](#bip32-hierarchical-deterministic-wallet-commands)
- [Signature Commands](#signature-commands)
- [2FA Commands](#2fa-commands)
- [PKI Commands](#pki-commands)
- [Secure Channel Commands](#secure-channel-commands)
- [Error Codes](#error-codes)

## General Information

### APDU Structure
All APDUs follow the standard ISO 7816-4 structure:
- **CLA**: Command class (always `0xB0` for Satochip)
- **INS**: Instruction code
- **P1**: Parameter 1
- **P2**: Parameter 2
- **Lc**: Length of command data (optional)
- **Data**: Command data (optional)
- **Le**: Length of expected response data (optional)

### Secure Channel
Most commands require secure channel encryption when the applet is configured to need it. The secure channel provides:
- Command encryption/decryption
- Response integrity protection
- Replay attack prevention

## Card Management Commands

### SELECT Applet
Selects the Satochip applet on the card.

**APDU Format:**
- **CLA**: `0x00`
- **INS**: `0xA4`
- **P1**: `0x04`
- **P2**: `0x00`
- **Data**: `5361746f43686970` (ASCII: "SatoChip")

**Response:** Application selection response

**Possible Errors:**
- `0x6A82`: File not found (applet not installed)

### GET_STATUS (0x3C)
Retrieves general information about the applet and current session status.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x3C`
- **P1**: `0x00`
- **P2**: `0x00`
- **Data**: (none)

**Response Data:**
```
[protocol_version(2b) | applet_version(2b) | 
 pin0_tries(1b) | puk0_tries(1b) | pin1_tries(1b) | puk1_tries(1b) |
 needs_2fa(1b) | is_seeded(1b) | setup_done(1b) | needs_secure_channel(1b) |
 nfc_policy(1b) | schnorr_policy(1b) | nostr_policy(1b) | liquid_policy(1b) | musig2_policy(1b)]
```

**Possible Errors:** None (always succeeds)

### SETUP (0x2A)
Performs initial setup of the card with PIN/PUK configuration and memory allocation.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x2A`
- **P1**: `0x00`
- **P2**: `0x00`
- **Data**: 
```
[default_pin_length(1b) | default_pin | 
 pin_tries0(1b) | ublk_tries0(1b) | pin0_length(1b) | pin0 | ublk0_length(1b) | ublk0 | 
 pin_tries1(1b) | ublk_tries1(1b) | pin1_length(1b) | pin1 | ublk1_length(1b) | ublk1 | 
 secmemsize(2b) | RFU(2b) | RFU(3b) |
 option_flags(2b) | 
 (optional): hmacsha1_key(20b) | amount_limit(8b)]
```

**Response:** (none)

**Possible Errors:**
- `0x9C07`: Setup already done
- `0x9C0F`: Invalid parameter (PIN policy violation)

### CARD_LABEL (0x3D)
Sets or retrieves a human-readable label for the card.

**Get Label:**
- **CLA**: `0xB0`
- **INS**: `0x3D`
- **P1**: `0x00`
- **P2**: `0x01`
- **Data**: (none)

**Set Label:**
- **CLA**: `0xB0`
- **INS**: `0x3D`
- **P1**: `0x00`
- **P2**: `0x00`
- **Data**: `[label_size(1b) | label]`

**Response (Get):** `[label_size(1b) | label]`

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C0F`: Invalid parameter

### SET_NFC_POLICY (0x3E)
Configures the NFC interface access policy.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x3E`
- **P1**: NFC policy value
  - `0x00`: NFC enabled
  - `0x01`: NFC disabled (can be re-enabled)
  - `0x02`: NFC blocked (requires factory reset to re-enable)
- **P2**: `0x00` (reserved)
- **Data**: (none)

**Response:** (none)

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C48`: NFC disabled (command sent via NFC)
- `0x9C49`: NFC blocked permanently

### SET_FEATURE_POLICY (0x3A)
Configures access policies for optional features.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x3A`
- **P1**: Feature ID
  - `0x00`: Schnorr signatures
  - `0x01`: Nostr support
  - `0x02`: Liquid Bitcoin support
  - `0x03`: MuSig2 support
- **P2**: Policy value
  - `0x00`: Feature enabled
  - `0x01`: Feature disabled (can be re-enabled)
  - `0x02`: Feature blocked (requires factory reset)
- **Data**: (none)

**Response:** (none)

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C10`: Incorrect P1 (invalid feature ID)
- `0x9C11`: Incorrect P2 (invalid policy)
- `0x9C4B`: Feature already blocked

### RESET_TO_FACTORY (0xFF)
Resets the card to factory state (requires multiple invocations).

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0xFF`
- **P1**: `0x00`
- **P2**: `0x00`
- **Data**: (none)

**Response:** Status indicating remaining reset attempts

**Possible Errors:**
- `0xFF00`: Factory reset completed
- `0xFFxx`: Factory reset in progress (xx = remaining attempts)

## PIN Management Commands

### VERIFY_PIN (0x42)
Verifies a PIN to authenticate the user.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x42`
- **P1**: PIN number (`0x00` for PIN0, `0x01` for PIN1)
- **P2**: `0x00`
- **Data**: PIN bytes

**Response:** (none)

**Possible Errors:**
- `0x63C0-0x63CF`: Wrong PIN (last nibble = remaining attempts)
- `0x9C02`: Authentication failed (legacy)
- `0x9C0C`: PIN blocked
- `0x9C10`: Incorrect P1 (invalid PIN number)
- `0x9C0F`: Invalid parameter (PIN policy violation)

### CHANGE_PIN (0x44)
Changes a PIN from old value to new value.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x44`
- **P1**: PIN number (`0x00` or `0x01`)
- **P2**: `0x00`
- **Data**: `[old_pin_length(1b) | old_pin | new_pin_length(1b) | new_pin]`

**Response:** (none)

**Possible Errors:**
- `0x63C0-0x63CF`: Wrong old PIN
- `0x9C0C`: PIN blocked
- `0x9C0F`: Invalid parameter (PIN policy violation)

### UNBLOCK_PIN (0x46)
Unblocks a blocked PIN using the PUK.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x46`
- **P1**: PIN number (`0x00` or `0x01`)
- **P2**: `0x00`
- **Data**: PUK bytes

**Response:** (none)

**Possible Errors:**
- `0x63C0-0x63CF`: Wrong PUK
- `0x9C03`: Operation not allowed (PIN not blocked)
- `0x9C0C`: PUK blocked

### CREATE_PIN (0x40)
Creates a new PIN/PUK pair.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x40`
- **P1**: PIN number (`0x00`-`0x07`)
- **P2**: Maximum retry attempts
- **Data**: `[pin_length(1b) | pin | puk_length(1b) | puk]`

**Response:** (none)

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN0 required)
- `0x9C10`: Incorrect P1 (PIN already exists)
- `0x9C0F`: Invalid parameter (PIN policy violation)

### LIST_PINS (0x48)
Lists available PINs as a bitmask.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x48`
- **P1**: `0x00`
- **P2**: `0x00`
- **Data**: (none)

**Response:** `[RFU(1b) | pin_mask(1b)]`

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN0 required)

### LOGOUT_ALL (0x60)
Logs out all authenticated identities.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x60`
- **P1**: `0x00`
- **P2**: `0x00`
- **Data**: (none)

**Response:** (none)

**Possible Errors:** None

## BIP32 Hierarchical Deterministic Wallet Commands

### BIP32_IMPORT_SEED (0x6C)
Imports a master seed for BIP32 key derivation.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x6C`
- **P1**: Seed length in bytes
- **P2**: `0x00`
- **Data**: Master seed bytes (16-64 bytes)

**Response:** `[coordx_size(2b) | coordx | sig_size(2b) | sig]`

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C17`: Seed already initialized
- `0x6700`: Wrong length

### BIP32_RESET_SEED (0x77)
Resets the BIP32 seed (requires PIN and optional 2FA).

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x77`
- **P1**: PIN length
- **P2**: `0x00`
- **Data**: `[pin | (optional)hmac_2fa(20b)]`

**Response:** (none)

**Possible Errors:**
- `0x63C0-0x63CF`: Wrong PIN
- `0x9C14`: Seed not initialized
- `0x9C0B`: Invalid 2FA signature
- `0x6700`: Wrong length

### BIP32_GET_AUTHENTIKEY (0x73)
Retrieves the authentication key derived from the seed.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x73`
- **P1**: `0x00`
- **P2**: `0x00`
- **Data**: (none)

**Response:** `[coordx_size(2b) | coordx | sig_size(2b) | sig]`

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C14`: Seed not initialized

### BIP32_GET_EXTENDED_KEY (0x6D)
Derives an extended key for the specified BIP32 path.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x6D`
- **P1**: Depth (number of derivation levels)
- **P2**: Option flags
  - `0x80`: Reset cache memory
  - `0x40`: Optimize for non-hardened derivation
  - `0x20`: Store key as object
- **Data**: Path indices (4 bytes per level)

**Response:** `[chaincode(32b) | coordx_size(2b) | coordx | sig_size(2b) | self_sig | sig_size(2b) | authentikey_sig]`

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C14`: Seed not initialized
- `0x9C10`: Incorrect P1 (depth > 10)
- `0x9C01`: No memory left
- `0x9C0E`: BIP32 derivation error

### BIP32_GET_LIQUID_MASTER_BLINDING_KEY (0x7D)
Retrieves the Liquid Bitcoin master blinding key.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x7D`
- **P1**: `0x00`
- **P2**: `0x00`
- **Data**: (none)

**Response:** `[blinding_key_size(2b) | blinding_key(32b) | sig_size(2b) | authentikey_sig]`

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C14`: Seed not initialized
- `0x9C4A`: Feature disabled

## Signature Commands

### SIGN_MESSAGE (0x6E)
Signs a message using Bitcoin message signing format.

**Init:**
- **P1**: Key number (`0xFF` for BIP32 key)
- **P2**: `0x01` (OP_INIT)
- **Data**: `[msg_size(4b) | (optional)altcoin_size(1b) | altcoin_name]`

**Process:**
- **P2**: `0x02` (OP_PROCESS)
- **Data**: `[chunk_size(2b) | chunk_data]`

**Finalize:**
- **P2**: `0x03` (OP_FINALIZE)
- **Data**: `[chunk_size(2b) | final_chunk | (optional)hmac_2fa(20b)]`

**Response (Finalize):** DER-encoded signature

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C10`: Incorrect P1 (invalid key number)
- `0x9C14`: Seed not initialized (for 0xFF key)
- `0x9C13`: Incorrect initialization
- `0x9C0B`: Invalid 2FA signature

### SIGN_TRANSACTION_HASH (0x7A)
Signs a transaction hash directly.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x7A`
- **P1**: Key number (`0xFF` for BIP32 key)
- **P2**: `0x00`
- **Data**: `[hash(32b) | (optional)2fa_flag(2b) | hmac_2fa(20b)]`

**Response:** DER-encoded signature

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C10`: Incorrect P1 (invalid key number)
- `0x9C14`: Seed not initialized
- `0x9C09`: Incorrect algorithm (2FA flag wrong)
- `0x9C0B`: Invalid 2FA signature
- `0x6700`: Wrong length

### PARSE_TRANSACTION (0x71)
Parses a raw Bitcoin transaction and returns the hash.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x71`
- **P1**: `0x01` (OP_INIT) or `0x02` (OP_PROCESS)
- **P2**: `0x00` (standard) or `0x01` (SegWit)
- **Data**: Raw transaction data

**Response:** 
- **Process**: Transaction context data
- **Finished**: `[hash_size(2b) | hash(32b) | needs_2fa(2b) | sig_size(2b) | sig | tx_context]`

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x6700`: Wrong data (transaction parsing error)

### SIGN_TRANSACTION (0x6F)
Signs a parsed transaction using cached hash.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x6F`
- **P1**: Key number (`0xFF` for BIP32 key)
- **P2**: `0x00`
- **Data**: `[hash(32b) | (optional)2fa_flag(2b) | hmac_2fa(20b)]`

**Response:** DER-encoded signature

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C15`: Incorrect transaction hash
- `0x9C0B`: Invalid 2FA signature

### TAPROOT_TWEAK_PRIVKEY (0x7C)
Generates a Taproot-tweaked private key for Schnorr signatures.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x7C`
- **P1**: Key number (`0xFF` for BIP32 key)
- **P2**: `0x00` (apply tweak) or `0x01` (bypass tweak for Nostr)
- **Data**: `[tweak_size(1b) | tweak(32b)]`

**Response:** `[coordx_size(2b) | coordx | sig_size(2b) | authentikey_sig]`

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C10`: Incorrect P1
- `0x9C14`: Seed not initialized
- `0x9C4A`: Feature disabled (Nostr mode)
- `0x9C43`: Taproot tweak error
- `0x6700`: Wrong length

### SIGN_SCHNORR_HASH (0x7B)
Signs a hash using Schnorr signature algorithm (BIP340).

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x7B`
- **P1**: `0x00`
- **P2**: `0x00`
- **Data**: `[hash(32b) | (optional)2fa_flag(2b) | hmac_2fa(20b)]`

**Response:** 64-byte Schnorr signature

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C4A`: Feature disabled
- `0x9C09`: Incorrect algorithm (2FA flag)
- `0x9C0B`: Invalid 2FA signature
- `0x6700`: Wrong length

### MUSIG2_GENERATE_NONCE (0x7E)
Generates nonce for MuSig2 signing protocol.

**Init:**
- **P1**: Key number (`0xFF` for BIP32 key)
- **P2**: `0x01` (OP_INIT)
- **Data**: `[aggpk_size(1b) | aggpk | msg_size(1b) | msg | extra_size(1b) | extra]`

**Response (Init):** `[pubnonce(66b)]`

**Finalize:**
- **P2**: `0x03` (OP_FINALIZE)
- **Data**: (none)

**Response (Finalize):** `[encrypted_secnonce(144b)]`

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C4A`: Feature disabled
- `0x9C10`: Incorrect P1
- `0x9C14`: Seed not initialized
- `0x9C46`: Counter overflow
- `0x9C0F`: Invalid parameter

### MUSIG2_SIGN_HASH (0x7F)
Performs partial signature in MuSig2 protocol.

**Init:**
- **P1**: Key number
- **P2**: `0x01` (OP_INIT)
- **Data**: `[encrypted_secnonce(144b)]`

**Finalize:**
- **P2**: `0x03` (OP_FINALIZE)
- **Data**: `[b(32b) | ea(32b) | r_evenness(1b) | ggacc(1b)]`

**Response (Finalize):** `[psig(32b)]`

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C4A`: Feature disabled
- `0x9C44`: Wrong secnonce
- `0x9C47`: Invalid nonce ID
- `0x9C45`: Public key mismatch

## 2FA Commands

### SET_2FA_KEY (0x79)
Sets up two-factor authentication with HMAC key.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x79`
- **P1**: `0x00`
- **P2**: `0x00`
- **Data**: `[hmac_key(20b) | amount_limit(8b)]`

**Response:** (none)

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C18`: 2FA already initialized
- `0x6700`: Wrong length

### RESET_2FA_KEY (0x78)
Resets/disables two-factor authentication.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x78`
- **P1**: `0x00`
- **P2**: `0x00`
- **Data**: `[hmac_verification(20b)]`

**Response:** (none)

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C19`: 2FA not initialized
- `0x9C0B`: Invalid signature
- `0x6700`: Wrong length

### CRYPT_TRANSACTION_2FA (0x76)
Encrypts/decrypts transaction data for 2FA device communication.

**Init Encrypt:**
- **P1**: `0x01` (MODE_ENCRYPT)
- **P2**: `0x01` (OP_INIT)
- **Data**: (none)

**Init Decrypt:**
- **P1**: `0x02` (MODE_DECRYPT)
- **P2**: `0x01` (OP_INIT)
- **Data**: `[IV(16b)]`

**Process/Finalize:**
- **P2**: `0x02` (OP_PROCESS) or `0x03` (OP_FINALIZE)
- **Data**: `[chunk_size(2b) | chunk_data]`

**Response:**
- **Init Encrypt**: `[IV(16b) | 2fa_id(20b)]`
- **Process/Finalize**: `[chunk_size(2b) | processed_data]`

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C19`: 2FA not initialized
- `0x9C0F`: Invalid parameter
- `0x9C11`: Incorrect P2

## PKI Commands

### EXPORT_PKI_PUBKEY (0x98)
Exports the PKI public key for device authentication.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x98`
- **P1**: `0x00`
- **P2**: `0x00`
- **Data**: (none)

**Response:** `[pubkey(65b)]`

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)

### SIGN_PKI_CSR (0x94)
Signs a Certificate Signing Request with the device key.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x94`
- **P1**: `0x00`
- **P2**: `0x00`
- **Data**: `[hash(32b)]`

**Response:** DER-encoded signature

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C40`: PKI already locked
- `0x6700`: Wrong length

### IMPORT_PKI_CERTIFICATE (0x92)
Imports the device certificate (chunked transfer).

**Init:**
- **P1**: `0x00`
- **P2**: `0x01` (OP_INIT)
- **Data**: `[total_size(2b)]`

**Process:**
- **P2**: `0x02` (OP_PROCESS)
- **Data**: `[chunk_offset(2b) | chunk_size(2b) | chunk_data]`

**Response:** (none)

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C40`: PKI already locked
- `0x6700`: Wrong length

### EXPORT_PKI_CERTIFICATE (0x93)
Exports the device certificate (chunked transfer).

**Init:**
- **P1**: `0x00`
- **P2**: `0x01` (OP_INIT)
- **Data**: (none)

**Response (Init):** `[total_size(2b)]`

**Process:**
- **P2**: `0x02` (OP_PROCESS)
- **Data**: `[chunk_offset(2b) | chunk_size(2b)]`

**Response (Process):** Certificate chunk data

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)

### LOCK_PKI (0x99)
Locks the PKI configuration permanently.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x99`
- **P1**: `0x00`
- **P2**: `0x00`
- **Data**: (none)

**Response:** (none)

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)

### CHALLENGE_RESPONSE_PKI (0x9A)
Performs challenge-response authentication with device key.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x9A`
- **P1**: `0x00`
- **P2**: `0x00`
- **Data**: `[challenge(32b)]`

**Response:** `[device_challenge(32b) | sig_size(2b) | signature]`

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C0B`: Signature invalid
- `0x6700`: Wrong length

## Secure Channel Commands

### INIT_SECURE_CHANNEL (0x81)
Initiates secure channel establishment with the card.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x81`
- **P1**: `0x00`
- **P2**: `0x00`
- **Data**: `[client_pubkey(65b)]`

**Response:** `[coordx_size(2b) | card_pubkey_x | sig_size(2b) | self_sig | sig2_size(2b) | auth_sig]`

**Possible Errors:**
- `0x9C0F`: Invalid parameter (wrong pubkey format)

### PROCESS_SECURE_CHANNEL (0x82)
Processes encrypted secure channel messages.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x82`
- **P1**: `0x00`
- **P2**: `0x00`
- **Data**: `[IV(16b) | data_size(2b) | encrypted_data | mac_size(2b) | mac(20b)]`

**Response:** Decrypted command data

**Possible Errors:**
- `0x9C21`: Secure channel uninitialized
- `0x9C22`: Wrong IV
- `0x9C23`: Wrong MAC
- `0x6700`: Wrong length

### IMPORT_ENCRYPTED_SECRET (0xAC)
Imports encrypted secrets from a trusted source (SeedKeeper).

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0xAC`
- **P1**: `0x00`
- **P2**: `0x00`
- **Data**: `[header(12b) | IV(16b) | encrypted_secret_size(2b) | encrypted_secret | hmac_size(1b) | hmac(20b)]`

**Response:** Depends on secret type (same as import operations)

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C35`: No trusted public key
- `0x9C32`: Imported data too long
- `0x9C33`: Wrong MAC
- `0x9C34`: Wrong fingerprint

### IMPORT_TRUSTED_PUBKEY (0xAA)
Imports a trusted public key for secure secret import.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0xAA`
- **P1**: `0x00`
- **P2**: `0x00`
- **Data**: `[pubkey_size(2b) | pubkey(65b)]`

**Response:** `[coordx_size(2b) | coordx | sig_size(2b) | sig]`

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C17`: Seed already initialized
- `0x9C0F`: Invalid parameter

### EXPORT_TRUSTED_PUBKEY (0xAB)
Exports the currently stored trusted public key.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0xAB`
- **P1**: `0x00`
- **P2**: `0x00`
- **Data**: (none)

**Response:** `[pubkey_size(2b) | pubkey(65b) | sig_size(2b) | authentikey_sig]`

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C35`: No trusted public key

### EXPORT_AUTHENTIKEY (0xAD)
Exports the device's authentication key.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0xAD`
- **P1**: `0x00`
- **P2**: `0x00`
- **Data**: (none)

**Response:** `[coordx_size(2b) | coordx | sig_size(2b) | sig]`

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)

## Key Management Commands

### IMPORT_KEY (0x32)
Imports a private EC key into a specific key slot.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x32`
- **P1**: Key number (`0x00`-`0x0F`)
- **P2**: `0x00`
- **Data**: `[key_encoding(1b) | key_type(1b) | key_size(2b) | RFU(6b) | blob_size(2b) | key_blob(32b) | (optional)hmac_2fa(20b)]`

**Response:** (none)

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C10`: Incorrect P1 (invalid key number)
- `0x9C05`: Unsupported feature (wrong encoding)
- `0x9C09`: Incorrect algorithm (wrong key type)
- `0x9C0F`: Invalid parameter (wrong key size)
- `0x9C03`: Operation not allowed (key already exists)
- `0x9C0B`: Invalid 2FA signature

### RESET_KEY (0x33)
Resets/clears a private key from a key slot.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x33`
- **P1**: Key number (`0x00`-`0x0F`)
- **P2**: `0x00`
- **Data**: `[(optional)hmac_2fa(20b)]`

**Response:** (none)

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C10`: Incorrect P1 (key doesn't exist)
- `0x9C0B`: Invalid 2FA signature

### GET_PUBLIC_FROM_PRIVATE (0x35)
Retrieves the public key corresponding to a private key slot.

**APDU Format:**
- **CLA**: `0xB0`
- **INS**: `0x35`
- **P1**: Key number (`0x00`-`0x0F`)
- **P2**: `0x00`
- **Data**: (none)

**Response:** `[coordx_size(2b) | coordx(32b) | sig_size(2b) | signature]`

**Possible Errors:**
- `0x9C06`: Unauthorized (PIN required)
- `0x9C10`: Incorrect P1 (key doesn't exist or not initialized)
- `0x9C09`: Incorrect algorithm (wrong key type/size)

## Error Codes

### Success Codes
| Code | Name | Description |
|------|------|-------------|
| `0x9000` | `SW_OK` | Command executed successfully |

### PIN/Authentication Errors
| Code | Name | Description |
|------|------|-------------|
| `0x63C0-0x63CF` | `SW_PIN_FAILED` | Wrong PIN (last nibble = remaining attempts) |
| `0x9C02` | `SW_AUTH_FAILED` | Authentication failed (deprecated) |
| `0x9C06` | `SW_UNAUTHORIZED` | PIN verification required |
| `0x9C0C` | `SW_IDENTITY_BLOCKED` | PIN/PUK blocked after max attempts |

### Setup and State Errors
| Code | Name | Description |
|------|------|-------------|
| `0x9C04` | `SW_SETUP_NOT_DONE` | Card setup required |
| `0x9C07` | `SW_SETUP_ALREADY_DONE` | Card already set up |
| `0x9C17` | `SW_BIP32_INITIALIZED_SEED` | BIP32 seed already exists |
| `0x9C14` | `SW_BIP32_UNINITIALIZED_SEED` | BIP32 seed not initialized |
| `0x9C18` | `SW_2FA_INITIALIZED_KEY` | 2FA already set up |
| `0x9C19` | `SW_2FA_UNINITIALIZED_KEY` | 2FA not initialized |
| `0x9C1A` | `SW_ECKEYS_INITIALIZED_KEY` | EC key already exists |

### Parameter and Operation Errors
| Code | Name | Description |
|------|------|-------------|
| `0x9C03` | `SW_OPERATION_NOT_ALLOWED` | Operation not allowed |
| `0x9C05` | `SW_UNSUPPORTED_FEATURE` | Feature not supported |
| `0x9C09` | `SW_INCORRECT_ALG` | Wrong algorithm specified |
| `0x9C0F` | `SW_INVALID_PARAMETER` | Invalid parameter |
| `0x9C10` | `SW_INCORRECT_P1` | Invalid P1 parameter |
| `0x9C11` | `SW_INCORRECT_P2` | Invalid P2 parameter |
| `0x9C13` | `SW_INCORRECT_INITIALIZATION` | Wrong initialization |

### Memory and Resource Errors
| Code | Name | Description |
|------|------|-------------|
| `0x9C01` | `SW_NO_MEMORY_LEFT` | Insufficient memory |

### Cryptographic Errors
| Code | Name | Description |
|------|------|-------------|
| `0x9C0B` | `SW_SIGNATURE_INVALID` | Invalid signature |
| `0x9C0E` | `SW_BIP32_DERIVATION_ERROR` | BIP32 key derivation failed |
| `0x9C15` | `SW_INCORRECT_TXHASH` | Wrong transaction hash |
| `0x9C43` | `SW_TAPROOT_TWEAK_ERROR` | Taproot key tweaking failed |

### Secure Channel Errors
| Code | Name | Description |
|------|------|-------------|
| `0x9C20` | `SW_SECURE_CHANNEL_REQUIRED` | Secure channel required |
| `0x9C21` | `SW_SECURE_CHANNEL_UNINITIALIZED` | Secure channel not established |
| `0x9C22` | `SW_SECURE_CHANNEL_WRONG_IV` | Invalid initialization vector |
| `0x9C23` | `SW_SECURE_CHANNEL_WRONG_MAC` | Invalid message authentication code |

### Import/Export Errors
| Code | Name | Description |
|------|------|-------------|
| `0x9C32` | `SW_IMPORTED_DATA_TOO_LONG` | Import data exceeds limits |
| `0x9C33` | `SW_SECURE_IMPORT_WRONG_MAC` | Invalid import MAC |
| `0x9C34` | `SW_SECURE_IMPORT_WRONG_FINGERPRINT` | Wrong import fingerprint |
| `0x9C35` | `SW_SECURE_IMPORT_NO_TRUSTEDPUBKEY` | No trusted public key |

### PKI Errors
| Code | Name | Description |
|------|------|-------------|
| `0x9C40` | `SW_PKI_ALREADY_LOCKED` | PKI configuration locked |

### NFC and Feature Policy Errors
| Code | Name | Description |
|------|------|-------------|
| `0x9C48` | `SW_NFC_DISABLED` | NFC interface disabled |
| `0x9C49` | `SW_NFC_BLOCKED` | NFC interface permanently blocked |
| `0x9C4A` | `SW_FEATURE_DISABLED` | Optional feature disabled |
| `0x9C4B` | `SW_FEATURE_BLOCKED` | Optional feature permanently blocked |

### MuSig2 Specific Errors
| Code | Name | Description |
|------|------|-------------|
| `0x9C44` | `SW_BIP327_WRONG_SECNONCE` | Invalid secret nonce |
| `0x9C45` | `SW_BIP327_PUBKEY_MISMATCH` | Public key mismatch |
| `0x9C46` | `SW_BIP327_COUNTER_OVERFLOW` | Nonce counter overflow |
| `0x9C47` | `SW_BIP327_INVALID_ID` | Invalid nonce ID |

### HMAC Errors
| Code | Name | Description |
|------|------|-------------|
| `0x9C1E` | `SW_HMAC_UNSUPPORTED_KEYSIZE` | HMAC key size not supported |
| `0x9C1F` | `SW_HMAC_UNSUPPORTED_MSGSIZE` | HMAC message size not supported |

### Special Codes
| Code | Name | Description |
|------|------|-------------|
| `0x9C26` | `SW_INS_DEPRECATED` | Instruction deprecated |
| `0xFF00` | `SW_RESET_TO_FACTORY` | Factory reset completed |
| `0x9CFF` | `SW_INTERNAL_ERROR` | Internal error (debugging) |
| `0x9FFF` | `SW_DEBUG_FLAG` | Debug flag (debugging) |

### Standard ISO7816 Codes
| Code | Name | Description |
|------|------|-------------|
| `0x6700` | `SW_WRONG_LENGTH` | Wrong length in Lc or Le |
| `0x6982` | `SW_SECURITY_CONDITION_NOT_SATISFIED` | Security condition not satisfied |
| `0x6985` | `SW_CONDITIONS_OF_USE_NOT_SATISFIED` | Conditions of use not satisfied |
| `0x6A82` | `SW_FILE_NOT_FOUND` | File/application not found |
| `0x6D00` | `SW_INS_NOT_SUPPORTED` | Instruction not supported |

## Protocol Notes

### BIP32 Path Format
BIP32 paths are encoded as a series of 4-byte big-endian integers:
- Hardened derivation: Add `0x80000000` to the index
- Example: `m/44'/0'/0'/0/0` becomes `[0x8000002C, 0x80000000, 0x80000000, 0x00000000, 0x00000000]`

### 2FA Challenge-Response Format
When 2FA is enabled, certain operations require a 20-byte HMAC-SHA1 challenge-response:
- **Transaction signing**: `HMAC-SHA1(key, hash || 0x00...00)`
- **Key import**: `HMAC-SHA1(key, pubkey_x || (0x10^key_nb)...)`
- **Key reset**: `HMAC-SHA1(key, pubkey_x || (0x20^key_nb)...)`
- **Seed reset**: `HMAC-SHA1(key, authentikey_x || 0xFF...FF)`
- **Message signing**: `HMAC-SHA1(key, hash || 0xBB...BB)`
- **Hash signing**: `HMAC-SHA1(key, hash || 0xCC...CC)`
- **Schnorr signing**: `HMAC-SHA1(key, hash || 0xDD...DD)`

### Secure Channel Protocol
1. Client generates ECDH key pair
2. `INIT_SECURE_CHANNEL` exchanges public keys
3. Both sides compute shared secret using ECDH
4. Session keys derived using HMAC-SHA1
5. Subsequent commands encrypted with AES-128-CBC
6. MAC verification prevents tampering

### Message Signing Format
Bitcoin message signing prepends the message with a standard header:
```
[0x18] "Bitcoin Signed Message:\n" [message_length_varint] [message]
```
For altcoins, the header format can be customized in the init phase.