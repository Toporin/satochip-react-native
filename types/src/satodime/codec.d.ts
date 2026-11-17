import { APDUCommand } from '../satochip/types';
import { KeyslotMetadata, KeyslotStatus, SatodimeCardStatus, SatodimeOwnership, SatodimePrivkey, SatodimePubkeyResponse, SatodimeStatus } from './types';
/** Default contract / tokenid field: [RFU=0x00, size=0x20, 32 zero bytes]. */
export declare function emptyTlv32(): Buffer;
export declare function encodeGetStatus(): APDUCommand;
/**
 * GET_STATUS (0x3C): [versions(4) | dummy PIN tries(4) | needs2FA(1) | is_seeded(1) | setupDone(1) | needs_secure_channel(1)]
 */
export declare function decodeCardStatus(data: Buffer): SatodimeCardStatus;
export declare function encodeGetSatodimeStatus(): APDUCommand;
/**
 * GET_SATODIME_STATUS (0x50):
 * [unlock_counter(4) | nb_slots(1) | state(nb_slots) | fixed_unlock_secret(1) | is_coa(1) | rfu1(1) | rfu2(1)]
 * The last 4 bytes only exist from protocol 0.2.
 */
export declare function decodeSatodimeStatus(data: Buffer): SatodimeStatus;
export declare function encodeGetKeyslotStatus(slot: number): APDUCommand;
/**
 * GET_SATODIME_KEYSLOT_STATUS (0x51):
 * [state(1) | key_type(1) | asset(1) | slip44(4) | contract(34) | tokenid(34) | data(66)]
 */
export declare function decodeKeyslotStatus(data: Buffer): KeyslotStatus;
export declare function encodeGetPubkey(slot: number): APDUCommand;
/** GET_SATODIME_PUBKEY (0x55) / SEAL (0x57): [pubkey_size(2) | pubkey | sig_size(2) | sig] */
export declare function decodePubkeyResponse(data: Buffer): SatodimePubkeyResponse;
/** Verify an ECDSA(SHA-256) signature made by the card authentikey. */
export declare function verifyAuthentikeySignature(signedData: Buffer, signature: Buffer, authentikey: Buffer): boolean;
/**
 * GET_SATODIME_PRIVKEY (0x56) / UNSEAL (0x58):
 * [0x0060 | user_entropy(32) | authentikey_coordx(32) | card_entropy(32) | privkey_size(2) | privkey | sig_size(2) | sig]
 */
export declare function decodePrivkeyResponse(data: Buffer): SatodimePrivkey;
/** SETUP (0x2A). The applet ignores the data and returns the new ownership data. */
export declare function encodeSetup(): APDUCommand;
/** SETUP (0x2A) response: [unlock_counter(4) | unlock_secret(20)] */
export declare function decodeSetupResponse(data: Buffer): SatodimeOwnership;
/**
 * Build a command whose data is `before | unlock_counter(4) | unlock_code(20) | after`,
 * with unlock_code = HMAC-SHA1(secret, CLA INS P1 P2 Lc | before | counter).
 */
export declare function encodeUnlockedCommand(ins: number, p1: number, p2: number, counter: Buffer, secret: Buffer, before?: Buffer, after?: Buffer): APDUCommand;
/** SIGN_SATODIME_TRANSACTION_HASH (0x5B): data [hash(32) | counter(4) | code(20)], returns DER signature. */
export declare function encodeSignTransactionHash(slot: number, hash: Buffer, counter: Buffer, secret: Buffer): APDUCommand;
/** CHECK_SATODIME_UNLOCK_CODE (0x54): data [counter(4) | code(20)]. */
export declare function encodeCheckUnlockCode(counter: Buffer, secret: Buffer): APDUCommand;
/** GET_SATODIME_PRIVKEY (0x56), unsealed vaults only. */
export declare function encodeGetPrivkey(slot: number, counter: Buffer, secret: Buffer): APDUCommand;
/** SEAL_SATODIME_KEY (0x57): uninitialized -> sealed; data [counter | code | user_entropy(32)]. */
export declare function encodeSeal(slot: number, counter: Buffer, secret: Buffer, entropy: Buffer): APDUCommand;
/** UNSEAL_SATODIME_KEY (0x58): sealed -> unsealed. */
export declare function encodeUnseal(slot: number, counter: Buffer, secret: Buffer): APDUCommand;
/** RESET_SATODIME_KEY (0x59): unsealed -> uninitialized. */
export declare function encodeReset(slot: number, counter: Buffer, secret: Buffer): APDUCommand;
/** INITIATE_SATODIME_TRANSFER (0x5A): releases ownership (setupDone = false). */
export declare function encodeTransfer(counter: Buffer, secret: Buffer): APDUCommand;
/**
 * SET_SATODIME_KEYSLOT_STATUS (0x52) P2=0x00:
 * [counter | code | RFU(1) | RFU(1) | asset(1) | slip44(4) | contract(34) | tokenid(34)]
 */
export declare function encodeSetKeyslotMetadata(slot: number, counter: Buffer, secret: Buffer, meta: KeyslotMetadata): APDUCommand;
/** SET_SATODIME_KEYSLOT_STATUS (0x52) P2=0x01: [counter | code | data(66)] */
export declare function encodeSetKeyslotData(slot: number, counter: Buffer, secret: Buffer, data: Buffer): APDUCommand;
