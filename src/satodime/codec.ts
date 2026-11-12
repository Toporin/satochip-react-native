/**
 * Satodime APDU encoding / response decoding.
 *
 * Pure functions (no NFC): every layout below follows Satodime-Applet
 * (branch support-dynamic-ndef). Commands are sent through the secure channel
 * by SatodimeCard, except GET_STATUS (0x3C) which is sent in plain.
 */
import * as crypto from 'crypto';
import { ec as EC } from 'elliptic';
import { APDUCommand } from '../satochip/types';
import { parseCardVersion } from '../core/status';
import {
  INS_CHECK_SATODIME_UNLOCK_CODE,
  INS_GET_SATODIME_KEYSLOT_STATUS,
  INS_GET_SATODIME_PRIVKEY,
  INS_GET_SATODIME_PUBKEY,
  INS_GET_SATODIME_STATUS,
  INS_GET_STATUS,
  INS_INITIATE_SATODIME_TRANSFER,
  INS_RESET_SATODIME_KEY,
  INS_SEAL_SATODIME_KEY,
  INS_SET_SATODIME_KEYSLOT_STATUS,
  INS_SETUP,
  INS_SIGN_SATODIME_TRANSACTION_HASH,
  INS_UNSEAL_SATODIME_KEY,
  KeyslotState,
  MAX_NUM_KEYSLOTS,
  SATODIME_CLA,
  SIZE_CONTRACT,
  SIZE_DATA,
  SIZE_ENTROPY,
  SIZE_KEYSLOT_STATUS,
  SIZE_SLIP44,
  SIZE_TOKENID,
  SIZE_UNLOCK_COUNTER,
  SIZE_UNLOCK_SECRET,
} from './constants';
import {
  KeyslotMetadata,
  KeyslotStatus,
  SatodimeCardStatus,
  SatodimeOwnership,
  SatodimePrivkey,
  SatodimePubkeyResponse,
  SatodimeStatus,
} from './types';
import { computeUnlockCode } from './unlock';

const secp256k1 = new EC('secp256k1');

function checkSlot(slot: number): void {
  if (!Number.isInteger(slot) || slot < 0 || slot >= MAX_NUM_KEYSLOTS) {
    throw new Error(`Invalid vault index: ${slot}`);
  }
}

function checkCounter(counter: Buffer): void {
  if (counter.length !== SIZE_UNLOCK_COUNTER) {
    throw new Error('Invalid unlock counter length');
  }
}

/** Default contract / tokenid field: [RFU=0x00, size=0x20, 32 zero bytes]. */
export function emptyTlv32(): Buffer {
  const b = Buffer.alloc(SIZE_CONTRACT, 0);
  b[1] = 0x20;
  return b;
}

// ========================================
// Plain / read-only commands
// ========================================

export function encodeGetStatus(): APDUCommand {
  return { cla: SATODIME_CLA, ins: INS_GET_STATUS, p1: 0x00, p2: 0x00 };
}

/**
 * GET_STATUS (0x3C): [versions(4) | dummy PIN tries(4) | needs2FA(1) | is_seeded(1) | setupDone(1) | needs_secure_channel(1)]
 */
export function decodeCardStatus(data: Buffer): SatodimeCardStatus {
  if (data.length < 12) {
    throw new Error(`Invalid Satodime status length: ${data.length}`);
  }
  return {
    version: parseCardVersion(data),
    setupDone: data[10] === 0x01,
    needsSecureChannel: data[11] === 0x01,
  };
}

export function encodeGetSatodimeStatus(): APDUCommand {
  return { cla: SATODIME_CLA, ins: INS_GET_SATODIME_STATUS, p1: 0x00, p2: 0x00 };
}

/**
 * GET_SATODIME_STATUS (0x50):
 * [unlock_counter(4) | nb_slots(1) | state(nb_slots) | fixed_unlock_secret(1) | is_coa(1) | rfu1(1) | rfu2(1)]
 * The last 4 bytes only exist from protocol 0.2.
 */
export function decodeSatodimeStatus(data: Buffer): SatodimeStatus {
  if (data.length < SIZE_UNLOCK_COUNTER + 1) {
    throw new Error('Invalid Satodime status response');
  }
  const unlockCounter = Buffer.from(data.slice(0, SIZE_UNLOCK_COUNTER));
  const nbKeyslots = data[SIZE_UNLOCK_COUNTER];
  const statesStart = SIZE_UNLOCK_COUNTER + 1;
  if (data.length < statesStart + nbKeyslots) {
    throw new Error('Invalid Satodime status response: missing keyslot states');
  }
  const keyslotStates: KeyslotState[] = [];
  for (let i = 0; i < nbKeyslots; i++) {
    keyslotStates.push(data[statesStart + i] as KeyslotState);
  }
  const flagsStart = statesStart + nbKeyslots;
  const status: SatodimeStatus = { unlockCounter, nbKeyslots, keyslotStates };
  if (data.length > flagsStart) {
    status.fixedUnlockSecret = data[flagsStart] === 0x01;
  }
  if (data.length > flagsStart + 1) {
    status.isCoA = data[flagsStart + 1] === 0x01;
  }
  return status;
}

export function encodeGetKeyslotStatus(slot: number): APDUCommand {
  checkSlot(slot);
  return { cla: SATODIME_CLA, ins: INS_GET_SATODIME_KEYSLOT_STATUS, p1: slot, p2: 0x00 };
}

/**
 * GET_SATODIME_KEYSLOT_STATUS (0x51):
 * [state(1) | key_type(1) | asset(1) | slip44(4) | contract(34) | tokenid(34) | data(66)]
 */
export function decodeKeyslotStatus(data: Buffer): KeyslotStatus {
  if (data.length < SIZE_KEYSLOT_STATUS) {
    throw new Error(`Invalid keyslot status length: ${data.length}`);
  }
  let offset = 0;
  const state = data[offset++] as KeyslotState;
  const keyType = data[offset++];
  const asset = data[offset++];
  const slip44 = data.readUInt32BE(offset);
  offset += SIZE_SLIP44;
  const contract = Buffer.from(data.slice(offset, offset + SIZE_CONTRACT));
  offset += SIZE_CONTRACT;
  const tokenId = Buffer.from(data.slice(offset, offset + SIZE_TOKENID));
  offset += SIZE_TOKENID;
  const keyData = Buffer.from(data.slice(offset, offset + SIZE_DATA));
  return {
    state,
    keyType,
    asset,
    slip44,
    isTestnet: (slip44 & 0x80000000) === 0,
    contract,
    tokenId,
    data: keyData,
  };
}

export function encodeGetPubkey(slot: number): APDUCommand {
  checkSlot(slot);
  return { cla: SATODIME_CLA, ins: INS_GET_SATODIME_PUBKEY, p1: slot, p2: 0x00 };
}

/** GET_SATODIME_PUBKEY (0x55) / SEAL (0x57): [pubkey_size(2) | pubkey | sig_size(2) | sig] */
export function decodePubkeyResponse(data: Buffer): SatodimePubkeyResponse {
  if (data.length < 2) {
    throw new Error('Invalid pubkey response');
  }
  const pubkeySize = data.readUInt16BE(0);
  if (pubkeySize !== 65 || data.length < 2 + pubkeySize + 2) {
    throw new Error(`Invalid pubkey response (size ${pubkeySize})`);
  }
  const pubkey = Buffer.from(data.slice(2, 2 + pubkeySize));
  if (pubkey[0] !== 0x04) {
    throw new Error('Invalid pubkey encoding');
  }
  const signedData = Buffer.from(data.slice(0, 2 + pubkeySize));
  const sigSize = data.readUInt16BE(2 + pubkeySize);
  const signature = Buffer.from(data.slice(4 + pubkeySize, 4 + pubkeySize + sigSize));
  if (signature.length !== sigSize || sigSize === 0) {
    throw new Error('Invalid pubkey response: missing signature');
  }
  return { pubkey, signedData, signature };
}

/** Verify an ECDSA(SHA-256) signature made by the card authentikey. */
export function verifyAuthentikeySignature(signedData: Buffer, signature: Buffer, authentikey: Buffer): boolean {
  try {
    const digest = crypto.createHash('sha256').update(signedData).digest();
    return secp256k1.keyFromPublic(authentikey).verify(digest, signature);
  } catch {
    return false;
  }
}

/**
 * GET_SATODIME_PRIVKEY (0x56) / UNSEAL (0x58):
 * [0x0060 | user_entropy(32) | authentikey_coordx(32) | card_entropy(32) | privkey_size(2) | privkey | sig_size(2) | sig]
 */
export function decodePrivkeyResponse(data: Buffer): SatodimePrivkey {
  let offset = 0;
  const entropySize = data.readUInt16BE(offset);
  offset += 2;
  if (entropySize !== 3 * SIZE_ENTROPY || data.length < offset + entropySize + 2) {
    throw new Error('Invalid privkey response');
  }
  const userEntropy = Buffer.from(data.slice(offset, offset + SIZE_ENTROPY));
  offset += SIZE_ENTROPY;
  const authentikeyCoordx = Buffer.from(data.slice(offset, offset + SIZE_ENTROPY));
  offset += SIZE_ENTROPY;
  const cardEntropy = Buffer.from(data.slice(offset, offset + SIZE_ENTROPY));
  offset += SIZE_ENTROPY;
  const privkeySize = data.readUInt16BE(offset);
  offset += 2;
  const privkey = Buffer.from(data.slice(offset, offset + privkeySize));
  offset += privkeySize;
  const signedData = Buffer.from(data.slice(0, offset));
  const sigSize = data.readUInt16BE(offset);
  offset += 2;
  const signature = Buffer.from(data.slice(offset, offset + sigSize));
  if (privkey.length !== privkeySize || signature.length !== sigSize) {
    throw new Error('Invalid privkey response: truncated');
  }
  return { privkey, userEntropy, authentikeyCoordx, cardEntropy, signedData, signature };
}

// ========================================
// Ownership
// ========================================

/** SETUP (0x2A). The applet ignores the data and returns the new ownership data. */
export function encodeSetup(): APDUCommand {
  return { cla: SATODIME_CLA, ins: INS_SETUP, p1: 0x00, p2: 0x00 };
}

/** SETUP (0x2A) response: [unlock_counter(4) | unlock_secret(20)] */
export function decodeSetupResponse(data: Buffer): SatodimeOwnership {
  if (data.length < SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_SECRET) {
    throw new Error('Invalid setup response');
  }
  return {
    unlockCounter: Buffer.from(data.slice(0, SIZE_UNLOCK_COUNTER)),
    unlockSecret: Buffer.from(data.slice(SIZE_UNLOCK_COUNTER, SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_SECRET)),
  };
}

// ========================================
// Commands carrying an unlock code
// ========================================

/**
 * Build a command whose data is `before | unlock_counter(4) | unlock_code(20) | after`,
 * with unlock_code = HMAC-SHA1(secret, CLA INS P1 P2 Lc | before | counter).
 */
export function encodeUnlockedCommand(
  ins: number,
  p1: number,
  p2: number,
  counter: Buffer,
  secret: Buffer,
  before: Buffer = Buffer.alloc(0),
  after: Buffer = Buffer.alloc(0),
): APDUCommand {
  checkCounter(counter);
  const lc = before.length + SIZE_UNLOCK_COUNTER + 20 + after.length;
  if (lc > 255) {
    throw new Error('Command data too long');
  }
  const prefix = Buffer.concat([Buffer.from([SATODIME_CLA, ins, p1, p2, lc]), before, counter]);
  const code = computeUnlockCode(secret, prefix);
  return {
    cla: SATODIME_CLA,
    ins,
    p1,
    p2,
    data: Buffer.concat([before, counter, code, after]),
  };
}

/** SIGN_SATODIME_TRANSACTION_HASH (0x5B): data [hash(32) | counter(4) | code(20)], returns DER signature. */
export function encodeSignTransactionHash(slot: number, hash: Buffer, counter: Buffer, secret: Buffer): APDUCommand {
  checkSlot(slot);
  if (hash.length !== 32) {
    throw new Error('Hash must be 32 bytes');
  }
  return encodeUnlockedCommand(INS_SIGN_SATODIME_TRANSACTION_HASH, slot, 0x00, counter, secret, hash);
}

/** CHECK_SATODIME_UNLOCK_CODE (0x54): data [counter(4) | code(20)]. */
export function encodeCheckUnlockCode(counter: Buffer, secret: Buffer): APDUCommand {
  return encodeUnlockedCommand(INS_CHECK_SATODIME_UNLOCK_CODE, 0x00, 0x00, counter, secret);
}

/** GET_SATODIME_PRIVKEY (0x56), unsealed vaults only. */
export function encodeGetPrivkey(slot: number, counter: Buffer, secret: Buffer): APDUCommand {
  checkSlot(slot);
  return encodeUnlockedCommand(INS_GET_SATODIME_PRIVKEY, slot, 0x00, counter, secret);
}

/** SEAL_SATODIME_KEY (0x57): uninitialized -> sealed; data [counter | code | user_entropy(32)]. */
export function encodeSeal(slot: number, counter: Buffer, secret: Buffer, entropy: Buffer): APDUCommand {
  checkSlot(slot);
  if (entropy.length !== SIZE_ENTROPY) {
    throw new Error('Entropy must be 32 bytes');
  }
  return encodeUnlockedCommand(INS_SEAL_SATODIME_KEY, slot, 0x00, counter, secret, Buffer.alloc(0), entropy);
}

/** UNSEAL_SATODIME_KEY (0x58): sealed -> unsealed. */
export function encodeUnseal(slot: number, counter: Buffer, secret: Buffer): APDUCommand {
  checkSlot(slot);
  return encodeUnlockedCommand(INS_UNSEAL_SATODIME_KEY, slot, 0x00, counter, secret);
}

/** RESET_SATODIME_KEY (0x59): unsealed -> uninitialized. */
export function encodeReset(slot: number, counter: Buffer, secret: Buffer): APDUCommand {
  checkSlot(slot);
  return encodeUnlockedCommand(INS_RESET_SATODIME_KEY, slot, 0x00, counter, secret);
}

/** INITIATE_SATODIME_TRANSFER (0x5A): releases ownership (setupDone = false). */
export function encodeTransfer(counter: Buffer, secret: Buffer): APDUCommand {
  return encodeUnlockedCommand(INS_INITIATE_SATODIME_TRANSFER, 0x00, 0x00, counter, secret);
}

/**
 * SET_SATODIME_KEYSLOT_STATUS (0x52) P2=0x00:
 * [counter | code | RFU(1) | RFU(1) | asset(1) | slip44(4) | contract(34) | tokenid(34)]
 */
export function encodeSetKeyslotMetadata(
  slot: number,
  counter: Buffer,
  secret: Buffer,
  meta: KeyslotMetadata,
): APDUCommand {
  checkSlot(slot);
  const contract = meta.contract ?? emptyTlv32();
  const tokenId = meta.tokenId ?? emptyTlv32();
  if (contract.length !== SIZE_CONTRACT || tokenId.length !== SIZE_TOKENID) {
    throw new Error('contract and tokenId must be 34 bytes');
  }
  const slip44 = Buffer.alloc(SIZE_SLIP44);
  slip44.writeUInt32BE(meta.slip44 >>> 0, 0);
  const after = Buffer.concat([Buffer.from([0x00, 0x00, meta.asset & 0xff]), slip44, contract, tokenId]);
  return encodeUnlockedCommand(INS_SET_SATODIME_KEYSLOT_STATUS, slot, 0x00, counter, secret, Buffer.alloc(0), after);
}

/** SET_SATODIME_KEYSLOT_STATUS (0x52) P2=0x01: [counter | code | data(66)] */
export function encodeSetKeyslotData(slot: number, counter: Buffer, secret: Buffer, data: Buffer): APDUCommand {
  checkSlot(slot);
  if (data.length !== SIZE_DATA) {
    throw new Error('Keyslot data must be 66 bytes');
  }
  return encodeUnlockedCommand(INS_SET_SATODIME_KEYSLOT_STATUS, slot, 0x01, counter, secret, Buffer.alloc(0), data);
}
