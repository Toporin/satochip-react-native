import * as bs58 from 'bs58';

import { sendSecureAPDU } from '../apduSecure';
import {
  INS_BIP32_GET_EXTENDED_KEY,
  INS_BIP32_IMPORT_SEED,
  INS_BIP32_RESET_SEED,
  SATOCHIP_CLA,
  SUPPORTED_XTYPES,
  SW_NO_MEMORY_LEFT,
  XPUB_HEADERS_MAINNET,
  XPUB_HEADERS_TESTNET,
  XType
} from '../constants';
import { APDUCommand, APDUResponse, ExtendedKey } from '../types';
import { SecureChannel } from '../SecureChannel';
import { SatochipCardError } from '../errors';
import { CardDataParser } from '../parser';
import { hash160, sha256s } from '../utils/crypto';
import { ECPubkey } from '../utils/ECKey';
import { console_log } from '../utils/logging';

/**
 * Import BIP32 seed into the card (requires secure channel)
 * This is a one-time operation to initialize the card with entropy
 */
export async function importSeed(
  secureChannel: SecureChannel,
  seed: Buffer,
  options = 0x00
): Promise<void> {
  if (!secureChannel) {
    throw new Error('Secure channel required for seed import');
  }

  if (seed.length < 16 || seed.length > 64) {
    throw new Error('Seed must be between 16 and 64 bytes');
  }

  const command: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_BIP32_IMPORT_SEED,
    p1: seed.length,
    p2: options,
    data: seed,
  };
  
  const rapdu =  await sendSecureAPDU(command, secureChannel);

  // todo recover authentikey
  // response: [coordx_size(2b) | coordx | sig_size(2b) | sig]
}

/**
 * Reset BIP32 seed (factory reset - requires secure channel)
 * WARNING: This will permanently delete all keys!
 */
export async function resetSeed(secureChannel: SecureChannel, pinBytes: Buffer, hmacBytes: Buffer | null): Promise<void> {
  if (!secureChannel) {
    throw new Error('Secure channel required for seed reset');
  }

  // Build data
  let data = pinBytes;
  if (hmacBytes != null){
    data = Buffer.concat([pinBytes, hmacBytes]);
  }

  const command: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_BIP32_RESET_SEED,
    p1: pinBytes.length,
    p2: 0x00,
    data: data,
  };
  
  const radpu = await sendSecureAPDU(command, secureChannel);
}

/**
 * Get extended public key for a specific BIP32 path
 */
export async function getExtendedKey(
  secureChannel: SecureChannel,
  pathString: string
): Promise<ExtendedKey> {
  console_log(`In bip32 getExtendedKey`);
  if (!secureChannel) {
    throw new Error('Secure channel required for extended key operations');
  }

  const {depth, bytePath} = CardDataParser.bip32path2bytes(pathString);
  console_log(`In bip32 getExtendedKey depth: ${depth}, bytePath: ${bytePath.toString('hex')}`);

  const command: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_BIP32_GET_EXTENDED_KEY,
    p1: depth,
    p2: 0x00,
    data: bytePath,
    le: 0x00,
  };

  let rapdu: APDUResponse;
  try {
    rapdu = await sendSecureAPDU(command, secureChannel);
  } catch (error){
    if (error instanceof SatochipCardError) {
      if (error.statusWord == SW_NO_MEMORY_LEFT){
        // legacy card: reset memory
        console_log(`In bip32 getExtendedKey: reset bip32 cache`);
        command.p2 = command.p2 ^ 0x80;
        rapdu = await sendSecureAPDU(command, secureChannel);
      } else {
        throw error;
      }
    } else {
      throw error;
    }
  }

  // parse response
  const {pubkey,  chaincode, authentikeyCandidates} = CardDataParser.parseBip32GetExtendedkey(rapdu.data);
  console_log(`In bip32 getExtendedKey pubkey: ${pubkey.getPublicKeyBytes(true).toString('hex')}`);
  console_log(`In bip32 getExtendedKey chaincode: ${chaincode.toString('hex')}`);

  // check that one authentikey candidate match cached value
  secureChannel.checkAuthentikeyCandidates(authentikeyCandidates);

  return {
    pubkey: pubkey.getPublicKeyBytes(),
    chaincode,
  };
}

/**
 * Get the BIP32 extended public key (xpub) for a given derivation path
 *
 * @param secureChannel - The secure channel instance for communication
 * @param path - The BIP32 derivation path (e.g., "m/44'/0'/0'" or as Buffer of 4-byte indices)
 * @param xtype - The type of address format ('standard', 'p2wpkh-p2sh', 'p2wpkh', 'p2wsh-p2sh', 'p2wsh')
 * @param isMainnet - Whether to use mainnet or testnet header bytes
 * @param sid - (Optional) For SeedKeeper, the secret_id of the master seed to use for derivation
 * @returns The xpub string in Base58Check format
 */
export async function cardBip32GetXpub(
  secureChannel: SecureChannel,
  path: string,
  xtype: XType,
  isMainnet: boolean,
): Promise<string> {

  console_log(`cardBip32GetXpub(): path=${path.toString()}`);

  // Validate xtype
  if (!SUPPORTED_XTYPES.includes(xtype)) {
    throw new Error(`Unsupported xtype: ${xtype}. Must be one of: ${SUPPORTED_XTYPES.join(', ')}`);
  }

  // Convert path string to bytes
  const {depth, bytePath} = CardDataParser.bip32path2bytes(path);

  // get the extended key for the parent path
  let fingerprint: Buffer;
  let childNumber: Buffer;
  if (depth === 0) {
    // Master key - use zero bytes
    fingerprint = Buffer.from([0, 0, 0, 0]);
    childNumber = Buffer.from([0, 0, 0, 0]);
  } else {
    // Get parent key info
    const parentBytePath = bytePath.slice(0, -4);
    const parentPathString = CardDataParser.bytes2Bip32path(parentBytePath);
    const parentExtendedKey = await getExtendedKey(secureChannel, parentPathString);

    // Create ECPubkey from parent pubkey
    const parentKey = new ECPubkey(parentExtendedKey.pubkey);

    // Calculate fingerprint: first 4 bytes of hash160 of compressed parent pubkey
    const parentPubkeyCompressed = parentKey.getPublicKeyBytes(true);
    fingerprint = hash160(parentPubkeyCompressed).slice(0, 4);

    // Child number is the last 4 bytes of the path
    childNumber = bytePath.slice(-4);
  }

  // Get the extended key for the child path
  const childExtendedKey = await getExtendedKey(secureChannel, path);
  // Create ECPubkey from the pubkey buffer
  const childKey = new ECPubkey(childExtendedKey.pubkey);
  const childChaincode = childExtendedKey.chaincode;

  // Select appropriate xpub header
  const xpubHeader = isMainnet
    ? XPUB_HEADERS_MAINNET[xtype]
    : XPUB_HEADERS_TESTNET[xtype];

  // Build xpub: header(4) + depth(1) + fingerprint(4) + child_number(4) + chaincode(32) + pubkey(33)
  const xpubBytes = Buffer.concat([
    Buffer.from(xpubHeader, 'hex'),  // 4 bytes
    Buffer.from([depth]),             // 1 byte
    fingerprint,                      // 4 bytes
    childNumber,                      // 4 bytes
    childChaincode,                   // 32 bytes
    childKey.getPublicKeyBytes(true), // 33 bytes (compressed)
  ]);
  console_log(`cardBip32GetXpub(): xpubHeader= ${xpubHeader}`);
  console_log(`cardBip32GetXpub(): depth= ${depth}`);
  console_log(`cardBip32GetXpub(): fingerprint= ${fingerprint.toString('hex')}`);
  console_log(`cardBip32GetXpub(): childNumber= ${childNumber.toString('hex')}`);
  console_log(`cardBip32GetXpub(): childChaincode= ${childChaincode.toString('hex')}`);
  console_log(`cardBip32GetXpub(): childKey.getPublicKeyBytes(true)= ${childKey.getPublicKeyBytes(true).toString('hex')}`);
  console_log(`cardBip32GetXpub(): xpubBytes= ${xpubBytes.toString('hex')}`);
  console_log(`cardBip32GetXpub(): xpubBytes.length= ${xpubBytes.length}`);

  // Verify total length is 78 bytes
  if (xpubBytes.length !== 78) {
    throw new Error(`Invalid xpub length: ${xpubBytes.length}, expected 78`);
  }

  // Encode with Base58Check
  const xpub = encodeBase58Check(xpubBytes);
  console_log(`cardBip32GetXpub(): xpub=${xpub}`);

  return xpub;
}


/**
 * Get the master fingerprint (first 4 bytes of hash160 of master public key)
 *
 * The fingerprint of a public key is defined in BIP 32 as the first 4 bytes
 * of the RIPEMD160 hash of the SHA256 hash of the public key.
 *
 * @param secureChannel - The secure channel instance for communication
 * @returns string containing the 4-byte master fingerprint encode as hex
 */
export async function cardBip32GetMasterXFP(
  secureChannel: SecureChannel,
): Promise<string> {
  console_log('In cardBip32GetMasterXFP()');

  // Get the master extended key (path "m")
  const masterPath = 'm';
  const masterExtendedKey = await getExtendedKey(secureChannel, masterPath);

  // Create ECPubkey from the master pubkey buffer
  const masterKey = new ECPubkey(masterExtendedKey.pubkey);

  // Get compressed public key (33 bytes)
  const masterPubkeyCompressed = masterKey.getPublicKeyBytes(true);
  console_log(`cardBip32GetMasterXFP(): masterPubkeyCompressed= ${masterKey.getPublicKeyBytes(true).toString('hex')}`);

  // Calculate fingerprint: first 4 bytes of hash160 of compressed master pubkey
  const fingerprint = hash160(masterPubkeyCompressed).slice(0, 4);
  console_log(`cardBip32GetMasterXFP(): hash160(masterPubkeyCompressed)= ${hash160(masterPubkeyCompressed).toString('hex')}`);
  console_log(`cardBip32GetMasterXFP(): fingerprint= ${fingerprint.toString('hex')}`);

  return fingerprint.toString('hex');
}

/**
 * Encode data with Base58Check encoding (Base58 with checksum)
 * @param data - Data to encode
 * @returns Base58Check encoded string
 */
function encodeBase58Check(data: Buffer): string {
  // Calculate checksum (first 4 bytes of double SHA256)
  const hash1 = Buffer.from(sha256s(data));
  const hash2 = Buffer.from(sha256s(hash1));
  const checksum = hash2.slice(0, 4);

  // Append checksum and encode
  const dataWithChecksum = Buffer.concat([data, checksum]);
  return bs58.encode(dataWithChecksum);
}
