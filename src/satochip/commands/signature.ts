import { sendSecureAPDU } from '../apduSecure';
import {
  INS_SIGN_SCHNORR_HASH,
  INS_SIGN_TRANSACTION_HASH,
  INS_TAPROOT_TWEAK_PRIVKEY,
  SATOCHIP_CLA,
} from '../constants';
import { APDUCommand } from '../types';
import { SecureChannel } from '../SecureChannel';
import { checkResponseApdu, SatochipError } from '../errors';

/**
 * Build the data field of a hash-signing command: the 32-byte hash, followed
 * by 0x8000 and the 20-byte 2FA hmac when one is provided.
 */
function buildHashSignData(hash: Buffer, hmac: Buffer): Buffer {
  if (hash.length !== 32) {
    throw new SatochipError('Hash to sign must be exactly 32 bytes');
  }
  if (hmac.length !== 0 && hmac.length !== 20) {
    throw new SatochipError('Hmac challenge response must be 0 or 20 bytes');
  }
  return hmac.length === 20
    ? Buffer.concat([hash, Buffer.from('8000', 'hex'), hmac])
    : hash;
}

/**
 * Sign a transaction hash (simpler version for pre-computed hash).
 *
 * @param keynbr - The key to use (0xFF for BIP32 key)
 * @param secureChannel - The secure channel for communication
 * @param hmac - The 20-byte hmac code required if 2FA is enabled (optional)
 * @returns Buffer containing the DER signature
 */
export async function signTransactionHash(
  secureChannel: SecureChannel,
  keynbr: number,
  txHash: Buffer,
  hmac: Buffer = Buffer.alloc(0),
): Promise<Buffer> {
  const command: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_SIGN_TRANSACTION_HASH,
    p1: keynbr,
    p2: 0x00,
    data: buildHashSignData(txHash, hmac),
    le: 0x00,
  };

  const rapdu = await sendSecureAPDU(command, secureChannel);
  checkResponseApdu(rapdu);

  // signature in DER format (70-72 bytes)
  return rapdu.data;
}

/**
 * Apply the BIP341 Taproot tweak to a private key before Schnorr signing.
 *
 * @param keynbr - The key to use (0xFF for BIP32 key)
 * @param tweak - optional 32-byte tweak (BIP341 script tree hash); zero by default
 * @param bypass - if true, the key is left untweaked (e.g. for Nostr signatures)
 * @returns the card response (tweaked public key)
 */
export async function taprootTweakPrivkey(
  secureChannel: SecureChannel,
  keynbr: number,
  tweak: Buffer | null = null,
  bypass = false,
): Promise<Buffer> {
  const tweakBytes = tweak ?? Buffer.alloc(32);
  if (tweakBytes.length !== 32) {
    throw new SatochipError('Taproot tweak must be exactly 32 bytes');
  }

  const command: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_TAPROOT_TWEAK_PRIVKEY,
    p1: keynbr,
    p2: bypass ? 0x01 : 0x00,
    data: Buffer.concat([Buffer.from([tweakBytes.length]), tweakBytes]),
  };

  const rapdu = await sendSecureAPDU(command, secureChannel);
  checkResponseApdu(rapdu);
  return rapdu.data;
}

/**
 * Sign a 32-byte hash with BIP340 Schnorr. The key must first be prepared
 * with taprootTweakPrivkey().
 *
 * @param keynbr - The key to use (0xFF for BIP32 key)
 * @param hmac - The 20-byte hmac code required if 2FA is enabled (optional)
 * @returns 64-byte Schnorr signature
 */
export async function signSchnorrHash(
  secureChannel: SecureChannel,
  keynbr: number,
  hash: Buffer,
  hmac: Buffer = Buffer.alloc(0),
): Promise<Buffer> {
  const command: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_SIGN_SCHNORR_HASH,
    p1: keynbr,
    p2: 0x00,
    data: buildHashSignData(hash, hmac),
  };

  const rapdu = await sendSecureAPDU(command, secureChannel);
  checkResponseApdu(rapdu);
  if (rapdu.data.length !== 64) {
    throw new SatochipError(`Invalid Schnorr signature length: ${rapdu.data.length}`);
  }
  return rapdu.data;
}
