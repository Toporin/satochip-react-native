/**
 * Satodime unlock code.
 *
 * Commands that change the card state (and, from protocol 0.2, hash signing)
 * carry `unlock_counter(4) | unlock_code(20)`. Over NFC, the applet checks
 *
 *   unlock_code = HMAC-SHA1(unlock_secret, inner_apdu[0 .. end of counter])
 *
 * i.e. the (decrypted) APDU header `CLA INS P1 P2 Lc`, the data preceding the
 * counter (the hash for 0x5B, nothing for the other commands) and the counter.
 * This matches pysatochip (hmac.new(secret, apduheader + counter, sha1)).
 * On success the card increments its counter.
 */
import * as crypto from 'crypto';
import { SIZE_UNLOCK_COUNTER, SIZE_UNLOCK_SECRET } from './constants';

/** Normalize an unlock secret to 20 bytes (zero-padded, as the applet stores CVCs). */
export function normalizeUnlockSecret(secret: Buffer): Buffer {
  if (secret.length === 0 || secret.length > SIZE_UNLOCK_SECRET) {
    throw new Error(`Invalid unlock secret length: ${secret.length}`);
  }
  const out = Buffer.alloc(SIZE_UNLOCK_SECRET, 0);
  secret.copy(out, 0);
  return out;
}

/**
 * Unlock secret of a card with a fixed CVC (protocol >= 0.2, fixedUnlockSecret):
 * the engraved code's bytes, zero-padded to 20 bytes (as Satodime-Android does).
 */
export function cvcToUnlockSecret(cvc: string): Buffer {
  const bytes = Buffer.from(cvc.trim(), 'utf8');
  if (bytes.length === 0 || bytes.length > SIZE_UNLOCK_SECRET) {
    throw new Error('Invalid CVC length');
  }
  return normalizeUnlockSecret(bytes);
}

/**
 * Compute the unlock code.
 * @param secret - unlock secret (<= 20 bytes, zero-padded)
 * @param apduPrefix - inner APDU bytes from CLA up to and including the counter
 */
export function computeUnlockCode(secret: Buffer, apduPrefix: Buffer): Buffer {
  return crypto.createHmac('sha1', normalizeUnlockSecret(secret)).update(apduPrefix).digest();
}

/** Increment a 4-byte big-endian counter (with wrap-around), as the card does. */
export function incrementUnlockCounter(counter: Buffer): Buffer {
  if (counter.length !== SIZE_UNLOCK_COUNTER) {
    throw new Error('Invalid unlock counter length');
  }
  const value = (counter.readUInt32BE(0) + 1) >>> 0;
  const out = Buffer.alloc(SIZE_UNLOCK_COUNTER);
  out.writeUInt32BE(value, 0);
  return out;
}
