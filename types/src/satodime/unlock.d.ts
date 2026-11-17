/** Normalize an unlock secret to 20 bytes (zero-padded, as the applet stores CVCs). */
export declare function normalizeUnlockSecret(secret: Buffer): Buffer;
/**
 * Unlock secret of a card with a fixed CVC (protocol >= 0.2, fixedUnlockSecret):
 * the engraved code's bytes, zero-padded to 20 bytes (as Satodime-Android does).
 */
export declare function cvcToUnlockSecret(cvc: string): Buffer;
/**
 * Compute the unlock code.
 * @param secret - unlock secret (<= 20 bytes, zero-padded)
 * @param apduPrefix - inner APDU bytes from CLA up to and including the counter
 */
export declare function computeUnlockCode(secret: Buffer, apduPrefix: Buffer): Buffer;
/** Increment a 4-byte big-endian counter (with wrap-around), as the card does. */
export declare function incrementUnlockCounter(counter: Buffer): Buffer;
