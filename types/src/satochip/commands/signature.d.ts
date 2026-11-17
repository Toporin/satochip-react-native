import { SecureChannel } from '../SecureChannel';
/**
 * Sign a transaction hash (simpler version for pre-computed hash).
 *
 * @param keynbr - The key to use (0xFF for BIP32 key)
 * @param secureChannel - The secure channel for communication
 * @param hmac - The 20-byte hmac code required if 2FA is enabled (optional)
 * @returns Buffer containing the DER signature
 */
export declare function signTransactionHash(secureChannel: SecureChannel, keynbr: number, txHash: Buffer, hmac?: Buffer): Promise<Buffer>;
/**
 * Apply the BIP341 Taproot tweak to a private key before Schnorr signing.
 *
 * @param keynbr - The key to use (0xFF for BIP32 key)
 * @param tweak - optional 32-byte tweak (BIP341 script tree hash); zero by default
 * @param bypass - if true, the key is left untweaked (e.g. for Nostr signatures)
 * @returns the card response (tweaked public key)
 */
export declare function taprootTweakPrivkey(secureChannel: SecureChannel, keynbr: number, tweak?: Buffer | null, bypass?: boolean): Promise<Buffer>;
/**
 * Sign a 32-byte hash with BIP340 Schnorr. The key must first be prepared
 * with taprootTweakPrivkey().
 *
 * @param keynbr - The key to use (0xFF for BIP32 key)
 * @param hmac - The 20-byte hmac code required if 2FA is enabled (optional)
 * @returns 64-byte Schnorr signature
 */
export declare function signSchnorrHash(secureChannel: SecureChannel, keynbr: number, hash: Buffer, hmac?: Buffer): Promise<Buffer>;
