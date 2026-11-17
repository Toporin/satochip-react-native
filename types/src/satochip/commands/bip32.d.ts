import { XType } from '../constants';
import { ExtendedKey } from '../types';
import { SecureChannel } from '../SecureChannel';
/**
 * Import BIP32 seed into the card (requires secure channel)
 * This is a one-time operation to initialize the card with entropy
 */
export declare function importSeed(secureChannel: SecureChannel, seed: Buffer, options?: number): Promise<void>;
/**
 * Reset BIP32 seed (factory reset - requires secure channel)
 * WARNING: This will permanently delete all keys!
 */
export declare function resetSeed(secureChannel: SecureChannel, pinBytes: Buffer, hmacBytes: Buffer | null): Promise<void>;
/**
 * Get extended public key for a specific BIP32 path
 */
export declare function getExtendedKey(secureChannel: SecureChannel, pathString: string): Promise<ExtendedKey>;
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
export declare function cardBip32GetXpub(secureChannel: SecureChannel, path: string, xtype: XType, isMainnet: boolean): Promise<string>;
/**
 * Get the master fingerprint (first 4 bytes of hash160 of master public key)
 *
 * The fingerprint of a public key is defined in BIP 32 as the first 4 bytes
 * of the RIPEMD160 hash of the SHA256 hash of the public key.
 *
 * @param secureChannel - The secure channel instance for communication
 * @returns string containing the 4-byte master fingerprint encode as hex
 */
export declare function cardBip32GetMasterXFP(secureChannel: SecureChannel): Promise<string>;
