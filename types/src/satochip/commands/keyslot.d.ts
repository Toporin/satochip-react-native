import { SecureChannel } from '../SecureChannel';
import { ECPubkey } from '../utils/ECKey';
/**
 * Get the public key associated with a particular private key stored
 * at a given keyslot in the applet.
 *
 * The exact key blob contents depend on the key algorithm and type.
 * For SECP256K1, returns the public key object for the given slot.
 * Raises an error if the slot is not initialized.
 *
 * @param secureChannel - The secure channel for communication
 * @param keyNumber - The keyslot number to query
 * @returns The public key (ECPubkey) for the given keyslot
 * @throws Error if keyslot is not initialized or other card errors
 */
export declare function getPubkeyFromKeyslot(secureChannel: SecureChannel, keyNumber: number): Promise<ECPubkey>;
