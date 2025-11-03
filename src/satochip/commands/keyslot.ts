import { sendSecureAPDU } from '../apduSecure';
import { SATOCHIP_CLA } from '../constants';
import { APDUCommand, APDUResponse } from '../types';
import { SecureChannel } from '../SecureChannel';
import { INS_GET_PUBLIC_FROM_PRIVATE } from '../constants';
import { checkResponseApdu, SatochipCardError } from '../errors';
import { CardDataParser } from '../parser';
import { ECPubkey } from '../utils/ECKey';
import { console_log } from '../utils/logging';

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
export async function getPubkeyFromKeyslot(
  secureChannel: SecureChannel,
  keyNumber: number,
): Promise<ECPubkey> {
  console_log('In getPubkeyFromKeyslot');

  if (!secureChannel?.isEstablished()) {
    throw new Error('Secure channel required for keyslot operations');
  }

  const command: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_GET_PUBLIC_FROM_PRIVATE,
    p1: keyNumber,
    p2: 0x00,
  };

  // Send APDU (contains sensitive data!)
  const rapdu = await sendSecureAPDU(command, secureChannel);
  checkResponseApdu(rapdu);

  // Response format: [coordx_size(2b) | pubkey_coordx | sig_size(2b) | sig]
  const pubkey = CardDataParser.parseGetPubkeyFromKeyslot(rapdu.data);

  return pubkey;
}