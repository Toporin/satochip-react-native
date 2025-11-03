import { sendSecureAPDU } from '../apduSecure';
import { INS_SIGN_TRANSACTION_HASH, SATOCHIP_CLA } from '../constants';
import { APDUCommand } from '../types';
import { SecureChannel } from '../SecureChannel';
import { checkResponseApdu, SatochipError } from '../errors';


/**
 * Sign a transaction hash (simpler version for pre-computed hash).
 *
 * @param keynbr - The key to use (0xFF for BIP32 key)
 * @param secureChannel - The secure channel for communication
 * @param hmac - The 20-byte hmac code required if 2FA is enabled (optional)
 * @returns Buffer containing the response and compact signature (65-byte format)
 */
export async function signTransactionHash(
  secureChannel: SecureChannel,
  keynbr: number,
  txHash: Buffer,
  hmac: Buffer = Buffer.alloc(0),
): Promise<Buffer> {

  if (!secureChannel?.isEstablished()) {
    throw new SatochipError('Secure channel required for transaction signing');
  }

  if (txHash.length !== 32) {
    throw new SatochipError('Transaction hash must be exactly 32 bytes');
  }

  if (hmac.length != 0 && hmac.length != 20) {
    throw new SatochipError('Hmac challenge response must be 0 or 20 bytes');
  }

  let data: Buffer;
  if (hmac.length == 20){
    data = Buffer.concat([txHash, Buffer.from('8000', 'hex') , hmac]);
  } else {
    data = txHash;
  }

  const command: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_SIGN_TRANSACTION_HASH,
    p1: keynbr,
    p2: 0x00,
    data: data,
    le: 0x00,
  };

  const rapdu = await sendSecureAPDU(command, secureChannel);
  checkResponseApdu(rapdu);

  // signature in DER format (70-72 bytes)
  return rapdu.data;
}

