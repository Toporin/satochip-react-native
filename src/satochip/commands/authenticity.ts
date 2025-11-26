import { sendSecureAPDU } from '../apduSecure';
import {
  INS_CHALLENGE_RESPONSE_PKI,
  INS_EXPORT_PKI_CERTIFICATE, INS_EXPORT_PKI_PUBKEY,
  OP_INIT,
  OP_PROCESS,
  SATOCHIP_CLA
} from '../constants';
import { APDUCommand } from '../types';
import { SecureChannel } from '../SecureChannel';
import { checkResponseApdu, SatochipError } from '../errors';
import { CardDataParser } from '../parser';
import * as crypto from 'crypto';
import {console_log} from '../utils/logging';

/**
 * Result of challenge-response verification
 */
export interface ChallengeResponseResult {
  success: boolean;
  error: string;
}

/**
 * Export the personalization certificate from the device
 *
 * The certificate is retrieved in chunks and converted to PEM format.
 * This certificate is used for device authenticity verification.
 *
 * @param secureChannel - The secure channel for communication
 * @returns Certificate in PEM format and raw bytes
 * @throws Error if card doesn't support PKI or other errors
 */
export async function exportPersoCertificate(
  secureChannel: SecureChannel
): Promise<string> {
  console_log('In cardExportPersoCertificate');

  if (!secureChannel) {
    throw new SatochipError('Secure channel required for PKI operations');
  }

  // ========================================
  // INIT - Get certificate size
  // ========================================

  const initCommand: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_EXPORT_PKI_CERTIFICATE,
    p1: 0x00,
    p2: OP_INIT,
  };

  let rapdu = await sendSecureAPDU(initCommand, secureChannel);
  checkResponseApdu(rapdu);

  // Parse certificate size from response
  const certificateSize = (rapdu.data[0] << 8) + rapdu.data[1];
  console_log(`cardExportPersoCertificate certificateSize: ${certificateSize} bytes`);

  if (certificateSize === 0) {
    return '';
  }

  // ========================================
  // UPDATE - Retrieve certificate data in chunks
  // ========================================

  const certificate = Buffer.alloc(certificateSize);
  const CHUNK_SIZE = 128;
  let remainingSize = certificateSize;
  let certOffset = 0;

  // Retrieve chunks while remaining size > 128
  while (remainingSize > CHUNK_SIZE) {
    // Build data: chunk_offset(2b) | chunk_size(2b)
    const data = Buffer.alloc(4);
    data.writeUInt16BE(certOffset, 0);
    data.writeUInt16BE(CHUNK_SIZE, 2);

    const updateCommand: APDUCommand = {
      cla: SATOCHIP_CLA,
      ins: INS_EXPORT_PKI_CERTIFICATE,
      p1: 0x00,
      p2: OP_PROCESS,
      data,
    };

    rapdu = await sendSecureAPDU(updateCommand, secureChannel);

    // Copy chunk to certificate buffer
    rapdu.data.copy(certificate, certOffset, 0, CHUNK_SIZE);
    remainingSize -= CHUNK_SIZE;
    certOffset += CHUNK_SIZE;
  }

  // ========================================
  // Last chunk
  // ========================================
  const data = Buffer.alloc(4);
  data.writeUInt16BE(certOffset, 0);
  data.writeUInt16BE(remainingSize, 2);

  const lastCommand: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_EXPORT_PKI_CERTIFICATE,
    p1: 0x00,
    p2: OP_PROCESS,
    data,
  };

  rapdu = await sendSecureAPDU(lastCommand, secureChannel);

  // Copy last chunk
  rapdu.data.copy(certificate, certOffset, 0, remainingSize);

  // ========================================
  // Convert to PEM format
  // ========================================
  const certificatePem = CardDataParser.convertBytesToStringPem(certificate);
  console_log(`cardExportPersoCertificate certificatePem: ${certificatePem}`);

  return certificatePem;
}

/**
 * Perform challenge-response authentication with the device
 *
 * This verifies that the device possesses the private key corresponding
 * to the public key in the certificate.
 *
 * @param secureChannel - The secure channel for communication
 * @param authentikeyBytes
 * @returns Verification result with success flag and error message
 */
export async function cardChallengeResponsePki(
  secureChannel: SecureChannel,
  authentikeyBytes: Buffer,
): Promise<ChallengeResponseResult> {
  console_log('In cardChallengeResponsePki');

  if (!secureChannel) {
    throw new SatochipError('Secure channel required for PKI operations');
  }

  // Generate 32-byte random challenge from host
  const challengeFromHost = crypto.randomBytes(32);
  console_log(`cardChallengeResponsePki challengeFromHost: ${challengeFromHost.toString('hex')}`);

  const command: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_CHALLENGE_RESPONSE_PKI,
    p1: 0x00,
    p2: 0x00,
    data: challengeFromHost,
  };

  const rapdu = await sendSecureAPDU(command, secureChannel);

  // Verify challenge-response
  const verif = CardDataParser.verifyChallengeResponsePki(
    rapdu.data,
    challengeFromHost,
    authentikeyBytes
  );

  return verif;
}

/**
 * Export the personalization public key from the device
 *
 * @param secureChannel - The secure channel for communication
 * @returns The public key bytes
 */
export async function cardExportPersoPubkey(
  secureChannel: SecureChannel
): Promise<Buffer> {
  console_log('In cardExportPersoPubkey');

  if (!secureChannel) {
    throw new SatochipError('Secure channel required for PKI operations');
  }

  const cla = SATOCHIP_CLA;
  const ins = INS_EXPORT_PKI_PUBKEY;
  const p1 = 0x00;
  const p2 = 0x00;

  const command: APDUCommand = {
    cla,
    ins,
    p1,
    p2,
  };

  const rapdu = await sendSecureAPDU(command, secureChannel);
  checkResponseApdu(rapdu);

  // authentikey as 65-byte uncompressed pubkey
  return rapdu.data
}