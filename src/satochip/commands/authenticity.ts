/**
 * PKI / authenticity commands. The implementation is shared by every applet
 * (src/core/commands/common.ts); these wrappers keep the historical Satochip
 * signatures, taking a SecureChannel.
 */
import { sendSecureAPDU } from '../apduSecure';
import { SecureChannel } from '../SecureChannel';
import { SatochipError } from '../errors';
import { APDUCommand } from '../types';
import {
  ChallengeResponseResult,
  SecureSender,
  cardChallengeResponsePki as coreChallengeResponsePki,
  exportPersoCertificate as coreExportPersoCertificate,
  exportPersoPubkey as coreExportPersoPubkey,
} from '../../core/commands/common';

export type { ChallengeResponseResult };

function senderFor(secureChannel: SecureChannel): SecureSender {
  if (!secureChannel) {
    throw new SatochipError('Secure channel required for PKI operations');
  }
  return (command: APDUCommand) => sendSecureAPDU(command, secureChannel);
}

export async function exportPersoCertificate(secureChannel: SecureChannel): Promise<string> {
  return coreExportPersoCertificate(senderFor(secureChannel));
}

export async function cardChallengeResponsePki(
  secureChannel: SecureChannel,
  authentikeyBytes: Buffer,
): Promise<ChallengeResponseResult> {
  return coreChallengeResponsePki(senderFor(secureChannel), authentikeyBytes);
}

export async function cardExportPersoPubkey(secureChannel: SecureChannel): Promise<Buffer> {
  return coreExportPersoPubkey(senderFor(secureChannel));
}
