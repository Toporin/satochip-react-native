/**
 * Commands shared by every applet of the Satochip family.
 * Encrypted commands are sent through `send`, which wraps the command in the
 * card's secure channel and maps status words with the card's error table.
 */
import * as crypto from 'crypto';
import { transmitAPDU } from '../apdu';
import { CardError } from '../errors';
import { CARD_CLA } from './secureChannel';
import { APDUCommand, APDUResponse } from '../../satochip/types';
import { CardDataParser } from '../../satochip/parser';
import { ECPubkey } from '../../satochip/utils/ECKey';
import type { SecureChannel } from '../SecureChannel';

export type SecureSender = (command: APDUCommand) => Promise<APDUResponse>;

export const INS_SELECT = 0xA4;
export const INS_GET_STATUS = 0x3C;
export const INS_SETUP = 0x2A;
export const INS_CARD_LABEL = 0x3D;
export const INS_EXPORT_AUTHENTIKEY = 0xAD;
export const INS_EXPORT_PKI_CERTIFICATE = 0x93;
export const INS_EXPORT_PKI_PUBKEY = 0x98;
export const INS_CHALLENGE_RESPONSE_PKI = 0x9A;
export const OP_INIT = 0x01;
export const OP_PROCESS = 0x02;

export interface ChallengeResponseResult {
  success: boolean;
  error: string;
}

/** ISO SELECT by AID (sent in plain, status word not checked). */
export async function selectAid(aid: Buffer): Promise<APDUResponse> {
  return transmitAPDU({ cla: 0x00, ins: INS_SELECT, p1: 0x04, p2: 0x00, data: aid });
}

/** GET_STATUS (INS 0x3C, sent in plain, status word not checked). */
export async function getRawStatus(): Promise<APDUResponse> {
  return transmitAPDU({ cla: CARD_CLA, ins: INS_GET_STATUS, p1: 0x00, p2: 0x00 });
}

/** Export the card authentikey and check it against the secure-channel candidates. */
export async function getAuthentikey(send: SecureSender, secureChannel: SecureChannel): Promise<ECPubkey> {
  const response = await send({ cla: CARD_CLA, ins: INS_EXPORT_AUTHENTIKEY, p1: 0x00, p2: 0x00, le: 0x00 });
  const authentikey = CardDataParser.parseGetAuthentikey(response.data);
  secureChannel.checkAuthentikeyCandidates([authentikey]);
  return authentikey;
}

/** Get the card label ('(none)' if the applet does not support labels). */
export async function getLabel(send: SecureSender): Promise<string> {
  try {
    const response = await send({ cla: CARD_CLA, ins: INS_CARD_LABEL, p1: 0x00, p2: 0x01 });
    const labelSize = response.data.readUInt8(0);
    try {
      return response.data.slice(1, 1 + labelSize).toString('utf8');
    } catch (error) {
      console.warn('Error decoding card label:', error);
      return response.data.slice(1).toString('hex');
    }
  } catch (error) {
    if (error instanceof CardError && error.statusWord == 0x6D00) {
      return '(none)'; // INS_NOT_SUPPORTED
    }
    throw error;
  }
}

/** Set the card label (UTF-8). */
export async function setLabel(send: SecureSender, label: string): Promise<void> {
  const labelBytes = Buffer.from(label, 'utf8');
  const data = Buffer.concat([Buffer.from([labelBytes.length]), labelBytes]);
  await send({ cla: CARD_CLA, ins: INS_CARD_LABEL, p1: 0x00, p2: 0x00, data });
}

/** Export the personalization certificate (PEM) used for authenticity checks. */
export async function exportPersoCertificate(send: SecureSender): Promise<string> {
  let rapdu = await send({ cla: CARD_CLA, ins: INS_EXPORT_PKI_CERTIFICATE, p1: 0x00, p2: OP_INIT });
  const certificateSize = (rapdu.data[0] << 8) + rapdu.data[1];
  if (certificateSize === 0) {
    return '';
  }

  const certificate = Buffer.alloc(certificateSize);
  const CHUNK_SIZE = 128;
  let remainingSize = certificateSize;
  let certOffset = 0;
  while (remainingSize > 0) {
    const chunkSize = Math.min(CHUNK_SIZE, remainingSize);
    const data = Buffer.alloc(4);
    data.writeUInt16BE(certOffset, 0);
    data.writeUInt16BE(chunkSize, 2);
    rapdu = await send({ cla: CARD_CLA, ins: INS_EXPORT_PKI_CERTIFICATE, p1: 0x00, p2: OP_PROCESS, data });
    rapdu.data.copy(certificate, certOffset, 0, chunkSize);
    remainingSize -= chunkSize;
    certOffset += chunkSize;
  }
  return CardDataParser.convertBytesToStringPem(certificate);
}

/** Challenge-response proving the card holds the authentikey private key. */
export async function cardChallengeResponsePki(
  send: SecureSender,
  authentikeyBytes: Buffer,
): Promise<ChallengeResponseResult> {
  const challengeFromHost = crypto.randomBytes(32);
  const rapdu = await send({ cla: CARD_CLA, ins: INS_CHALLENGE_RESPONSE_PKI, p1: 0x00, p2: 0x00, data: challengeFromHost });
  return CardDataParser.verifyChallengeResponsePki(rapdu.data, challengeFromHost, authentikeyBytes);
}

/** Export the personalization public key (65-byte uncompressed). */
export async function exportPersoPubkey(send: SecureSender): Promise<Buffer> {
  const rapdu = await send({ cla: CARD_CLA, ins: INS_EXPORT_PKI_PUBKEY, p1: 0x00, p2: 0x00 });
  return rapdu.data;
}
