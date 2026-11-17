import { ResponseChecker } from '../errors';
import { APDUCommand, APDUResponse } from '../../satochip/types';
import { ECPubkey } from '../../satochip/utils/ECKey';
import type { SecureChannel } from '../SecureChannel';
export type SecureSender = (command: APDUCommand) => Promise<APDUResponse>;
export declare const INS_SELECT = 164;
export declare const INS_GET_STATUS = 60;
export declare const INS_SETUP = 42;
export declare const INS_CARD_LABEL = 61;
export declare const INS_EXPORT_AUTHENTIKEY = 173;
export declare const INS_EXPORT_PKI_CERTIFICATE = 147;
export declare const INS_EXPORT_PKI_PUBKEY = 152;
export declare const INS_CHALLENGE_RESPONSE_PKI = 154;
export declare const INS_RESET_TO_FACTORY = 255;
export declare const OP_INIT = 1;
export declare const OP_PROCESS = 2;
export interface ChallengeResponseResult {
    success: boolean;
    error: string;
}
/** Progress of the multi-presentation factory-reset sequence. */
export interface FactoryResetResult {
    /** True once the card has been reset to factory state. */
    complete: boolean;
    /** Number of card presentations still required (0 when complete). */
    remaining: number;
}
/** ISO SELECT by AID (sent in plain, status word not checked). */
export declare function selectAid(aid: Buffer): Promise<APDUResponse>;
/** GET_STATUS (INS 0x3C, sent in plain, status word not checked). */
export declare function getRawStatus(): Promise<APDUResponse>;
/**
 * Advance the factory-reset sequence by one card presentation (INS 0xFF).
 *
 * The command is sent in plain: the applet requires several separate card
 * presentations with no other command (except SELECT) in between, so no
 * secure channel can be established. The card answers 0xFF00 when the reset
 * is complete, 0xFF01..0xFF0F with the number of presentations remaining, and
 * 0xFFFF if the sequence was interrupted.
 */
export declare function resetToFactory(check: ResponseChecker): Promise<FactoryResetResult>;
/** Export the card authentikey and check it against the secure-channel candidates. */
export declare function getAuthentikey(send: SecureSender, secureChannel: SecureChannel): Promise<ECPubkey>;
/** Get the card label ('(none)' if the applet does not support labels). */
export declare function getLabel(send: SecureSender): Promise<string>;
/** Set the card label (UTF-8). */
export declare function setLabel(send: SecureSender, label: string): Promise<void>;
/** Export the personalization certificate (PEM) used for authenticity checks. */
export declare function exportPersoCertificate(send: SecureSender): Promise<string>;
/** Challenge-response proving the card holds the authentikey private key. */
export declare function cardChallengeResponsePki(send: SecureSender, authentikeyBytes: Buffer): Promise<ChallengeResponseResult>;
/** Export the personalization public key (65-byte uncompressed). */
export declare function exportPersoPubkey(send: SecureSender): Promise<Buffer>;
