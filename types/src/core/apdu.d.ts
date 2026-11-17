import { APDUCommand, APDUResponse } from '../satochip/types';
import { ResponseChecker } from './errors';
import type { SecureChannel } from './SecureChannel';
export declare function buildAPDU(command: APDUCommand): number[];
export declare function parseAPDUResponse(responseBytes: number[]): APDUResponse;
/** Send a plain APDU and return the raw response (status word not checked). */
export declare function transmitAPDU(command: APDUCommand): Promise<APDUResponse>;
/** Send a plain APDU and check its status word with `check`. */
export declare function sendPlainAPDU(command: APDUCommand, check: ResponseChecker): Promise<APDUResponse>;
/**
 * Send an APDU wrapped in the secure channel (establishing it if needed),
 * check the status word with `check` and return the decrypted response.
 */
export declare function sendEncryptedAPDU(command: APDUCommand, secureChannel: SecureChannel, check: ResponseChecker): Promise<APDUResponse>;
