/**
 * Satochip APDU helpers. The transport and secure-channel wrapping are
 * card-agnostic (src/core/apdu.ts); this module keeps the historical Satochip
 * API and error mapping (SatochipCardError).
 */
import { APDUCommand, APDUResponse } from './types';
import { SecureChannel } from '../core/SecureChannel';
import { buildAPDU, parseAPDUResponse } from '../core/apdu';
export { buildAPDU, parseAPDUResponse };
export declare function sendAPDU(command: APDUCommand, check?: boolean): Promise<APDUResponse>;
/**
 * Enhanced APDU sender that can handle secure channel encryption automatically
 * This is the main function that should be used for secure commands
 */
export declare function sendSecureAPDU(command: APDUCommand, secureChannel?: SecureChannel | null): Promise<APDUResponse>;
