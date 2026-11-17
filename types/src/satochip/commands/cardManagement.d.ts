import { APDUResponse, SatochipStatus } from '../types';
import { SecureChannel } from '../SecureChannel';
import { ECPubkey } from '../utils/ECKey';
export declare function selectApplet(): Promise<APDUResponse>;
/**
 * Get the card authentikey (master public key).
 */
export declare function getAuthentikey(secureChannel: SecureChannel): Promise<ECPubkey>;
export declare function getStatus(): Promise<SatochipStatus>;
export declare function setup(secureChannel: SecureChannel, pin: string, max_try?: number): Promise<void>;
/**
 * Get the card label ('(none)' if the card does not support labels).
 */
export declare function cardGetLabel(secureChannel: SecureChannel): Promise<string>;
/**
 * Set the card label on the Satochip (UTF-8 encoded).
 */
export declare function cardSetLabel(secureChannel: SecureChannel, label: string): Promise<void>;
