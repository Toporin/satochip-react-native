import { SecureChannel } from '../SecureChannel';
import { ChallengeResponseResult } from '../../core/commands/common';
export type { ChallengeResponseResult };
export declare function exportPersoCertificate(secureChannel: SecureChannel): Promise<string>;
export declare function cardChallengeResponsePki(secureChannel: SecureChannel, authentikeyBytes: Buffer): Promise<ChallengeResponseResult>;
export declare function cardExportPersoPubkey(secureChannel: SecureChannel): Promise<Buffer>;
