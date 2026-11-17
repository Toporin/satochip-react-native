import { SecureChannel } from '../SecureChannel';
export declare function verifyPIN(secureChannel: SecureChannel, pinNumber: number, pin: string): Promise<void>;
export declare function changePIN(secureChannel: SecureChannel, pinNumber: number, oldPin: string, newPin: string): Promise<void>;
export declare function unblockPIN(secureChannel: SecureChannel, pinNumber: number, puk: string): Promise<void>;
export declare function logoutAll(secureChannel: SecureChannel): Promise<void>;
