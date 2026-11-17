import { ECPubkey } from './utils/ECKey';
export interface APDUCommand {
    cla: number;
    ins: number;
    p1: number;
    p2: number;
    data?: Buffer;
    le?: number;
}
export declare class APDUResponse {
    data: Buffer;
    sw1: number;
    sw2: number;
    statusWord: number;
    constructor(data: Buffer, sw1: number, sw2: number, statusWord: number);
    toString(): string;
}
export interface SecureChannelData {
    iv: Buffer;
    ciphertext: Buffer;
    mac: Buffer;
}
export interface SecureChannelInitResponse {
    cardPublicKey: ECPubkey;
    authentikeyCandidates: ECPubkey[];
}
export interface SatochipStatus {
    protocol_version: number;
    applet_version: number;
    pin0_tries: number;
    puk0_tries: number;
    pin1_tries: number;
    puk1_tries: number;
    needs_2fa: boolean;
    is_seeded: boolean;
    setup_done: boolean;
    needs_secure_channel: boolean;
    nfc_policy: number;
    schnorr_policy: number;
    nostr_policy: number;
    liquid_policy: number;
    musig2_policy: number;
}
export declare enum Feature {
    SCHNORR = 0,
    NOSTR = 1,
    LIQUID = 2,
    MUSIG2 = 3
}
export declare enum Policy {
    ENABLED = 0,
    DISABLED = 1,
    BLOCKED = 2
}
export declare enum NFCPolicy {
    ENABLED = 0,
    DISABLED = 1,
    BLOCKED = 2
}
export interface BIP32Path {
    path: number[];
    pathString: string;
}
export interface ExtendedKey {
    pubkey: Buffer;
    chaincode: Buffer;
}
