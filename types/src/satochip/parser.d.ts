import { SecureChannelInitResponse } from './types';
import { ECPubkey } from './utils/ECKey';
export declare class CardDataParser {
    private static getCoordxFromPubkey;
    static bip32path2bytes(bip32path: string): {
        depth: number;
        bytePath: Buffer;
    };
    /**
     * Helper function to format a byte path back to string representation
     * @param bytePath - Buffer containing 4-byte path indices
     * @returns String representation like "m/44'/0'/0'"
     */
    static bytes2Bip32path(bytePath: Buffer): string;
    /**
     * Sign a transaction hash (simpler version for pre-computed hash).
     *
     * @param sigin - the signature in DER format (70-72 bytes)
     * @param recid - The secure channel for communication
     * @param compressed - flag indicating whether the signature key use compressed format
     * @returns Buffer containing the compact signature (65-byte format)
     */
    static parseToCompactSig(sigin: Buffer, recid: number, compressed: boolean): Buffer;
    static parseGetAuthentikey(response: Buffer, authentikeyFromStorage?: ECPubkey): ECPubkey;
    static parseBip32ImportSeed(response: Buffer, authentikeyFromStorage?: ECPubkey): ECPubkey;
    static parseBip32GetExtendedkey(response: Buffer): {
        pubkey: ECPubkey;
        chaincode: Buffer;
        authentikeyCandidates: ECPubkey[];
    };
    static parseGetPubkeyFromKeyslot(response: Buffer): ECPubkey;
    static parseInitiateSecureChannel(response: Buffer, authentikey?: ECPubkey): SecureChannelInitResponse;
    static parseMessageSignature(response: Buffer, hash: Buffer, pubkey: ECPubkey): Buffer;
    static convertBytesToStringPem(certBytes: Buffer): string;
    static verifyChallengeResponsePki(response: Buffer, challengeFromHost: Buffer, pubkey: Buffer): {
        success: boolean;
        error: string;
    };
    private static getPubkeyFromSignature;
    private static getPubkeyCandidatesFromSignature;
    private static verifySignature;
}
