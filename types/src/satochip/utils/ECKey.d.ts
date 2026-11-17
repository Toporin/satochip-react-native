export declare class ECPubkey {
    private key;
    private ec;
    constructor(pubkeyBytes: Buffer);
    getPublicKeyBytes(compressed?: boolean): Buffer;
    static fromSigString(sigString: Buffer, recid: number, hash: Buffer): ECPubkey;
    equals(other: ECPubkey): boolean;
}
export declare class ECPrivkey {
    private key;
    constructor(privkeyBytes: Buffer);
    getPublicKey(): ECPubkey;
}
export declare class InvalidECPointException extends Error {
    constructor(message: string);
}
