/** Version information common to every applet's GET_STATUS (INS 0x3C) response. */
export interface CardVersion {
    protocolMajor: number;
    protocolMinor: number;
    appletMajor: number;
    appletMinor: number;
    /** (protocolMajor << 8) | protocolMinor */
    protocolVersion: number;
    /** (appletMajor << 8) | appletMinor */
    appletVersion: number;
}
/** Parse the first 4 bytes of a GET_STATUS response. */
export declare function parseCardVersion(data: Buffer): CardVersion;
/** Human-readable "vX.Y-Z.W" (protocol-applet), as used in the applet changelogs. */
export declare function formatCardVersion(v: CardVersion): string;
