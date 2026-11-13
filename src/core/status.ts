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
export function parseCardVersion(data: Buffer): CardVersion {
  if (data.length < 4) {
    throw new Error('Invalid status response: too short');
  }
  const [protocolMajor, protocolMinor, appletMajor, appletMinor] = [data[0], data[1], data[2], data[3]];
  return {
    protocolMajor,
    protocolMinor,
    appletMajor,
    appletMinor,
    protocolVersion: (protocolMajor << 8) | protocolMinor,
    appletVersion: (appletMajor << 8) | appletMinor,
  };
}

/** Human-readable "vX.Y-Z.W" (protocol-applet), as used in the applet changelogs. */
export function formatCardVersion(v: CardVersion): string {
  return `v${v.protocolMajor}.${v.protocolMinor}-${v.appletMajor}.${v.appletMinor}`;
}
