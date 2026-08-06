/// <reference types="node" />

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

export interface ExtendedKey {
  pubkey: Buffer;
  chaincode: Buffer;
}

export interface CardInfo {
  appletVersion: string;
  protocolVersion: string;
  setupDone: boolean;
  isSeeded: boolean;
  needs2FA: boolean;
  pinStates: { pin0Tries: number; pin1Tries: number };
}

export interface FactoryResetResult {
  complete: boolean;
  remaining: number;
}

export class SatochipCard {
  startNfcSession(): Promise<void>;
  endNfcSession(): Promise<void>;
  nfcWrapper<T>(callback: () => Promise<T>): Promise<T>;
  selectApplet(): Promise<void>;
  getStatus(): Promise<SatochipStatus>;
  getCachedStatus(): Promise<SatochipStatus>;
  getCardInfo(): Promise<CardInfo>;
  setup(pin: string, maxTry?: number): Promise<void>;
  getLabel(): Promise<string>;
  setLabel(label: string): Promise<void>;
  verifyPIN(pinNumber: number, pin: string): Promise<void>;
  changePIN(pinNumber: number, oldPin: string, newPin: string): Promise<void>;
  unblockPIN(pinNumber: number, puk: string): Promise<void>;
  logoutAll(): Promise<void>;
  isPINVerified(pinNumber: number): boolean;
  importSeed(seed: Buffer, options?: number): Promise<void>;
  resetSeed(pin: string): Promise<void>;
  factoryReset(): Promise<FactoryResetResult>;
  getExtendedKey(path: string): Promise<ExtendedKey>;
  getXpub(path: string, xtype?: string, isMainnet?: boolean): Promise<string>;
  getMasterXfp(): Promise<string>;
  signMessage(keyNumber: number, hash: Buffer, hmac?: Buffer): Promise<Buffer>;
  signTransactionHash(keyNumber: number, hash: Buffer, hmac?: Buffer): Promise<Buffer>;
  prepareSchnorrKey(keyNumber: number, bypassTweak?: boolean): Promise<Buffer>;
  signSchnorrHash(keyNumber: number, hash: Buffer, hmac?: Buffer): Promise<Buffer>;
  exportPersoCertificate(): Promise<string>;
  isSeeded(): Promise<boolean>;
}

export class SatochipCardError extends Error {
  statusWord: number;
  code: string;
  remainingAttempts?: number;
}

export enum Feature {
  SCHNORR = 0,
  NOSTR = 1,
  LIQUID = 2,
  MUSIG2 = 3,
}

export enum Policy {
  ENABLED = 0,
  DISABLED = 1,
  BLOCKED = 2,
}

export enum NFCPolicy {
  ENABLED = 0,
  DISABLED = 1,
  BLOCKED = 2,
}

export const SatochipConstants: Record<string, unknown>;
