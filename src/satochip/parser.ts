import * as crypto from 'crypto';
import { ec as EC } from 'elliptic';
import { SecureChannelInitResponse } from './types';
import { ECPubkey, InvalidECPointException } from './utils/ECKey';
import { SatochipError } from './errors';
import { console_log } from './utils/logging';

export class CardDataParser {

  // ========================================
  // utility methods
  // ========================================

  // Helper to extract coordx from full pubkey
  private static getCoordxFromPubkey(pubkey: ECPubkey): Buffer {
    const fullKey = pubkey.getPublicKeyBytes(true); // compressed
    return fullKey.slice(1); // remove prefix byte (0x02 or 0x03)
  }

  static bip32path2bytes(bip32path: string): { depth: number; bytePath: Buffer } {
    console_log(`In parser bip32path2bytes bip32path: ${bip32path}`);
    let splitPath = bip32path.split('/').filter(x => x);
    if (splitPath.length > 0 && splitPath[0] === 'm') {
      splitPath = splitPath.slice(1);
    }

    const buffers: Buffer[] = [];
    const depth = splitPath.length;

    for (const index of splitPath) {
      const buffer = Buffer.alloc(4);
      if (index.endsWith("'")) {
        buffer.writeUInt32BE(parseInt(index.slice(0, -1)) + 0x80000000, 0);
      } else {
        buffer.writeUInt32BE(parseInt(index), 0);
      }
      buffers.push(buffer);
    }

    return { depth, bytePath: Buffer.concat(buffers) };
  }

  /**
   * Helper function to format a byte path back to string representation
   * @param bytePath - Buffer containing 4-byte path indices
   * @returns String representation like "m/44'/0'/0'"
   */
  static bytes2Bip32path(bytePath: Buffer): string {
    if (bytePath.length === 0) {
      return 'm';
    }

    let path = 'm';
    for (let i = 0; i < bytePath.length; i += 4) {
      const index = bytePath.readUInt32BE(i);
      if (index >= 0x80000000) {
        // Hardened
        path += `/${index - 0x80000000}'`;
      } else {
        // Normal
        path += `/${index}`;
      }
    }

    return path;
  }

  /**
   * Sign a transaction hash (simpler version for pre-computed hash).
   *
   * @param sigin - the signature in DER format (70-72 bytes)
   * @param recid - The secure channel for communication
   * @param compressed - flag indicating whether the signature key use compressed format
   * @returns Buffer containing the compact signature (65-byte format)
   */
  static parseToCompactSig(sigin: Buffer, recid: number, compressed: boolean): Buffer {
    console_log(`In parser parseToCompactSig`);
    const sigout = Buffer.alloc(65);

    // Parse input
    const first = sigin[0];
    if (first !== 0x30) {
      throw new Error("Wrong first byte!");
    }

    const lt = sigin[1];
    const check = sigin[2];
    if (check !== 0x02) {
      throw new Error("Check byte should be 0x02");
    }

    // Extract r
    const lr = sigin[3];
    for (let i = 0; i < 32; i++) {
      const tmp = sigin[4 + lr - 1 - i];
      if (lr >= (i + 1)) {
        sigout[32 - i] = tmp;
      } else {
        sigout[32 - i] = 0;
      }
    }

    // Extract s
    const check2 = sigin[4 + lr];
    if (check2 !== 0x02) {
      throw new Error("Second check byte should be 0x02");
    }

    const ls = sigin[5 + lr];
    if (lt !== (lr + ls + 4)) {
      throw new Error("Wrong lt value");
    }

    for (let i = 0; i < 32; i++) {
      const tmp = sigin[5 + lr + ls - i];
      if (ls >= (i + 1)) {
        sigout[64 - i] = tmp;
      } else {
        sigout[64 - i] = 0;
      }
    }

    // 1 byte header
    if (recid > 3 || recid < 0) {
      throw new Error("Wrong recid value");
    }

    if (compressed) {
      sigout[0] = 27 + recid + 4;
    } else {
      sigout[0] = 27 + recid;
    }

    return sigout;
  }

  // ========================================
  // Parser methods for card management
  // ========================================

  static parseGetAuthentikey(
    response: Buffer,
    authentikeyFromStorage?: ECPubkey
  ): ECPubkey {

    const coordxSize = (response[0] << 8) + response[1];
    const coordx = response.slice(2, 2 + coordxSize);
    const dataSize = 2 + coordxSize;
    const data = response.slice(0, dataSize);
    const sigSize = (response[dataSize] << 8) + response[dataSize + 1];
    const signature = response.slice(dataSize + 2, dataSize + 2 + sigSize);

    if (sigSize === 0) {
      throw new Error("Signature missing");
    }

    const authentikey = this.getPubkeyFromSignature(coordx, data, signature);

    // if already initialized, check that authentikey matches value from storage
    if (authentikeyFromStorage && !authentikey.equals(authentikeyFromStorage)) {
      throw new SatochipError(`Authentikey mismatch: recovered authentikey ${authentikey.getPublicKeyBytes().toString('hex')}`);
    }

    return authentikey;
  }

  // ========================================
  // Parser methods for BIP32
  // ========================================

  static parseBip32ImportSeed(
    response: Buffer,
    authentikeyFromStorage?: ECPubkey
  ): ECPubkey {
    return this.parseGetAuthentikey(response, authentikeyFromStorage);
  }

  // Methods that use authentikey (passed as parameter)
  static parseBip32GetExtendedkey(
    response: Buffer
  ): { pubkey: ECPubkey; chaincode: Buffer, authentikeyCandidates: ECPubkey[] } {

    // First self-signed signature
    const chaincode = response.slice(0, 32);
    const dataSize = ((response[32] & 0x7f) << 8) + response[33];
    const data = response.slice(34, 32 + 2 + dataSize);
    const msgSize = 32 + 2 + dataSize;
    const msg = response.slice(0, msgSize);
    const sigSize = (response[msgSize] << 8) + response[msgSize + 1];
    const signature = response.slice(msgSize + 2, msgSize + 2 + sigSize);

    if (sigSize === 0) {
      throw new Error("Signature missing");
    }

    const coordx = data;
    const pubkey = this.getPubkeyFromSignature(coordx, msg, signature);

    // Second signature by authentikey
    const msg2Size = msgSize + 2 + sigSize;
    const msg2 = response.slice(0, msg2Size);
    const sig2Size = (response[msg2Size] << 8) + response[msg2Size + 1];
    const sig2 = response.slice(msg2Size + 2, msg2Size + 2 + sig2Size);
    const authentikeyCandidates = this.getPubkeyCandidatesFromSignature(msg2, sig2);

    return { pubkey, chaincode, authentikeyCandidates};
  }

  // ========================================
  // Parser method for keyslot
  // ========================================

  static parseGetPubkeyFromKeyslot(response: Buffer): ECPubkey {
    const resp = Buffer.from(response);
    const coordxSize = (resp[0] << 8) + resp[1];
    const coordx = resp.slice(2, 2 + coordxSize);
    const msgSize = 2 + coordxSize;
    const msg = resp.slice(0, msgSize);
    const sigSize = (resp[msgSize] << 8) + resp[msgSize + 1];
    const signature = resp.slice(msgSize + 2, msgSize + 2 + sigSize);

    if (sigSize === 0) {
      throw new Error("Signature missing");
    }

    const pubkey = this.getPubkeyFromSignature(coordx, msg, signature);
    return pubkey;
  }

  // ========================================
  // Parser method for Secure Channel
  // ========================================

  static parseInitiateSecureChannel(
    response: Buffer,
    authentikey?: ECPubkey
  ): SecureChannelInitResponse {
    console_log(`In parser static parseInitiateSecureChannel`);

    const coordxSize = (response[0] << 8) + response[1];
    const coordx = response.slice(2, 2 + coordxSize);
    const dataSize = 2 + coordxSize;
    const data = response.slice(0, dataSize);
    const sigSize = (response[dataSize] << 8) + response[dataSize + 1];
    const signature = response.slice(dataSize + 2, dataSize + 2 + sigSize);

    if (sigSize === 0) {
      throw new Error("Signature missing");
    }

    // console_log(`In parser static parseInitiateSecureChannel coordxSize: ${coordxSize}`);
    // console_log(`In parser static parseInitiateSecureChannel coordx: ${coordx.toString('hex')}`);
    // console_log(`In parser static parseInitiateSecureChannel msgSize: ${dataSize}`);
    // console_log(`In parser static parseInitiateSecureChannel msg: ${data.toString('hex')}`);
    // console_log(`In parser static parseInitiateSecureChannel sigSize: ${sigSize}`);
    // console_log(`In parser static parseInitiateSecureChannel signature: ${signature.toString('hex')}`);

    const pubkey = this.getPubkeyFromSignature(coordx, data, signature);

    // Second signature by authentikey (optional)
    const data2Size = dataSize + 2 + sigSize;
    const data2 = response.slice(0, data2Size);
    const sig2Size = (response[data2Size] << 8) + response[data2Size + 1];
    const sig2 = response.slice(data2Size + 2, data2Size + 2 + sig2Size);

    // TODO recover authentikey coordx if available
    const authentikeyCandidates: ECPubkey[] = [];
    const coordx2Offset = data2Size + 2 + sig2Size
    if (response.length >= coordx2Offset + 32){
      // recover unique authentikey from coordx, data & sig
      const coordx2 = response.slice(coordx2Offset, coordx2Offset + 32);
      authentikeyCandidates.push(this.getPubkeyFromSignature(coordx2, data2, sig2));
    } else {
      // recover list of authentikey candidates
      authentikeyCandidates.concat(this.getPubkeyCandidatesFromSignature(data2, sig2));
    }

    return {cardPublicKey: pubkey, authentikeyCandidates};
  }

  // ========================================
  // Parser method for signature
  // ========================================

  static parseMessageSignature(response: Buffer, hash: Buffer, pubkey: ECPubkey): Buffer {
    const coordx = pubkey.getPublicKeyBytes(true);
    const resp = Buffer.from(response);

    let recid = -1;
    let compactSig: Buffer | null = null;

    for (let id = 0; id < 4; id++) {
      const compsig = this.parseToCompactSig(resp, id, true);
      const compsig2 = compsig.slice(1);

      try {
        const pk = ECPubkey.fromSigString(compsig2, id, hash);
        const pkbytes = pk.getPublicKeyBytes(true);

        if (coordx.equals(pkbytes)) {
          recid = id;
          compactSig = compsig;
          break;
        }
      } catch (e) {
        if (e instanceof InvalidECPointException) {
          continue;
        }
        throw e;
      }
    }

    if (recid === -1) {
      throw new Error("Unable to recover public key from signature");
    }

    return compactSig!;
  }

  // ========================================
  // Parser method for PKI
  // ========================================

  static convertBytesToStringPem(certBytes: Buffer): string {
    console_log(`In parser convertBytesToStringPem`);
    const certB64 = certBytes.toString('base64');
    let certPem = "-----BEGIN CERTIFICATE-----\r\n";

    for (let i = 0; i < certB64.length; i += 64) {
      certPem += certB64.slice(i, i + 64) + '\r\n';
    }

    certPem += "-----END CERTIFICATE-----";
    return certPem;
  }

  static verifyChallengeResponsePki(
    response: Buffer,
    challengeFromHost: Buffer,
    pubkey: Buffer
  ): { success: boolean; error: string } {
    console_log(`In parser verifyChallengeResponsePki`);
    //const resp = Buffer.from(response);

    // Parse response
    const challengeFromDevice = response.slice(0, 32);
    const sigSize = (response[32] << 8) + response[33];
    const derSig = response.slice(34, 34 + sigSize);
    console_log(`In parser verifyChallengeResponsePki sigSize: ${sigSize}`);
    console_log(`In parser verifyChallengeResponsePki derSig: ${derSig.toString('hex')}`);

    const challengePrefix = Buffer.from("Challenge:", 'utf-8');
    const challenge = Buffer.concat([challengePrefix, challengeFromDevice, challengeFromHost]);

    // Verify signature using elliptic
    try {
      const ec = new EC('secp256k1');
      const key = ec.keyFromPublic(pubkey);
      const hash = crypto.createHash('sha256').update(challenge).digest();

      const verified = key.verify(hash, derSig);

      if (verified) {
        return { success: true, error: "" };
      } else {
        return { success: false, error: "Bad signature during challenge response!" };
      }
    } catch (e) {
      return { success: false, error: "Invalid X9.62 encoding of the public key: " + pubkey.toString('hex') };
    }
  }

  // ========================================
  // Private helper methods
  // ========================================

  private static getPubkeyFromSignature(coordx: Buffer, data: Buffer, sig: Buffer): ECPubkey {
    // In the Satochip protocol, the card signs SHA256(data)
    // We need to hash the data first, then use that hash for recovery
    const hash = crypto.createHash('sha256').update(data).digest();

    let recid = -1;
    let pubkey: ECPubkey | null = null;

    // console_log(`In parser static getPubkeyFromSignature coordx: ${coordx.toString('hex')}`);
    // console_log(`In parser static getPubkeyFromSignature data: ${data.toString('hex')}`);
    // console_log(`In parser static getPubkeyFromSignature sig: ${sig.toString('hex')}`);

    for (let id = 0; id < 4; id++) {
      // console_log(`In parser static getPubkeyFromSignature FOR LOOP ID: ${id}`);

      try {

        const ec = new EC('secp256k1');

        // recover public key from DER signature
        const recoveredPubkey =  ec.recoverPubKey(hash, sig, id);
        // console_log(`In parser static getPubkeyFromSignature recoveredPubkey(DER sig & hash):`);
        // console_log(JSON.stringify(recoveredPubkey, null, 2));

        const recoveredCoordx = recoveredPubkey.getX().toBuffer();
        // console_log(`In parser static getPubkeyFromSignature recoveredCoordx: ${recoveredCoordx.toString('hex')}`);

        if (coordx.equals(recoveredCoordx)) {
          recid = id;
          pubkey = new ECPubkey(recoveredPubkey.encode());
          // console_log(`In parser static getPubkeyFromSignature pubkey: ${recoveredPubkey.encode().toString('hex')}`);
          break;
        }
      } catch (e) {
        // console_log(`In parser static getPubkeyFromSignature error: failed to recover pubkey for id ${id}`);
        // console_log(`In parser static getPubkeyFromSignature error: ${e}`);
      }
    }

    if (recid === -1) {
      throw new Error("Unable to recover public key from signature");
    }

    return pubkey!;
  }

  private static getPubkeyCandidatesFromSignature(data: Buffer, sig: Buffer): ECPubkey[] {
    // In the Satochip protocol, the card signs SHA256(data)
    // We need to hash the data first, then use that hash for recovery
    const hash = crypto.createHash('sha256').update(data).digest();

    const pubkeys: ECPubkey[] = [];

    // console_log(`In parser static getPubkeyFromSignature data: ${data.toString('hex')}`);
    // console_log(`In parser static getPubkeyFromSignature sig: ${sig.toString('hex')}`);

    for (let id = 0; id < 2; id++) {
      // console_log(`In parser static getPubkeyFromSignature FOR LOOP ID: ${id}`);

      try {

        const ec = new EC('secp256k1');

        // recover public key from DER signature
        const recoveredPubkey =  ec.recoverPubKey(hash, sig, id);
        // console_log(`In parser static getPubkeyFromSignature recoveredPubkey(DER sig & hash):`);
        // console_log(JSON.stringify(recoveredPubkey, null, 2));

        // add to list of candidates
        pubkeys.push(new ECPubkey(recoveredPubkey.encode()));
      } catch (e) {
        // console_log(`In parser static getPubkeyCandidatesFromSignature error: failed to recover pubkey for id ${id}`);
        // console_log(`In parser static getPubkeyCandidatesFromSignature error: ${e}`);
      }
    }

    return pubkeys;
  }


  private static verifySignature(data: Buffer, sig: Buffer, authentikey: ECPubkey): ECPubkey {
    const hash = crypto.createHash('sha256').update(data).digest();

    let recid = -1;
    let pk: ECPubkey | null = null;

    for (let id = 0; id < 4; id++) {
      const compsig = this.parseToCompactSig(sig, id, true);
      const compsigNoHeader = compsig.slice(1);

      try {
        pk = ECPubkey.fromSigString(compsigNoHeader, id, hash);

        if (pk.equals(authentikey)) {
          recid = id;
          break;
        }
      } catch (e) {
        if (e instanceof InvalidECPointException) {
          continue;
        }
        throw e;
      }
    }

    if (recid === -1) {
      throw new Error("Unable to recover authentikey from signature");
    }

    return pk!;
  }
}