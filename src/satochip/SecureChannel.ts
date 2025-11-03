import { ec as EC } from 'elliptic';
import * as crypto from 'crypto';
import { initSecureChannel } from './commands/secureChannel';
import { SatochipCardError } from './errors';

import { ECPubkey } from './utils/ECKey';
import { console_log } from './utils/logging';

export class UninitializedSecureChannelError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UninitializedSecureChannelError';
  }
}

export class SecureChannel {
  private initializedSecureChannel = false;
  private scPubkey: any = null;
  private scPeerPubkey: any = null;
  private scIVcounter = 0;
  private sharedKey: Buffer | null = null;
  private derivedKey: Buffer | null = null;
  private macKey: Buffer | null = null;
  private ec: EC;
  private keyPair: any;
  private authentikeyCandidates: ECPubkey[] = [];

  constructor() {
    this.ec = new EC('secp256k1');
    this.keyPair = this.ec.genKeyPair();
    this.scPubkey = this.keyPair.getPublic();
  }

  public getPublicKey(): Buffer {
    return Buffer.from(this.scPubkey.encode('array', false));
  }

  public isEstablished(): boolean {
    return this.initializedSecureChannel;
  }

  public reset() {
    this.initializedSecureChannel = false;
    // generate new keypair
    this.keyPair = this.ec.genKeyPair();
    this.scPubkey = this.keyPair.getPublic();
  }

  public checkAuthentikeyCandidates(keys: ECPubkey[]): void {

    // if the stored list of authentikey candidates is empty, update it with the given list of candidates
    if (this.authentikeyCandidates.length == 0) {
      this.authentikeyCandidates = keys;
      return;
    }

    // otherwise, there should be an authentikey that is common in both list
    for (const key of keys) {
      const matchingKey = this.authentikeyCandidates.find(target => target.equals(key));
      if (matchingKey) {
        // Clear the target list and add only the matching key
        this.authentikeyCandidates.length = 0;
        this.authentikeyCandidates.push(matchingKey);
        return;
      }
    }

    // otherwise, throw an error
    throw new Error('No matching authentikey found in candidates.');
  }

  /**
   * Establish secure channel with the card
   * This should be called before any operations that require encryption
   */
  async establishSecureChannel(): Promise<void> {
    console_log('In SecureChannel establishSecureChannel');
    if (this.isEstablished()) {
      return; // Already established
    }

    try {
      // Get client public key
      const clientPublicKey = this.getPublicKey();
      // console_log(`In SecureChannel establishSecureChannel clientPublicKey: ${clientPublicKey.toString('hex')}`);

      // Initialize secure channel with card
      const { cardPublicKey, authentikeyCandidates } = await initSecureChannel(clientPublicKey);
      // console_log(`In SecureChannel establishSecureChannel cardPublicKey: ${cardPublicKey.getPublicKeyBytes().toString('hex')}`);
      // console_log(`In SecureChannel establishSecureChannel authentikeyCandidates.length: ${authentikeyCandidates.length}`);

      // Complete the secure channel setup
      this.initiateSecureChannel(cardPublicKey.getPublicKeyBytes(false));
      // console_log(`In SecureChannel establishSecureChannel after initiateSecureChannel`);

      // set list of authentikey candidates extracted from card response
      this.authentikeyCandidates = authentikeyCandidates;

      // secure channel is set
      this.initializedSecureChannel = true;

    } catch (error) {

      this.initializedSecureChannel = false;

      throw new SatochipCardError(
        0x9C13,
        'SW_INCORRECT_INITIALIZATION',
        `Failed to establish secure channel: ${error.message}`
      );
    }
  }

  public initiateSecureChannel(peerPubkeyBytes: Buffer): void {
    // console_log(`In SecureChannel initiateSecureChannel peerPubkeyBytes: ${peerPubkeyBytes.toString('hex')}`);
    this.scIVcounter = 1;

    // Parse peer public key from uncompressed format
    this.scPeerPubkey = this.ec.keyFromPublic(peerPubkeyBytes);
    // console_log(`In SecureChannel initiateSecureChannel scPeerPubkey: ${this.scPeerPubkey.getPublic().toString('hex')}`);

    // Compute shared secret using ECDH
    const sharedPoint = this.keyPair.derive(this.scPeerPubkey.getPublic());
    // console_log(`In SecureChannel initiateSecureChannel sharedPoint: ${sharedPoint}`);
    // console_log(JSON.stringify(sharedPoint, null, 2));

    this.sharedKey = sharedPoint.toBuffer('be', 32) //Buffer.from(sharedPoint.toArray('be', 32));
    // console_log(`In SecureChannel initiateSecureChannel this.sharedKey 'be': ${this.sharedKey.toString('hex')}`);

    // Derive encryption key
    const keyMac = crypto.createHmac('sha1', this.sharedKey);
    keyMac.update('sc_key');
    this.derivedKey = keyMac.digest().slice(0, 16);
    // console_log(`In SecureChannel initiateSecureChannel this.derivedKey: ${this.derivedKey.toString('hex')}`);

    // Derive MAC key
    const macMac = crypto.createHmac('sha1', this.sharedKey);
    macMac.update('sc_mac');
    this.macKey = macMac.digest();
    // console_log(`In SecureChannel initiateSecureChannel this.macKey: ${this.macKey.toString('hex')}`);
  }

  public encryptSecureChannel(dataBytes: Buffer): { iv: Buffer; ciphertext: Buffer; mac: Buffer } {
    // console_log(`In SecureChannel encryptSecureChannel`);
    // console_log(`In SecureChannel encryptSecureChannel dataBytes: ${dataBytes.toString('hex')}`);

    if (!this.initializedSecureChannel) {
      throw new UninitializedSecureChannelError('Secure channel is not initialized');
    }

    // Generate IV: 12 random bytes + 4 bytes counter (big-endian)
    const randomBytes = crypto.randomBytes(12);
    const counterBytes = Buffer.alloc(4);
    counterBytes.writeUInt32BE(this.scIVcounter, 0);
    const iv = Buffer.concat([randomBytes, counterBytes]);
    // console_log(`In SecureChannel encryptSecureChannel iv: ${iv.toString('hex')}`);


    // Apply PKCS#7 padding
    const blockSize = 16;
    const paddingLength = blockSize - (dataBytes.length % blockSize);
    const padding = Buffer.alloc(paddingLength, paddingLength);
    const paddedData = Buffer.concat([dataBytes, padding]);
    // console_log(`In SecureChannel encryptSecureChannel paddedData: ${paddedData.toString('hex')}`);

    // Encrypt using AES-128-CBC
    const cipher = crypto.createCipheriv('aes-128-cbc', this.derivedKey!, iv);
    cipher.setAutoPadding(false); // We've already added padding
    const ciphertext = Buffer.concat([cipher.update(paddedData), cipher.final()]);
    // console_log(`In SecureChannel encryptSecureChannel ciphertext: ${ciphertext.toString('hex')}`);
    
    this.scIVcounter += 2;

    // Calculate MAC: HMAC-SHA1(iv || length || ciphertext)
    const lengthBytes = Buffer.alloc(2);
    lengthBytes.writeUInt16BE(ciphertext.length, 0);
    const dataToMac = Buffer.concat([iv, lengthBytes, ciphertext]);
    const mac = crypto.createHmac('sha1', this.macKey!).update(dataToMac).digest();
    // console_log(`In SecureChannel encryptSecureChannel mac: ${mac.toString('hex')}`);

    return { iv, ciphertext, mac };
  }

  public decryptSecureChannel(iv: Buffer, ciphertext: Buffer): Buffer {
    if (!this.initializedSecureChannel) {
      throw new UninitializedSecureChannelError('Secure channel is not initialized');
    }

    // Decrypt using AES-128-CBC
    const decipher = crypto.createDecipheriv('aes-128-cbc', this.derivedKey!, iv);
    decipher.setAutoPadding(false); // We'll remove padding manually
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    // Remove PKCS#7 padding
    const paddingLength = decrypted[decrypted.length - 1];
    const unpadded = decrypted.slice(0, decrypted.length - paddingLength);
    return unpadded;
  }
}