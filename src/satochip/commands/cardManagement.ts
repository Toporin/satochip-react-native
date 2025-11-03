import * as crypto from 'crypto';

//import { sendAPDU } from '../apdu';
import { sendAPDU, sendSecureAPDU } from '../apduSecure';
import {
  DEFAULT_PIN_BYTES,
  INS_EXPORT_AUTHENTIKEY,
  INS_GET_STATUS,
  INS_SELECT,
  INS_SETUP,
  SATOCHIP_AID,
  SATOCHIP_CLA,
  INS_CARD_LABEL,
} from '../constants';
import { APDUCommand, APDUResponse, SatochipStatus } from '../types';
import { SecureChannel } from '../SecureChannel';
import { ECPubkey } from '../utils/ECKey';
import { CardDataParser } from '../parser';
import { SatochipCardError } from '../errors';
import { console_log } from '../utils/logging';

export async function selectApplet(): Promise<APDUResponse> {
  const command: APDUCommand = {
    cla: 0x00, // Use standard CLA for SELECT command
    ins: INS_SELECT,
    p1: 0x04,
    p2: 0x00,
    data: SATOCHIP_AID,
  };

  return await sendAPDU(command);
}

/**
 * Get the card authentikey (master public key).
 */
export async function getAuthentikey(secureChannel: SecureChannel): Promise<ECPubkey> {
  if (!secureChannel) {
    throw new Error('Secure channel required for authentikey');
  }

  const command: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_EXPORT_AUTHENTIKEY, //INS_BIP32_GET_AUTHENTIKEY,
    p1: 0x00,
    p2: 0x00,
    le: 0x00
  };

  const response = await sendSecureAPDU(command, secureChannel);
  const recoveredAuthentikey = CardDataParser.parseGetAuthentikey(response.data);

  // check that recovered authentikey matches cached value
  secureChannel.checkAuthentikeyCandidates([recoveredAuthentikey]);

  return recoveredAuthentikey;
}

export async function getStatus(): Promise<SatochipStatus> {
  const command: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_GET_STATUS,
    p1: 0x00,
    p2: 0x00,
  };
  
  const response = await sendAPDU(command);

  console_log('Satochip getStatus:', response);
  console_log('Satochip getStatus:', response.data);
  
  let offset = 0;
  const protocol_version = response.data.readUInt16BE(offset);
  offset += 2;
  
  const applet_version = response.data.readUInt16BE(offset);
  offset += 2;

  const pin0_tries = response.data.readUInt8(offset++);
  const puk0_tries = response.data.readUInt8(offset++);
  const pin1_tries = response.data.readUInt8(offset++);
  const puk1_tries = response.data.readUInt8(offset++);
  
  const needs_2fa = response.data.readUInt8(offset++) === 1;
  const is_seeded = response.data.readUInt8(offset++) === 1;
  const setup_done = response.data.readUInt8(offset++) === 1;
  const needs_secure_channel = response.data.readUInt8(offset++) === 1;

  let nfc_policy = 0x00; //NFC_ENABLED by default
  if (response.data.length >= 13) {
    nfc_policy = response.data.readUInt8(12); // 0:NFC_ENABLED, 1:NFC_DISABLED, 2:NFC_BLOCKED
  }

  let schnorr_policy = -1;
  let nostr_policy = -1;
  let liquid_policy = -1;
  let musig2_policy = -1;
  if (response.data.length >= 17) {
    // 0:FEATURE_ENABLED, 1:FEATURE_DISABLED, 2:FEATURE_BLOCKED
    schnorr_policy = response.data.readUInt8(13);
    nostr_policy = response.data.readUInt8(14);
    liquid_policy = response.data.readUInt8(15);
    musig2_policy = response.data.readUInt8(16);
  }

  return {
    protocol_version,
    applet_version,
    pin0_tries,
    puk0_tries,
    pin1_tries,
    puk1_tries,
    needs_2fa,
    is_seeded,
    setup_done,
    needs_secure_channel,
    nfc_policy,
    schnorr_policy,
    nostr_policy,
    liquid_policy,
    musig2_policy,
  };
}

export async function setup(secureChannel: SecureChannel, pin: string, max_try= 5): Promise<void> {
  // Build setup data according to protocol specification
  const setupData: Buffer[] = [];
  
  // Default PIN
  const defaultPinBytes = DEFAULT_PIN_BYTES; //Buffer.from(config.default_pin, 'utf8');
  setupData.push(Buffer.from([defaultPinBytes.length]));
  setupData.push(defaultPinBytes);
  
  // PIN0 configuration
  setupData.push(Buffer.from([max_try])); // pin_tries0
  setupData.push(Buffer.from([1])); // puk_tries0
  
  const pin0Bytes = Buffer.from(pin, 'utf8');
  setupData.push(Buffer.from([pin0Bytes.length]));
  setupData.push(pin0Bytes);
  
  const puk0Bytes = crypto.randomBytes(16); // We use a random value as the PUK is not used currently and is not user-friendly
  setupData.push(Buffer.from([puk0Bytes.length]));
  setupData.push(puk0Bytes);
  
  // PIN1 configuration
  setupData.push(Buffer.from([1]));
  setupData.push(Buffer.from([1]));
  
  const pin1Bytes =  crypto.randomBytes(16); // We use a random value as the PIN1 is not used currently
  setupData.push(Buffer.from([pin1Bytes.length]));
  setupData.push(pin1Bytes);
  
  const puk1Bytes =  crypto.randomBytes(16); // We use a random value as the PUK1 is not used currently
  setupData.push(Buffer.from([puk1Bytes.length]));
  setupData.push(puk1Bytes);
  
  // Memory configuration
  const secmemsize = 32; // default, used for satochip
  setupData.push(Buffer.from([(secmemsize >> 8) & 0xFF, secmemsize & 0xFF]));
  
  // Reserved fields
  setupData.push(Buffer.from([0, 0])); // RFU(2b)
  setupData.push(Buffer.from([0, 0, 0])); // RFU(3b)

  const command: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_SETUP,
    p1: 0x00,
    p2: 0x00,
    data: Buffer.concat(setupData),
  };

  await sendSecureAPDU(command, secureChannel);
}

/**
 * Get the card label from the Satochip
 *
 * @param secureChannel
 * @returns Promise containing the label string
 * @throws Error if there's an unexpected error during transmission
 */
export async function cardGetLabel(secureChannel: SecureChannel): Promise<string> {
  console_log('In cardGetLabel');

  const command: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_CARD_LABEL,
    p1: 0x00,
    p2: 0x01, // Get operation
  };

  let label: string;

  try {
    const response = await sendSecureAPDU(command, secureChannel);

    // Success - decode the label
    const labelSize = response.data.readUInt8(0);
    try {
      // Extract label bytes (skip the first byte which is the size)
      const labelBytes = response.data.slice(1, 1 + labelSize);
      label = labelBytes.toString('utf8');
    } catch (error) {
      console.warn('Error decoding card label:', error);
      // Fallback to hex representation if UTF-8 decode fails
      label = response.data.slice(1).toString('hex');
    }

  } catch (error) {
    console.warn('Error getting card label:', error);
    //label = error.message;
    if (error instanceof SatochipCardError) {
      if (error.statusWord == 0x6D00){
        // INS_NOT_SUPPORTED - card doesn't support labels
        label = '(none)';
      } else {
        throw error;
      }
    } else {
      throw error;
    }
  }

  return label;
}

/**
 * Set the card label on the Satochip
 *
 * @param secureChannel
 * @param label - The label string to set on the card (will be UTF-8 encoded)
 * @returns void
 * @throws Error if there's an unexpected error during transmission
 */
export async function cardSetLabel(secureChannel: SecureChannel, label: string): Promise<void> {
  console_log('In cardSetLabel');

  // Encode label to UTF-8 bytes
  const labelBytes = Buffer.from(label, 'utf8');

  // Build data: [length, ...label_bytes]
  const data = Buffer.concat([
    Buffer.from([labelBytes.length]),
    labelBytes,
  ]);

  const command: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_CARD_LABEL,
    p1: 0x00,
    p2: 0x00, // Set operation
    data,
  };

  const response = await sendSecureAPDU(command, secureChannel);
}

