import { sendSecureAPDU } from '../apduSecure';
import { 
  SATOCHIP_CLA,
  INS_VERIFY_PIN, 
  INS_CHANGE_PIN, 
  INS_UNBLOCK_PIN,
  INS_LOGOUT_ALL,
  MIN_PIN_LENGTH,
  MAX_PIN_LENGTH
} from '../constants';
import { APDUCommand } from '../types';
import { SecureChannel } from '../SecureChannel';
import { console_log } from '../utils/logging';

export async function verifyPIN(secureChannel: SecureChannel, pinNumber: number, pin: string): Promise<void> {
  console_log('In pinManagement verifyPIN');

  const pinBytes = Buffer.from(pin, 'utf8')

  if (pinBytes.length < MIN_PIN_LENGTH || pinBytes.length > MAX_PIN_LENGTH) {
    throw new Error(`PIN must be between ${MIN_PIN_LENGTH} and ${MAX_PIN_LENGTH} characters`);
  }
  
  if (pinNumber < 0 || pinNumber > 1) {
    throw new Error('PIN number must be 0 or 1');
  }


  const command: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_VERIFY_PIN,
    p1: pinNumber,
    p2: 0x00,
    data: pinBytes,
  };

  await sendSecureAPDU(command, secureChannel);
}

export async function changePIN(
  secureChannel: SecureChannel,
  pinNumber: number, 
  oldPin: string, 
  newPin: string
): Promise<void> {
  console_log('In pinManagement changePIN');

  if (oldPin.length < MIN_PIN_LENGTH || oldPin.length > MAX_PIN_LENGTH) {
    throw new Error(`Old PIN must be between ${MIN_PIN_LENGTH} and ${MAX_PIN_LENGTH} characters`);
  }
  
  if (newPin.length < MIN_PIN_LENGTH || newPin.length > MAX_PIN_LENGTH) {
    throw new Error(`New PIN must be between ${MIN_PIN_LENGTH} and ${MAX_PIN_LENGTH} characters`);
  }
  
  if (pinNumber < 0 || pinNumber > 1) {
    throw new Error('PIN number must be 0 or 1');
  }
  
  const oldPinBytes = Buffer.from(oldPin, 'utf8');
  const newPinBytes = Buffer.from(newPin, 'utf8');
  
  const data = Buffer.concat([
    Buffer.from([oldPinBytes.length]),
    oldPinBytes,
    Buffer.from([newPinBytes.length]),
    newPinBytes,
  ]);
  
  const command: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_CHANGE_PIN,
    p1: pinNumber,
    p2: 0x00,
    data,
  };

  await sendSecureAPDU(command, secureChannel);
}

export async function unblockPIN(secureChannel: SecureChannel, pinNumber: number, puk: string): Promise<void> {
  if (puk.length < MIN_PIN_LENGTH || puk.length > MAX_PIN_LENGTH) {
    throw new Error(`PUK must be between ${MIN_PIN_LENGTH} and ${MAX_PIN_LENGTH} characters`);
  }
  
  if (pinNumber < 0 || pinNumber > 1) {
    throw new Error('PIN number must be 0 or 1');
  }
  
  const command: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_UNBLOCK_PIN,
    p1: pinNumber,
    p2: 0x00,
    data: Buffer.from(puk, 'utf8'),
  };

  await sendSecureAPDU(command, secureChannel);
}

export async function logoutAll(secureChannel: SecureChannel): Promise<void> {
  const command: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_LOGOUT_ALL,
    p1: 0x00,
    p2: 0x00,
  };

  await sendSecureAPDU(command, secureChannel);
}