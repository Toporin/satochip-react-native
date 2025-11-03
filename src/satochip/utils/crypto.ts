import { Message, sha256 } from 'js-sha256';
import RIPEMD160 from 'ripemd160';

/**
 * @param  {any} args
 * @returns any
 */
function ripemd160(args: any): any {
  return new RIPEMD160().update(args).digest();
}

/**
 * @param  {any} args
 * @returns any
 */
export function hash160(args: any): any {
  return ripemd160(Buffer.from(sha256s(args)));
}

/**
 * @param  {Message} msg
 * @returns number[]
 */
export function sha256s(msg: Message): number[] {
  const hash = sha256.create();
  const msg_digest = hash.update(msg).digest();
  return msg_digest;
}