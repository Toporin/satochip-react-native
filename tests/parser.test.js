import * as crypto from 'crypto';
import { ec as EC } from 'elliptic';
import { CardDataParser } from '../src/satochip/parser';

const ec = new EC('secp256k1');

const u16 = (n) => Buffer.from([(n >> 8) & 0xff, n & 0xff]);
const coordx = (key) => Buffer.from(key.getPublic().getX().toArray('be', 32));
const compressed = (key) => Buffer.from(key.getPublic(true, 'array'));
const signDer = (key, data) => {
  const hash = crypto.createHash('sha256').update(data).digest();
  return Buffer.from(key.sign(hash, { canonical: true }).toDER());
};

/**
 * Build an InitiateSecureChannel response as returned by the applet:
 * [coordx_size(2b) | ephemeralkey_coordx | sig_size(2b) | self_sig | sig2_size(2b) | authentikey_sig]
 * and, for applet v0.16+, [coordx_size(2b) | authentikey_coordx] appended.
 */
function buildInitResponse(ephemeralKey, authentiKey, withAuthentikeyCoordx) {
  const data = Buffer.concat([u16(32), coordx(ephemeralKey)]);
  const sig = signDer(ephemeralKey, data);
  const data2 = Buffer.concat([data, u16(sig.length), sig]);
  const sig2 = signDer(authentiKey, data2);
  const parts = [data2, u16(sig2.length), sig2];
  if (withAuthentikeyCoordx) {
    parts.push(u16(32), coordx(authentiKey));
  }
  return Buffer.concat(parts);
}

describe('CardDataParser.parseInitiateSecureChannel', () => {
  // several random key pairs, so that both parities of y are exercised
  for (let i = 0; i < 8; i++) {
    const ephemeralKey = ec.genKeyPair();
    const authentiKey = ec.genKeyPair();

    test(`applet v0.16+ response (with authentikey coordx) #${i}`, () => {
      const response = buildInitResponse(ephemeralKey, authentiKey, true);
      const res = CardDataParser.parseInitiateSecureChannel(response);
      expect(res.cardPublicKey.getPublicKeyBytes(true)).toEqual(compressed(ephemeralKey));
      expect(res.authentikeyCandidates).toHaveLength(1);
      expect(res.authentikeyCandidates[0].getPublicKeyBytes(true)).toEqual(compressed(authentiKey));
    });

    test(`legacy response (without authentikey coordx) #${i}`, () => {
      const response = buildInitResponse(ephemeralKey, authentiKey, false);
      const res = CardDataParser.parseInitiateSecureChannel(response);
      expect(res.cardPublicKey.getPublicKeyBytes(true)).toEqual(compressed(ephemeralKey));
    });
  }
});
