import * as crypto from 'crypto';
import { ec as EC } from 'elliptic';
import * as codec from '../src/satodime/codec';
import { computeUnlockCode, cvcToUnlockSecret, incrementUnlockCounter } from '../src/satodime/unlock';
import { mapSatodimeErrorCode, SatodimeCardError } from '../src/satodime/errors';
import { KeyslotState } from '../src/satodime/constants';
import { buildAPDU } from '../src/core/apdu';
import { CardError } from '../src/core/errors';
import { formatCardVersion } from '../src/core/status';
import { SatochipCardError } from '../src/satochip/errors';

const secp256k1 = new EC('secp256k1');

// Fixtures: HMAC-SHA1 vectors computed independently with python
// (pysatochip formula: hmac.new(secret, apduheader + [data before counter] + counter, sha1))
const SECRET = Buffer.from(Array.from({ length: 20 }, (_, i) => i + 1));
const COUNTER = Buffer.from('00000005', 'hex');
const HASH = Buffer.from('5311cbc30b4aa227b168e128b0c0f7f2a977a1e822b17598f02da61912757154', 'hex'); // sha256('satodime')

function hex(b) {
  return Buffer.from(b).toString('hex');
}

describe('Satodime unlock code', () => {
  test('sign transaction hash (0x5B) data layout and HMAC', () => {
    const cmd = codec.encodeSignTransactionHash(1, HASH, COUNTER, SECRET);
    expect([cmd.cla, cmd.ins, cmd.p1, cmd.p2]).toEqual([0xb0, 0x5b, 0x01, 0x00]);
    expect(cmd.data.length).toBe(0x38);
    expect(hex(cmd.data.slice(0, 32))).toBe(hex(HASH));
    expect(hex(cmd.data.slice(32, 36))).toBe('00000005');
    expect(hex(cmd.data.slice(36))).toBe('c0cf42fcb92f074a2410fc7f35299e3bbaa22802');
    // the HMAC prefix is exactly the inner APDU up to the counter
    const apdu = Buffer.from(buildAPDU(cmd));
    expect(hex(apdu.slice(0, 5))).toBe('b05b010038');
  });

  test('check unlock code (0x54)', () => {
    const cmd = codec.encodeCheckUnlockCode(COUNTER, SECRET);
    expect(hex(Buffer.from(buildAPDU(cmd)))).toBe('b054000018' + '00000005' + '16c2a02210b0a00246f4a4ea0377b8dedfef3174');
  });

  test('unseal (0x58) slot 2', () => {
    const cmd = codec.encodeUnseal(2, COUNTER, SECRET);
    expect(hex(cmd.data.slice(4))).toBe('3a3914f7f0b78eb2677b36bfaaaebf5ec1cd2829');
  });

  test('seal (0x57): Lc includes the trailing entropy', () => {
    const entropy = Buffer.alloc(32, 0xaa);
    const cmd = codec.encodeSeal(0, COUNTER, SECRET, entropy);
    expect(cmd.data.length).toBe(0x38);
    expect(hex(cmd.data.slice(4, 24))).toBe('d0e22f02b895245ada552cba5e3a5d0f7b5e9f8b');
    expect(hex(cmd.data.slice(24))).toBe(hex(entropy));
  });

  test('set keyslot metadata (0x52, P2=0): layout and HMAC', () => {
    const cmd = codec.encodeSetKeyslotMetadata(0, COUNTER, SECRET, { asset: 0x01, slip44: 0x8000003c });
    expect(cmd.data.length).toBe(0x63); // 4 + 20 + 3 + 4 + 34 + 34
    expect(hex(cmd.data.slice(4, 24))).toBe('2e7bba874b9d9a3eaa270dc31f189bb8d2aac454');
    expect(hex(cmd.data.slice(24, 31))).toBe('0000018000003c');
    expect(hex(cmd.data.slice(31, 33))).toBe('0020'); // contract [RFU, size=32]
  });

  test('CVC secret is the code bytes zero-padded to 20', () => {
    const secret = cvcToUnlockSecret('ABC123');
    expect(secret.length).toBe(20);
    expect(hex(secret)).toBe(hex(Buffer.from('ABC123')) + '00'.repeat(14));
    const prefix = Buffer.concat([Buffer.from('b054000018', 'hex'), COUNTER]);
    expect(hex(computeUnlockCode(secret, prefix))).toBe('ed20f4a9084fd9b6f876ed59eb3ee80fc4b775fd');
  });

  test('counter increments big-endian with wrap-around', () => {
    expect(hex(incrementUnlockCounter(Buffer.from('000000ff', 'hex')))).toBe('00000100');
    expect(hex(incrementUnlockCounter(Buffer.from('ffffffff', 'hex')))).toBe('00000000');
  });

  test('input validation', () => {
    expect(() => codec.encodeSignTransactionHash(0, Buffer.alloc(31), COUNTER, SECRET)).toThrow();
    expect(() => codec.encodeSignTransactionHash(16, HASH, COUNTER, SECRET)).toThrow();
    expect(() => codec.encodeUnseal(0, Buffer.alloc(3), SECRET)).toThrow();
    expect(() => cvcToUnlockSecret('x'.repeat(21))).toThrow();
  });
});

describe('Satodime response decoding', () => {
  test('card status (0x3C) v0.2-0.1, setup done', () => {
    const s = codec.decodeCardStatus(Buffer.from('000200010101010100000101', 'hex'));
    expect(s.version.protocolVersion).toBe(0x0002);
    expect(s.version.appletVersion).toBe(0x0001);
    expect(formatCardVersion(s.version)).toBe('v0.2-0.1');
    expect(s.setupDone).toBe(true);
    expect(s.needsSecureChannel).toBe(true);
  });

  test('satodime status (0x50) protocol 0.2 with CVC flag', () => {
    const s = codec.decodeSatodimeStatus(Buffer.from('00000007' + '03' + '010200' + '01000000', 'hex'));
    expect(hex(s.unlockCounter)).toBe('00000007');
    expect(s.nbKeyslots).toBe(3);
    expect(s.keyslotStates).toEqual([KeyslotState.SEALED, KeyslotState.UNSEALED, KeyslotState.UNINITIALIZED]);
    expect(s.fixedUnlockSecret).toBe(true);
    expect(s.isCoA).toBe(false);
  });

  test('satodime status (0x50) protocol 0.1 without flags', () => {
    const s = codec.decodeSatodimeStatus(Buffer.from('00000001' + '03' + '000000', 'hex'));
    expect(s.keyslotStates).toEqual([0, 0, 0]);
    expect(s.fixedUnlockSecret).toBeUndefined();
  });

  test('keyslot status (0x51): 141 bytes, mainnet/testnet bit', () => {
    const contract = codec.emptyTlv32();
    const tokenid = codec.emptyTlv32();
    const data = Buffer.alloc(66);
    const mainnet = Buffer.concat([Buffer.from('0200018000003c', 'hex'), contract, tokenid, data]);
    expect(mainnet.length).toBe(141); // 1 + 1 + 1 + 4 + 34 + 34 + 66
    const k = codec.decodeKeyslotStatus(mainnet);
    expect(k.state).toBe(KeyslotState.UNSEALED);
    expect(k.asset).toBe(1);
    expect(k.slip44).toBe(0x8000003c);
    expect(k.isTestnet).toBe(false);
    const testnet = Buffer.from(mainnet);
    testnet[3] = 0x00; // MSB cleared => testnet
    expect(codec.decodeKeyslotStatus(testnet).isTestnet).toBe(true);
    expect(codec.decodeKeyslotStatus(testnet).slip44).toBe(60);
  });

  test('pubkey response (0x55) and authentikey signature', () => {
    const authentikey = secp256k1.genKeyPair();
    const vault = secp256k1.genKeyPair();
    const pubkey = Buffer.from(vault.getPublic(false, 'array'));
    const signed = Buffer.concat([Buffer.from('0041', 'hex'), pubkey]);
    const sig = Buffer.from(authentikey.sign(crypto.createHash('sha256').update(signed).digest()).toDER());
    const sigSize = Buffer.alloc(2);
    sigSize.writeUInt16BE(sig.length);
    const resp = codec.decodePubkeyResponse(Buffer.concat([signed, sigSize, sig]));
    expect(hex(resp.pubkey)).toBe(hex(pubkey));
    const authPub = Buffer.from(authentikey.getPublic(false, 'array'));
    expect(codec.verifyAuthentikeySignature(resp.signedData, resp.signature, authPub)).toBe(true);
    const other = Buffer.from(secp256k1.genKeyPair().getPublic(false, 'array'));
    expect(codec.verifyAuthentikeySignature(resp.signedData, resp.signature, other)).toBe(false);
  });

  test('privkey response (0x56/0x58)', () => {
    const body = Buffer.concat([
      Buffer.from('0060', 'hex'),
      Buffer.alloc(32, 1), Buffer.alloc(32, 2), Buffer.alloc(32, 3),
      Buffer.from('0020', 'hex'), Buffer.alloc(32, 4),
    ]);
    const sig = Buffer.from('3006020101020101', 'hex');
    const r = codec.decodePrivkeyResponse(Buffer.concat([body, Buffer.from('0008', 'hex'), sig]));
    expect(hex(r.userEntropy)).toBe('01'.repeat(32));
    expect(hex(r.authentikeyCoordx)).toBe('02'.repeat(32));
    expect(hex(r.cardEntropy)).toBe('03'.repeat(32));
    expect(hex(r.privkey)).toBe('04'.repeat(32));
    expect(hex(r.signature)).toBe(hex(sig));
  });

  test('setup response (0x2A)', () => {
    const o = codec.decodeSetupResponse(Buffer.concat([COUNTER, SECRET]));
    expect(hex(o.unlockCounter)).toBe('00000005');
    expect(hex(o.unlockSecret)).toBe(hex(SECRET));
  });
});

describe('Satodime status words', () => {
  test('Satodime-specific codes', () => {
    const e = mapSatodimeErrorCode(0x9c, 0x51);
    expect(e).toBeInstanceOf(SatodimeCardError);
    expect(e).toBeInstanceOf(CardError);
    expect(e.code).toBe('SW_INCORRECT_UNLOCK_CODE');
    expect(mapSatodimeErrorCode(0x9c, 0x50).code).toBe('SW_INCORRECT_UNLOCK_COUNTER');
    expect(mapSatodimeErrorCode(0x9c, 0x52).code).toBe('SW_INCORRECT_KEYSLOT_STATE');
    expect(mapSatodimeErrorCode(0x9c, 0x54).code).toBe('SW_UNKNOWN_PROTOCOL_MEDIA');
  });

  test('shared codes fall back to the common table', () => {
    const e = mapSatodimeErrorCode(0x9c, 0x20);
    expect(e).toBeInstanceOf(SatodimeCardError);
    expect(e.statusWord).toBe(0x9c20);
    expect(mapSatodimeErrorCode(0x6d, 0x00).code).toBe('SW_INS_NOT_SUPPORTED');
  });

  test('SatochipCardError is still a CardError', () => {
    expect(new SatochipCardError(0x9c06, 'SW_UNAUTHORIZED', 'x')).toBeInstanceOf(CardError);
  });
});
