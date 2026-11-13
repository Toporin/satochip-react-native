import { SatodimeCard } from '../src/satodime/SatodimeCard';
import { computeUnlockCode } from '../src/satodime/unlock';
import { mapSatodimeErrorCode } from '../src/satodime/errors';

const SECRET = Buffer.from(Array.from({ length: 20 }, (_, i) => i + 1));
const HASH = Buffer.from('5311cbc30b4aa227b168e128b0c0f7f2a977a1e822b17598f02da61912757154', 'hex');

function hex(b) {
  return Buffer.from(b).toString('hex');
}

describe('SatodimeCard command sequencing (transport mocked)', () => {
  function makeCard({ protocolMinor = 2, counter = '0000000a' } = {}) {
    const card = new SatodimeCard();
    const sent = [];
    card.sendPlain = jest.fn(async () => ({ data: Buffer.from(`000${protocolMinor}000101010101000001 01`.replace(/ /g, ''), 'hex') }));
    card.sendSecure = jest.fn(async (cmd) => {
      sent.push(cmd);
      if (cmd.ins === 0x50) {
        return { data: Buffer.from(counter + '03' + '020100' + '00000000', 'hex') };
      }
      if (cmd.ins === 0x5b) {
        return { data: Buffer.from('3006020101020101', 'hex') };
      }
      return { data: Buffer.alloc(0) };
    });
    return { card, sent };
  }

  test('signTransactionHash reads the counter then sends 0x5B with the right unlock code', async () => {
    const { card, sent } = makeCard();
    card.setUnlockSecret(SECRET);
    const der = await card.signTransactionHash(0, HASH);
    expect(hex(der)).toBe('3006020101020101');
    expect(sent.map((c) => c.ins)).toEqual([0x50, 0x5b]);
    const sign = sent[1];
    expect(hex(sign.data.slice(32, 36))).toBe('0000000a');
    const prefix = Buffer.concat([Buffer.from('b05b000038', 'hex'), HASH, Buffer.from('0000000a', 'hex')]);
    expect(hex(sign.data.slice(36))).toBe(hex(computeUnlockCode(SECRET, prefix)));
  });

  test('hash signing is refused on protocol 0.1 cards', async () => {
    const { card } = makeCard({ protocolMinor: 1 });
    card.setUnlockSecret(SECRET);
    await expect(card.signTransactionHash(0, HASH)).rejects.toMatchObject({ code: 'SW_UNSUPPORTED_FEATURE' });
    expect(card.supportsHashSigning()).toBe(false);
  });

  test('unlocked commands need the unlock secret', async () => {
    const { card } = makeCard();
    await expect(card.signTransactionHash(0, HASH)).rejects.toMatchObject({ code: 'SW_UNLOCK_SECRET_MISSING' });
  });

  test('checkUnlockCode returns false on 9C51', async () => {
    const { card } = makeCard();
    card.setUnlockSecret(SECRET);
    card.sendSecure = jest.fn(async (cmd) => {
      if (cmd.ins === 0x50) {
        return { data: Buffer.from('00000001' + '03' + '000000' + '01000000', 'hex') };
      }
      throw mapSatodimeErrorCode(0x9c, 0x51);
    });
    await expect(card.checkUnlockCode()).resolves.toBe(false);
  });
});
