import NfcManager from 'react-native-nfc-manager';
import { SatochipCard } from '../src/satochip/protocol';
import { SatochipCardError } from '../src/satochip/errors';
import { CardError } from '../src/core/errors';
import { taprootTweakPrivkey, signSchnorrHash } from '../src/satochip/commands/signature';
import * as apduSecure from '../src/satochip/apduSecure';

const HASH = Buffer.alloc(32, 0xab);

describe('SatochipCard.factoryReset (transport mocked)', () => {
  function mockStatusWord(sw) {
    const sent = [];
    jest.spyOn(NfcManager.isoDepHandler, 'transceive').mockImplementation(async (apdu) => {
      sent.push(apdu);
      return [sw >> 8, sw & 0xff];
    });
    return sent;
  }

  afterEach(() => jest.restoreAllMocks());

  test('sends a plain B0 FF 00 00 and reports the remaining presentations', async () => {
    const sent = mockStatusWord(0xff03);
    const result = await new SatochipCard().factoryReset();
    expect(sent).toEqual([[0xb0, 0xff, 0x00, 0x00]]);
    expect(result).toEqual({ complete: false, remaining: 3 });
  });

  test('0xFF00 means the reset is complete', async () => {
    mockStatusWord(0xff00);
    expect(await new SatochipCard().factoryReset()).toEqual({ complete: true, remaining: 0 });
  });

  test('0xFFFF means the sequence was interrupted', async () => {
    mockStatusWord(0xffff);
    await expect(new SatochipCard().factoryReset()).rejects.toMatchObject({
      code: 'SW_RESET_TO_FACTORY_ABORTED',
    });
  });

  test('other status words are mapped to SatochipCardError', async () => {
    mockStatusWord(0x6d00);
    const error = await new SatochipCard().factoryReset().catch((e) => e);
    expect(error).toBeInstanceOf(SatochipCardError);
    expect(error).toBeInstanceOf(CardError);
    expect(error.statusWord).toBe(0x6d00);
  });

  test('clears the PIN verification state', async () => {
    mockStatusWord(0xff00);
    const card = new SatochipCard();
    card.pinVerified.set(0, true);
    await card.factoryReset();
    expect(card.isPINVerified(0)).toBe(false);
  });
});

describe('Schnorr signing commands (secure transport mocked)', () => {
  let sent;
  function mockSecure(data) {
    sent = [];
    jest.spyOn(apduSecure, 'sendSecureAPDU').mockImplementation(async (command) => {
      sent.push(command);
      return { data, sw1: 0x90, sw2: 0x00, statusWord: 0x9000 };
    });
  }

  afterEach(() => jest.restoreAllMocks());

  test('taprootTweakPrivkey sends a zero tweak by default and the bypass flag in P2', async () => {
    mockSecure(Buffer.alloc(0));
    await taprootTweakPrivkey({}, 0xff, null, true);
    expect(sent[0]).toMatchObject({ cla: 0xb0, ins: 0x7c, p1: 0xff, p2: 0x01 });
    expect(sent[0].data.toString('hex')).toBe('20' + '00'.repeat(32));
  });

  test('taprootTweakPrivkey sends a custom tweak without bypass', async () => {
    mockSecure(Buffer.alloc(0));
    const tweak = Buffer.alloc(32, 0x11);
    await taprootTweakPrivkey({}, 0xff, tweak);
    expect(sent[0].p2).toBe(0x00);
    expect(sent[0].data.toString('hex')).toBe('20' + '11'.repeat(32));
  });

  test('taprootTweakPrivkey rejects a tweak that is not 32 bytes', async () => {
    mockSecure(Buffer.alloc(0));
    await expect(taprootTweakPrivkey({}, 0xff, Buffer.alloc(31))).rejects.toThrow('32 bytes');
  });

  test('signSchnorrHash sends the hash (and 2FA hmac) and returns the 64-byte signature', async () => {
    const sig = Buffer.alloc(64, 0x22);
    mockSecure(sig);
    expect(await signSchnorrHash({}, 0xff, HASH)).toEqual(sig);
    expect(sent[0]).toMatchObject({ cla: 0xb0, ins: 0x7b, p1: 0xff, p2: 0x00 });
    expect(sent[0].data).toEqual(HASH);

    const hmac = Buffer.alloc(20, 0x33);
    await signSchnorrHash({}, 0xff, HASH, hmac);
    expect(sent[1].data).toEqual(Buffer.concat([HASH, Buffer.from('8000', 'hex'), hmac]));
  });

  test('signSchnorrHash validates the hash, hmac and signature lengths', async () => {
    mockSecure(Buffer.alloc(64));
    await expect(signSchnorrHash({}, 0xff, Buffer.alloc(31))).rejects.toThrow('32 bytes');
    await expect(signSchnorrHash({}, 0xff, HASH, Buffer.alloc(10))).rejects.toThrow('0 or 20 bytes');

    mockSecure(Buffer.alloc(70));
    await expect(signSchnorrHash({}, 0xff, HASH)).rejects.toThrow('Invalid Schnorr signature length');
  });
});
