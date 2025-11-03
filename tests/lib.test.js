import * as primitives from '../src/satochip/utils/crypto.js';

test('sha256s', () => {
  expect(Buffer.from(primitives.sha256s('abc')).toString('hex')).toBe(
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  );
});

test('hash160', () => {
  expect(primitives.hash160('abc').toString('hex')).toBe(
    'bb1be98c142444d7a56aa3981c3942a978e4dc33'
  );
});
