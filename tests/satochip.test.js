import { buildAPDU, parseAPDUResponse } from '../src/satochip/apduSecure';
import { SATOCHIP_CLA, INS_GET_STATUS } from '../src/satochip/constants';
import { mapErrorCode, SatochipCardError } from '../src/satochip/errors';
import { APDUCommand } from '../src/satochip/types';

describe('Satochip APDU Functions', () => {
  test('buildAPDU should create correct APDU bytes', () => {
    //const command: APDUCommand = {
    const command = {
      cla: SATOCHIP_CLA,
      ins: INS_GET_STATUS,
      p1: 0x00,
      p2: 0x00,
    };
    
    const expectedBytes = [0xB0, 0x3C, 0x00, 0x00];
    const actualBytes = buildAPDU(command);
    
    expect(actualBytes).toEqual(expectedBytes);
  });

  test('buildAPDU should handle data correctly', () => {
    const testData = Buffer.from([0x01, 0x02, 0x03]);
    const command = {
      cla: SATOCHIP_CLA,
      ins: INS_GET_STATUS,
      p1: 0x00,
      p2: 0x00,
      data: testData,
    };
    
    const expectedBytes = [0xB0, 0x3C, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03];
    const actualBytes = buildAPDU(command);
    
    expect(actualBytes).toEqual(expectedBytes);
  });

  test('parseAPDUResponse should parse success response', () => {
    const responseBytes = [0x01, 0x02, 0x03, 0x90, 0x00];
    const response = parseAPDUResponse(responseBytes);
    
    expect(response.data).toEqual(Buffer.from([0x01, 0x02, 0x03]));
    expect(response.sw1).toBe(0x90);
    expect(response.sw2).toBe(0x00);
    expect(response.statusWord).toBe(0x9000);
  });

  test('parseAPDUResponse should handle empty data', () => {
    const responseBytes = [0x90, 0x00];
    const response = parseAPDUResponse(responseBytes);
    
    expect(response.data).toEqual(Buffer.from([]));
    expect(response.sw1).toBe(0x90);
    expect(response.sw2).toBe(0x00);
    expect(response.statusWord).toBe(0x9000);
  });
});

describe('Satochip Error Handling', () => {
  test('mapErrorCode should handle PIN failure correctly', () => {
    const error = mapErrorCode(0x63, 0xC3); // 3 attempts remaining
    
    expect(error).toBeInstanceOf(SatochipCardError);
    expect(error.code).toBe('SW_PIN_FAILED');
    expect(error.remainingAttempts).toBe(3);
    expect(error.message).toContain('3 attempts remaining');
  });

  test('mapErrorCode should handle unauthorized error', () => {
    const error = mapErrorCode(0x9C, 0x06);
    
    expect(error).toBeInstanceOf(SatochipCardError);
    expect(error.code).toBe('SW_UNAUTHORIZED');
    expect(error.statusWord).toBe(0x9C06);
  });

  test('mapErrorCode should handle unknown error', () => {
    const error = mapErrorCode(0xFF, 0xFF);
    
    expect(error).toBeInstanceOf(SatochipCardError);
    expect(error.code).toBe('SW_UNKNOWN');
    expect(error.message).toContain('FFFF');
  });
});

describe('Satochip Constants', () => {
  test('should have correct CLA value', () => {
    expect(SATOCHIP_CLA).toBe(0xB0);
  });

  test('should have correct GET_STATUS INS', () => {
    expect(INS_GET_STATUS).toBe(0x3C);
  });
});