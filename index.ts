// Satochip support
export {
  SatochipCard,
  SatochipCardError,
  Feature,
  Policy,
  NFCPolicy,
  SatochipConstants
} from './src/satochip';
export type {
  APDUCommand,
  APDUResponse,
  SatochipStatus,
} from './src/satochip';

// Shared core (all Satochip-family applets)
export {
  BaseCard,
  CardError,
  detectCardType,
  CARD_AIDS,
  parseCardVersion,
  formatCardVersion,
} from './src/core';
export type { CardType, CardVersion, ChallengeResponseResult } from './src/core';

// Satodime support
export {
  SatodimeCard,
  SatodimeCardError,
  KeyslotState,
  SATODIME_AID,
  SATODIME_ASSET,
  SatodimeCodec,
  SatodimeConstants,
  computeUnlockCode,
  cvcToUnlockSecret,
} from './src/satodime';
export type {
  SatodimeCardStatus,
  SatodimeStatus,
  KeyslotStatus,
  SatodimePrivkey,
  SatodimeOwnership,
  KeyslotMetadata,
} from './src/satodime';
