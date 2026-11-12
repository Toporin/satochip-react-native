/**
 * Card type detection by applet SELECT.
 * Must be called inside an open NFC session (e.g. from a card's nfcWrapper callback,
 * or after startConnection()).
 */
import { selectAid } from './commands/common';
import { SW_OK } from './errors';

export type CardType = 'satochip' | 'satodime' | 'seedkeeper' | 'satocash';

/** Applet AIDs (selected by prefix, as pysatochip does). */
export const CARD_AIDS: Readonly<Record<CardType, Buffer>> = {
  satochip: Buffer.from('5361746f43686970', 'hex'), // "SatoChip"
  satodime: Buffer.from('5361746f44696d65', 'hex'), // "SatoDime"
  seedkeeper: Buffer.from('536565644b6565706572', 'hex'), // "SeedKeeper"
  satocash: Buffer.from('5361746f63617368', 'hex'), // "Satocash"
};

/**
 * Try to SELECT each known applet and return the first one present on the card.
 * Note: on iOS, an AID can only be selected if it is listed in the app's
 * com.apple.developer.nfc.readersession.iso7816.select-identifiers.
 * The selected applet afterwards is the detected one (or none).
 */
export async function detectCardType(
  candidates: CardType[] = ['satochip', 'satodime', 'seedkeeper', 'satocash'],
): Promise<CardType | null> {
  for (const type of candidates) {
    const rapdu = await selectAid(CARD_AIDS[type]);
    if (rapdu.statusWord === SW_OK) {
      return type;
    }
  }
  return null;
}
