export type CardType = 'satochip' | 'satodime' | 'seedkeeper' | 'satocash';
/** Applet AIDs (selected by prefix, as pysatochip does). */
export declare const CARD_AIDS: Readonly<Record<CardType, Buffer>>;
/**
 * Try to SELECT each known applet and return the first one present on the card.
 * Note: on iOS, an AID can only be selected if it is listed in the app's
 * com.apple.developer.nfc.readersession.iso7816.select-identifiers.
 * The selected applet afterwards is the detected one (or none).
 */
export declare function detectCardType(candidates?: CardType[]): Promise<CardType | null>;
