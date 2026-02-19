import { NativeModules }          from 'react-native';
import { CRYPTO_CONSTANTS, HKDF_INFO_LABELS } from './constants';
import { SecureBuffer }           from './RootKeyService';
import { MemoryWiper }            from './MemoryWiper';

const { NativeCrypto } = NativeModules;

/**
 * CanaryService embeds verifiable sentinel bytes into each fragment before
 * AES-GCM encryption. Even if GCM tag verification passes, a tampered
 * canary indicates cross-fragment substitution or key oracle attacks.
 *
 * Layout (after embedding, before AES):
 *   [ original fragment data ][ canary (16B) ][ derived padding (16B) ]
 *                              ^────────── CANARY_TOTAL_OVERHEAD ──────^
 */
export class CanaryService {
  private static readonly C = CRYPTO_CONSTANTS;

  /** Derive per-fragment canary bytes from ChapterRootKey. */
  static async derive(
    chapterRootKey: SecureBuffer,
    fragmentIndex:  number
  ): Promise<Uint8Array> {
    const ikmB64  = Buffer.from(chapterRootKey).toString('base64');
    const saltB64 = Buffer.from(`canary:${fragmentIndex}`).toString('base64');

    const b64: string = await NativeCrypto.hkdf(
      ikmB64, saltB64,
      HKDF_INFO_LABELS.CANARY_DERIVE,
      this.C.CANARY_LENGTH
    );
    return new Uint8Array(Buffer.from(b64, 'base64'));
  }

  /** Append canary + derived padding to fragment data. */
  static embed(data: Uint8Array, canary: Uint8Array): Uint8Array {
    const pad     = this.C.CANARY_TRAILING_PAD;
    const out     = new Uint8Array(data.length + this.C.CANARY_TOTAL_OVERHEAD);
    out.set(data,   0);
    out.set(canary, data.length);
    // Padding = XOR-scramble of canary bytes (deterministic, not secret)
    for (let i = 0; i < pad; i++) {
      out[data.length + this.C.CANARY_LENGTH + i] =
        canary[i % this.C.CANARY_LENGTH] ^ ((i + 1) * 0x5A);
    }
    return out;
  }

  /** Constant-time canary verification. */
  static verify(dataWithCanary: Uint8Array, expectedCanary: Uint8Array): boolean {
    const len = dataWithCanary.length;
    if (len < this.C.CANARY_TOTAL_OVERHEAD) return false;

    const canaryStart = len - this.C.CANARY_TOTAL_OVERHEAD;
    let diff = 0;
    for (let i = 0; i < this.C.CANARY_LENGTH; i++) {
      diff |= dataWithCanary[canaryStart + i] ^ expectedCanary[i];
    }
    return diff === 0;
  }

  /** Strip canary and padding, returning original data slice. */
  static strip(dataWithCanary: Uint8Array): Uint8Array {
    const origLen = dataWithCanary.length - this.C.CANARY_TOTAL_OVERHEAD;
    const result  = new Uint8Array(origLen);
    result.set(dataWithCanary.subarray(0, origLen));
    return result;
  }
}
