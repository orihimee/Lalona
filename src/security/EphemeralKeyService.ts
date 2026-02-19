import { NativeModules }          from 'react-native';
import { HKDF_INFO_LABELS }       from './constants';
import { MemoryWiper }            from './MemoryWiper';
import { SecureBuffer }           from './RootKeyService';

const { NativeCrypto } = NativeModules;

export interface RuntimeEntropyBundle {
  bootTime:       number;   // ms since epoch at session start
  frameCounter:   number;   // monotonically incrementing render counter
  scrollVelocity: number;   // pixels/ms, last observed
  chunkIndex:     number;   // fragment index being rendered
  memorySalt:     Uint8Array; // 16-byte random salt, session-scoped
}

/**
 * EphemeralKeyService — Level 2 key management.
 *
 * EphemeralKey = HKDF-SHA256(
 *   IKM  = ChapterRootKey,
 *   salt = serialized(runtimeEntropyBundle),
 *   info = "runtime-ephemeral",
 *   L    = 32
 * )
 *
 * ARCHITECTURE CONTRACT:
 *   - EphemeralKey ONLY drives DisplayMutation (XOR stream for in-memory rendering)
 *   - EphemeralKey NEVER touches any storage layer
 *   - Changes every render call due to frameCounter + scrollVelocity
 *   - Caller MUST wipe returned key with MemoryWiper.wipeUint8Array()
 */
export class EphemeralKeyService {
  private static _memorySalt: Uint8Array | null = null;
  private static readonly SALT_LEN = 16;
  private static readonly KEY_LEN  = 32;

  static async getOrCreateMemorySalt(): Promise<Uint8Array> {
    if (!this._memorySalt) {
      const b64: string = await NativeCrypto.randomBytes(this.SALT_LEN);
      this._memorySalt = new Uint8Array(Buffer.from(b64, 'base64'));
    }
    return new Uint8Array(this._memorySalt); // return copy, never expose reference
  }

  static wipeMemorySalt(): void {
    if (this._memorySalt) {
      MemoryWiper.wipeUint8Array(this._memorySalt);
      this._memorySalt = null;
    }
  }

  static async deriveEphemeralKey(
    chapterRootKey: SecureBuffer,
    entropy:        RuntimeEntropyBundle
  ): Promise<SecureBuffer> {
    // Serialize entropy bundle into a fixed-width binary blob
    const buf = Buffer.allocUnsafe(8 + 8 + 8 + 8 + entropy.memorySalt.length);
    let off = 0;
    buf.writeBigInt64LE(BigInt(entropy.bootTime),       off); off += 8;
    buf.writeBigInt64LE(BigInt(entropy.frameCounter),   off); off += 8;
    // scrollVelocity as micro-pixels/ms (3 decimal places via integer encoding)
    buf.writeBigInt64LE(BigInt(Math.round(entropy.scrollVelocity * 1000)), off); off += 8;
    buf.writeBigInt64LE(BigInt(entropy.chunkIndex),     off); off += 8;
    entropy.memorySalt.forEach((b, i) => { buf[off + i] = b; });

    const ikmB64  = Buffer.from(chapterRootKey).toString('base64');
    const saltB64 = buf.toString('base64');
    buf.fill(0); // wipe entropy serialization

    const b64: string = await NativeCrypto.hkdf(
      ikmB64, saltB64,
      HKDF_INFO_LABELS.RUNTIME_EPHEMERAL,
      this.KEY_LEN
    );

    return new Uint8Array(Buffer.from(b64, 'base64'));
  }

  static buildBundle(
    frameCounter:   number,
    scrollVelocity: number,
    chunkIndex:     number,
    bootTime:       number
  ): RuntimeEntropyBundle {
    const salt = this._memorySalt
      ? new Uint8Array(this._memorySalt)
      : new Uint8Array(this.SALT_LEN);
    return { bootTime, frameCounter, scrollVelocity, chunkIndex, memorySalt: salt };
  }
}
