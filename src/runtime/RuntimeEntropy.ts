import { NativeModules } from 'react-native';
import { MemoryWiper }   from '../security/MemoryWiper';
import { EphemeralKeyService, RuntimeEntropyBundle } from '../security/EphemeralKeyService';

const { NativeCrypto } = NativeModules;

/**
 * RuntimeEntropy — session-scoped, dynamic entropy collection.
 *
 * Sources:
 *   - bootTime:       session start epoch (ms)
 *   - frameCounter:   monotonically increments each render call
 *   - scrollVelocity: last observed px/ms, provided by scroll handler
 *   - memorySalt:     16-byte CSPRNG salt, generated once per session
 *
 * These values feed EphemeralKeyService.deriveEphemeralKey() and ensure
 * the EphemeralKey changes with every render interaction.
 */
export class RuntimeEntropy {
  private static _bootTime       = 0;
  private static _frameCounter   = 0;
  private static _scrollVelocity = 0.0;
  private static _memorySalt: Uint8Array | null = null;

  static async initialize(): Promise<void> {
    this._bootTime     = Date.now();
    this._frameCounter = 0;
    const b64: string  = await NativeCrypto.randomBytes(16);
    if (this._memorySalt) MemoryWiper.wipeUint8Array(this._memorySalt);
    this._memorySalt   = new Uint8Array(Buffer.from(b64, 'base64'));
    // Mirror to EphemeralKeyService
    await EphemeralKeyService.getOrCreateMemorySalt();
  }

  static incrementFrameCounter(): void {
    this._frameCounter = (this._frameCounter + 1) >>> 0; // clamp to uint32
  }

  static updateScrollVelocity(velocityPxPerMs: number): void {
    this._scrollVelocity = velocityPxPerMs;
  }

  static async buildBundle(chunkIndex: number): Promise<RuntimeEntropyBundle> {
    if (!this._memorySalt) await this.initialize();
    return {
      bootTime:       this._bootTime,
      frameCounter:   this._frameCounter,
      scrollVelocity: this._scrollVelocity,
      chunkIndex,
      memorySalt:     new Uint8Array(this._memorySalt!), // copy — never expose reference
    };
  }

  static wipe(): void {
    if (this._memorySalt) {
      MemoryWiper.wipeUint8Array(this._memorySalt);
      this._memorySalt = null;
    }
    EphemeralKeyService.wipeMemorySalt();
    this._frameCounter   = 0;
    this._scrollVelocity = 0.0;
    this._bootTime       = 0;
  }
}
