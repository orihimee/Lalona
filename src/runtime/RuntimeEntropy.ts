import * as Crypto from 'expo-crypto';
import { MemoryWiper } from '../security/MemoryWiper';
import { EphemeralKeyService, RuntimeEntropyBundle } from '../security/EphemeralKeyService';

export class RuntimeEntropy {
  private static _bootTime = 0;
  private static _frameCounter = 0;
  private static _scrollVelocity = 0.0;
  private static _memorySalt: Uint8Array | null = null;

  static async initialize(): Promise<void> {
    this._bootTime = Date.now();
    this._frameCounter = 0;

    const bytes = await Crypto.getRandomBytesAsync(16);

    if (this._memorySalt) {
      MemoryWiper.wipeUint8Array(this._memorySalt);
    }

    this._memorySalt = new Uint8Array(bytes);

    await EphemeralKeyService.getOrCreateMemorySalt();
  }

  static incrementFrameCounter(): void {
    this._frameCounter = (this._frameCounter + 1) >>> 0;
  }

  static updateScrollVelocity(velocityPxPerMs: number): void {
    this._scrollVelocity = velocityPxPerMs;
  }

  static async buildBundle(chunkIndex: number): Promise<RuntimeEntropyBundle> {
    if (!this._memorySalt) {
      await this.initialize();
    }

    return {
      bootTime: this._bootTime,
      frameCounter: this._frameCounter,
      scrollVelocity: this._scrollVelocity,
      chunkIndex,
      memorySalt: new Uint8Array(this._memorySalt!),
    };
  }

  static wipe(): void {
    if (this._memorySalt) {
      MemoryWiper.wipeUint8Array(this._memorySalt);
      this._memorySalt = null;
    }

    EphemeralKeyService.wipeMemorySalt();
    this._frameCounter = 0;
    this._scrollVelocity = 0.0;
    this._bootTime = 0;
  }
}