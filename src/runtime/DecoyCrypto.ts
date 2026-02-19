import { NativeModules } from 'react-native';

const { NativeCrypto } = NativeModules;

/**
 * DecoyCrypto — real cryptographic noise injection.
 *
 * Executes genuine AES-256-GCM operations on randomly generated data.
 * Results are immediately discarded. Indistinguishable from real
 * fragment decryption at the API tracing level (Frida hooks on
 * aesGCMEncrypt/aesGCMDecrypt will see identical call signatures).
 *
 * Call DecoyCrypto.run(N) before and after every real crypto operation.
 * Call DecoyCrypto.runSync() inside tight loops where async is impractical.
 */
export class DecoyCrypto {

  /** Fire N async AES operations on random data. Returns immediately (fire-and-forget). */
  static run(count: number = 3): Promise<void> {
    const ops: Promise<void>[] = [];
    for (let i = 0; i < count; i++) ops.push(this._oneOp());
    return Promise.allSettled(ops).then(() => {});
  }

  /** Synchronous CPU-bound decoy — simulates key schedule + 4 rounds. */
  static runSync(): void {
    const SZ  = 48 + Math.floor(Math.random() * 112); // 48–160 bytes
    const buf = new Uint8Array(SZ);
    for (let i = 0; i < SZ; i++) buf[i] = (Math.random() * 256) | 0;

    // Simulate AES SubBytes + ShiftRows-like ops
    for (let r = 0; r < 4; r++) {
      for (let i = 0; i < SZ; i++) {
        buf[i] = (buf[i] ^ buf[(i + 13) % SZ] ^ buf[(i + 7) % SZ]) & 0xFF;
        buf[i] = ((buf[i] << 1) | (buf[i] >>> 7)) & 0xFF; // rotate-left-1
      }
    }
    void buf[0]; // prevent elimination
  }

  private static async _oneOp(): Promise<void> {
    try {
      const keyB64:  string = await NativeCrypto.randomBytes(32);
      const dataB64: string = await NativeCrypto.randomBytes(
        64 + Math.floor(Math.random() * 192)
      );
      const enc: string = await NativeCrypto.aesGCMEncrypt(keyB64, dataB64, null);
      void enc; // discard
    } catch { /* silently absorb */ }
  }
}
