import { SECURITY_CONSTANTS } from './constants';

/**
 * MemoryWiper — best-effort secure buffer erasure.
 *
 * JavaScript's GC and string immutability mean we cannot guarantee
 * true memory erasure. This module overwrites buffer contents with
 * multiple passes before releasing references, minimizing the window
 * during which sensitive data appears in the heap.
 *
 * Note: The JNI layer uses explicit_bzero (via secure_wipe()) which
 * cannot be optimized away. JS-side wiping is defense-in-depth.
 */
export class MemoryWiper {
  private static readonly PASSES = SECURITY_CONSTANTS.WIPE_PASSES;

  /** Multi-pass overwrite: zeros → ones → random → final zero. */
  static wipeUint8Array(buf: Uint8Array | null | undefined): void {
    if (!buf || buf.length === 0) return;

    for (let pass = 0; pass < this.PASSES; pass++) {
      switch (pass % 3) {
        case 0: buf.fill(0x00); break;
        case 1: buf.fill(0xFF); break;
        case 2:
          for (let i = 0; i < buf.length; i++) buf[i] = (Math.random() * 256) | 0;
          break;
      }
    }
    buf.fill(0x00); // Final authoritative zero pass
  }

  /** Wipe a set of Uint8Arrays and clear the collection. */
  static wipeAll(bufs: Map<unknown, Uint8Array> | Set<Uint8Array>): void {
    if (bufs instanceof Map) {
      for (const buf of bufs.values()) this.wipeUint8Array(buf);
      bufs.clear();
    } else {
      for (const buf of bufs) this.wipeUint8Array(buf);
      bufs.clear();
    }
  }

  /** Null-safe wipe of named fields on an object. */
  static wipeFields<T extends object>(obj: T, fields: (keyof T)[]): void {
    for (const f of fields) {
      const v = obj[f];
      if (v instanceof Uint8Array) this.wipeUint8Array(v);
      (obj as any)[f] = null;
    }
  }

  /**
   * Schedule a deferred wipe — for buffers that must survive one render cycle.
   * Returns a cancel function.
   */
  static deferredWipe(buf: Uint8Array, delayMs = 150): () => void {
    const timer = setTimeout(() => this.wipeUint8Array(buf), delayMs);
    return () => clearTimeout(timer);
  }
}
