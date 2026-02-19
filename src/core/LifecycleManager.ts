import { AppState, AppStateStatus } from 'react-native';
import { SecurityOrchestrator }     from './SecurityOrchestrator';
import { EphemeralKeyService }      from '../security/EphemeralKeyService';
import { RuntimeEntropy }           from '../runtime/RuntimeEntropy';
import { MemoryWiper }              from '../security/MemoryWiper';

type WipeFn = () => void;

/**
 * LifecycleManager — AppState-driven secure cleanup.
 *
 * On background/inactive:
 *   1. Wipe all tracked Uint8Array buffers
 *   2. Execute all registered wipe callbacks
 *   3. Destroy session entropy (memorySalt, frameCounter, scrollVelocity)
 *
 * On active:
 *   1. Re-initialize session entropy (new memorySalt, reset counters)
 */
export class LifecycleManager {
  private static _sub:      ReturnType<typeof AppState.addEventListener> | null = null;
  private static _cbs:      Set<WipeFn>      = new Set();
  private static _buffers:  Set<Uint8Array>  = new Set();

  static initialize(): void {
    this._sub = AppState.addEventListener('change', this._onChange.bind(this));
  }

  static teardown(): void {
    this._sub?.remove();
    this._sub = null;
    this._cbs.clear();
    MemoryWiper.wipeAll(this._buffers);
  }

  static trackBuffer(buf: Uint8Array): void     { this._buffers.add(buf); }
  static untrackBuffer(buf: Uint8Array): void   { this._buffers.delete(buf); }

  /** Returns an unregister function. */
  static onBackground(cb: WipeFn): () => void {
    this._cbs.add(cb);
    return () => this._cbs.delete(cb);
  }

  private static async _onChange(next: AppStateStatus): Promise<void> {
    if (next === 'background' || next === 'inactive') {
      await this._secureWipe();
    } else if (next === 'active') {
      await RuntimeEntropy.initialize();
    }
  }

  private static async _secureWipe(): Promise<void> {
    // Wipe all tracked buffers
    MemoryWiper.wipeAll(this._buffers);

    // Fire registered callbacks (UI components clear their image states)
    for (const cb of this._cbs) {
      try { cb(); } catch { /* continue even on failure */ }
    }

    await SecurityOrchestrator.onBackground();
  }
}
