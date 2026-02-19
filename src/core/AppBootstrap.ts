import { SecurityOrchestrator } from './SecurityOrchestrator';
import { LifecycleManager }     from './LifecycleManager';
import { RootKeyService }       from '../security/RootKeyService';
import { SecureFileStorage }    from '../storage/SecureFileStorage';
import { RuntimeEntropy }       from '../runtime/RuntimeEntropy';

/**
 * AppBootstrap — deterministic, ordered initialization sequence.
 *
 * Order is critical:
 *   1. SecurityOrchestrator.run()  — MUST pass before anything else runs
 *   2. RootKeyService.initDeviceSalt() — idempotent first-launch setup
 *   3. SecureFileStorage.initialize()  — create vault dirs + .nomedia
 *   4. RuntimeEntropy.initialize()     — generate session memorySalt
 *   5. LifecycleManager.initialize()   — begin AppState monitoring
 */
export class AppBootstrap {
  private static _done = false;

  static async initialize(userId: string): Promise<void> {
    if (this._done) return;

    // Step 1 — security gate (throws on violation, kills process)
    await SecurityOrchestrator.run();

    // Step 2 — idempotent salt init
    await RootKeyService.initDeviceSalt(userId);

    // Step 3 — storage directories
    await SecureFileStorage.initialize();

    // Step 4 — session entropy
    await RuntimeEntropy.initialize();

    // Step 5 — lifecycle hooks
    LifecycleManager.initialize();

    this._done = true;
  }

  static teardown(): void {
    LifecycleManager.teardown();
    RuntimeEntropy.wipe();
    this._done = false;
  }
}
