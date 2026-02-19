import { IntegrityGuard }        from '../security/IntegrityGuard';
import { FridaDetector }         from '../security/FridaDetector';
import { RootKeyService }        from '../security/RootKeyService';
import { EphemeralKeyService }   from '../security/EphemeralKeyService';
import { RuntimeEntropy }        from '../runtime/RuntimeEntropy';

/**
 * SecurityOrchestrator — central gate for all security enforcement.
 *
 * Boot sequence:
 *   1. IntegrityGuard.runAllChecks()   ← root / emulator / debug
 *   2. FridaDetector.detect()          ← instrumentation
 *   On any failure → handleViolation() → destroy salt → wipe memory → crash
 *
 * Periodic:
 *   SecurityOrchestrator.periodicCheck() should be called on every screen mount.
 */
export class SecurityOrchestrator {
  private static _violationInProgress = false;

  static async run(): Promise<void> {
    // Run all checks concurrently
    const [report, fridaDetected] = await Promise.all([
      IntegrityGuard.runAllChecks(),
      FridaDetector.detect(),
    ]);

    if (!report.passed) {
      await this.handleViolation(`integrity:${report.reason}`);
    }
    if (fridaDetected) {
      await this.handleViolation('frida:detected-at-boot');
    }
  }

  static async periodicCheck(): Promise<void> {
    if (await FridaDetector.detect()) {
      await this.handleViolation('frida:detected-during-use');
    }
  }

  /**
   * Security violation handler.
   *
   * Steps (executed even if individual steps fail):
   *   1. Destroy device salt        → all encrypted data permanently inaccessible
   *   2. Wipe ephemeral key material
   *   3. Throw unhandled error      → process crash
   *
   * This function never returns normally.
   */
  static async handleViolation(reason: string): Promise<never> {
    if (this._violationInProgress) throw new Error('SECURITY_VIOLATION');
    this._violationInProgress = true;

    await Promise.allSettled([
      RootKeyService.destroyDeviceSalt(),
    ]);

    EphemeralKeyService.wipeMemorySalt();
    RuntimeEntropy.wipe();

    // Throw unhandled — crashes the JS runtime, which triggers React Native's
    // crash handler and kills the process cleanly.
    throw new Error(`SECURITY_VIOLATION:${reason}:${Date.now()}`);
  }

  static async onBackground(): Promise<void> {
    EphemeralKeyService.wipeMemorySalt();
    RuntimeEntropy.wipe();
  }
}
