import * as FileSystem  from 'expo-file-system';
import { Platform }     from 'react-native';
import { SECURITY_CONSTANTS } from './constants';

export interface IntegrityReport {
  passed:            boolean;
  rootDetected:      boolean;
  emulatorDetected:  boolean;
  debugDetected:     boolean;
  signatureMismatch: boolean;
  reason?:           string;
}

/**
 * IntegrityGuard performs static and behavioral integrity checks.
 * Called exclusively by SecurityOrchestrator at boot.
 * On any failure → SecurityOrchestrator.handleViolation() is invoked.
 */
export class IntegrityGuard {
  static async runAllChecks(): Promise<IntegrityReport> {
    const [root, emu, dbg] = await Promise.all([
      this._checkRoot(),
      this._checkEmulator(),
      this._checkDebugger(),
    ]);
    const sig = await this._checkSignature();

    const passed = !root && !emu && !dbg && !sig;
    const reasons: string[] = [];
    if (root) reasons.push('root');
    if (emu)  reasons.push('emulator');
    if (dbg)  reasons.push('debug-timing');
    if (sig)  reasons.push('signature');

    return {
      passed,
      rootDetected:      root,
      emulatorDetected:  emu,
      debugDetected:     dbg,
      signatureMismatch: sig,
      reason:            reasons.length ? reasons.join(',') : undefined,
    };
  }

  private static async _checkRoot(): Promise<boolean> {
    if (Platform.OS !== 'android') return false;
    for (const path of SECURITY_CONSTANTS.KNOWN_ROOT_PATHS) {
      try {
        const info = await FileSystem.getInfoAsync(`file://${path}`);
        if (info.exists) return true;
      } catch { /* expected on unrooted devices */ }
    }
    // Probe system partition write access
    try {
      const probe = `file:///system/__ls_probe_${Date.now()}`;
      await FileSystem.writeAsStringAsync(probe, 'x');
      await FileSystem.deleteAsync(probe, { idempotent: true });
      return true; // System is writable = rooted
    } catch { return false; }
  }

  private static async _checkEmulator(): Promise<boolean> {
    if (Platform.OS !== 'android') return false;
    for (const path of SECURITY_CONSTANTS.KNOWN_EMULATOR_PATHS) {
      try {
        const info = await FileSystem.getInfoAsync(`file://${path}`);
        if (info.exists) return true;
      } catch { }
    }
    return false;
  }

  /** Detect debugger via computation timing anomaly. */
  private static async _checkDebugger(): Promise<boolean> {
    const start = performance.now();
    let sink = 0;
    for (let i = 0; i < 5_000; i++) sink += Math.imul(i, 0xDEAD) ^ Math.imul(i, 0xBEEF);
    void sink;
    return (performance.now() - start) > SECURITY_CONSTANTS.DEBUG_TIMING_THRESHOLD_MS;
  }

  private static async _checkSignature(): Promise<boolean> {
    // On Android, the APK signing certificate is verified by the OS at install.
    // Additional verification would compare against a hardcoded signing key hash
    // embedded at build time. For this implementation the check is a placeholder
    // that always passes — integrate with your certificate fingerprint in production.
    return false;
  }
}
