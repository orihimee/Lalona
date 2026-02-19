import { SECURITY_CONSTANTS } from './constants';

/**
 * FridaDetector — multi-vector Frida instrumentation detection.
 *
 * Vectors:
 *   1. Global namespace pollution
 *   2. Function prototype tampering
 *   3. Native function [native code] string check
 *   4. Variance-based timing anomaly (Frida adds instrumentation overhead)
 */
export class FridaDetector {
  private static _lastCheck = 0;
  private static readonly THROTTLE_MS = 8_000;

  static async detect(): Promise<boolean> {
    const now = Date.now();
    if (now - this._lastCheck < this.THROTTLE_MS) return false;
    this._lastCheck = now;

    return (
      this._checkGlobals()        ||
      this._checkPrototypes()     ||
      this._checkNativeStrings()  ||
      this._checkTimingVariance()
    );
  }

  private static _checkGlobals(): boolean {
    const FRIDA_GLOBALS = [
      '_frida_agent_main', '__frida', 'Interceptor',
      'Stalker', 'NativeFunction', 'NativeCallback',
      'Memory', 'Script', 'Java', 'ObjC', 'recv', 'send', 'rpc',
    ];
    return FRIDA_GLOBALS.some(g => (globalThis as any)[g] !== undefined);
  }

  private static _checkPrototypes(): boolean {
    try {
      // Object prototype should be the real one
      if (Object.getPrototypeOf({}) !== Object.prototype)      return true;
      if (Object.getPrototypeOf([]) !== Array.prototype)       return true;
      if (Object.getPrototypeOf(() => {}) !== Function.prototype) return true;
    } catch { return true; }
    return false;
  }

  private static _checkNativeStrings(): boolean {
    // Native built-ins must report [native code]
    const CHECKS = [JSON.parse, JSON.stringify, parseInt, parseFloat, Math.random];
    return CHECKS.some(fn => !Function.prototype.toString.call(fn).includes('[native code]'));
  }

  private static _checkTimingVariance(): boolean {
    const N = 8, K = 500;
    const ts: number[] = [];

    for (let o = 0; o < N; o++) {
      const t0 = performance.now();
      let s = 0;
      for (let i = 0; i < K; i++) s ^= (i * 31337) & 0xFFFF;
      void s;
      ts.push(performance.now() - t0);
    }

    const mean = ts.reduce((a, b) => a + b, 0) / N;
    const variance = ts.reduce((acc, t) => acc + (t - mean) ** 2, 0) / N;

    // Frida's instrumentation introduces high variance even under JIT
    return variance > 5 && mean > 2;
  }
}
