import * as Device      from 'expo-device';
import * as Application from 'expo-application';
import * as Crypto      from 'expo-crypto';
import { NativeModules } from 'react-native';

const { NativeCrypto } = NativeModules;

export interface DeviceFingerprint {
  raw:  string;
  hash: string;
}

/**
 * DeviceBinding derives a stable, hardware-rooted device fingerprint.
 *
 * The fingerprint is used as part of the PBKDF2 password:
 *   PBKDF2(password = fingerprintHash + userId, salt = deviceSalt)
 *
 * This binds all encrypted data to the specific (device, user, install)
 * tuple. Extracting storage to another device cannot decrypt data.
 */
export class DeviceBinding {
  private static _cached: string | null = null;

  static async getFingerprint(): Promise<DeviceFingerprint> {
    const raw = this._cached ?? await this._build();
    if (!this._cached) this._cached = raw;

    const hash = await Crypto.digestStringAsync(
      Crypto.CryptoDigestAlgorithm.SHA256,
      raw,
      { encoding: Crypto.CryptoEncoding.HEX }
    );
    return { raw, hash };
  }

  private static async _build(): Promise<string> {
    const parts: string[] = [];

    // Android ID — unique per (device, user, app-signing-key)
    if (Application.androidId)   parts.push(`aid:${Application.androidId}`);

    // Hardware descriptors
    if (Device.manufacturer)     parts.push(`mfr:${Device.manufacturer}`);
    if (Device.modelId)          parts.push(`mdl:${Device.modelId}`);
    if (Device.deviceName)       parts.push(`dvn:${Device.deviceName}`);
    if (Device.osVersion)        parts.push(`osv:${Device.osVersion}`);
    if (Device.totalMemory)      parts.push(`mem:${Device.totalMemory}`);
    if (Device.supportedCpuArchitectures)
                                 parts.push(`cpu:${Device.supportedCpuArchitectures.join('|')}`);

    // Installation time (stable on same device, resets on reinstall)
    try {
      const t = await Application.getInstallationTimeAsync();
      if (t)                     parts.push(`ins:${t.getTime()}`);
    } catch { /* not fatal */ }

    return parts.join('||');
  }

  static clearCache(): void {
    this._cached = null;
  }

  static async validate(storedFingerprintHash: string): Promise<boolean> {
    const current = await this.getFingerprint();
    return current.hash === storedFingerprintHash;
  }
}
