import * as FileSystem from 'expo-file-system';
import * as Crypto     from 'expo-crypto';
import { STORAGE_CONSTANTS } from '../security/constants';

const VAULT_ROOT = `${FileSystem.documentDirectory}${STORAGE_CONSTANTS.ROOT_DIR}/`;
const META_ROOT  = `${FileSystem.documentDirectory}${STORAGE_CONSTANTS.META_DIR}/`;

/**
 * SecureFileStorage — raw file I/O on the encrypted vault.
 *
 * Layout:
 *   .ls_v/                   ← vault root
 *     .nomedia               ← inhibits Android media scanner
 *     <sha256(chapterId)>/   ← per-chapter directory (no clear name)
 *       .nomedia
 *       <sha256(chapterId+fragIdx+salt)>.dat   ← encrypted fragments
 *
 *   .ls_m/                   ← metadata root (separate from vault)
 *     <sha256("meta:"+imageId)>.meta
 *     <sha256("wk:"+chapterId)>.wk
 *     <sha256("cm:"+chapterId)>.cm
 */
export class SecureFileStorage {

  static async initialize(): Promise<void> {
    await this._ensureDir(VAULT_ROOT);
    await this._ensureDir(META_ROOT);
    await this._ensureNomedia(VAULT_ROOT);
    await this._ensureNomedia(META_ROOT);
  }

  // ── Chapter directories ───────────────────────────────────────────────────

  static async getChapterDir(chapterId: string): Promise<string> {
    const hash = await this._sha256(`dir:${chapterId}`);
    return `${VAULT_ROOT}${hash}/`;
  }

  static async initChapterDir(chapterId: string): Promise<string> {
    const dir = await this.getChapterDir(chapterId);
    await this._ensureDir(dir);
    await this._ensureNomedia(dir);
    return dir;
  }

  // ── Fragment I/O ──────────────────────────────────────────────────────────

  static async fragmentFilename(
    chapterId:     string,
    fragmentIndex: number,
    salt:          string
  ): Promise<string> {
    const hash = await this._sha256(`${chapterId}:${fragmentIndex}:${salt}`);
    return `${hash}${STORAGE_CONSTANTS.FRAGMENT_EXT}`;
  }

  static async writeFragment(
    chapterId: string,
    filename:  string,
    dataB64:   string  // Base64 encoded IV||CT||Tag
  ): Promise<void> {
    const dir = await this.initChapterDir(chapterId);
    await FileSystem.writeAsStringAsync(`${dir}${filename}`, dataB64, {
      encoding: FileSystem.EncodingType.UTF8,
    });
  }

  static async readFragment(
    chapterId: string,
    filename:  string
  ): Promise<string> {
    const dir = await this.getChapterDir(chapterId);
    return FileSystem.readAsStringAsync(`${dir}${filename}`, {
      encoding: FileSystem.EncodingType.UTF8,
    });
  }

  // ── Metadata I/O ──────────────────────────────────────────────────────────

  static async writeMeta(key: string, value: string): Promise<void> {
    const hash = await this._sha256(key);
    await FileSystem.writeAsStringAsync(`${META_ROOT}${hash}`, value, {
      encoding: FileSystem.EncodingType.UTF8,
    });
  }

  static async readMeta(key: string): Promise<string | null> {
    const hash     = await this._sha256(key);
    const filepath = `${META_ROOT}${hash}`;
    const info     = await FileSystem.getInfoAsync(filepath);
    if (!info.exists) return null;
    return FileSystem.readAsStringAsync(filepath, { encoding: FileSystem.EncodingType.UTF8 });
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  static async chapterExists(chapterId: string): Promise<boolean> {
    const dir  = await this.getChapterDir(chapterId);
    const info = await FileSystem.getInfoAsync(dir);
    return info.exists;
  }

  static async deleteChapter(chapterId: string): Promise<void> {
    const dir = await this.getChapterDir(chapterId);
    await FileSystem.deleteAsync(dir, { idempotent: true });
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  private static async _ensureDir(path: string): Promise<void> {
    const info = await FileSystem.getInfoAsync(path);
    if (!info.exists) await FileSystem.makeDirectoryAsync(path, { intermediates: true });
  }

  private static async _ensureNomedia(dir: string): Promise<void> {
    const p    = `${dir}${STORAGE_CONSTANTS.NOMEDIA_FILE}`;
    const info = await FileSystem.getInfoAsync(p);
    if (!info.exists) await FileSystem.writeAsStringAsync(p, '');
  }

  private static async _sha256(input: string): Promise<string> {
    return Crypto.digestStringAsync(
      Crypto.CryptoDigestAlgorithm.SHA256,
      input,
      { encoding: Crypto.CryptoEncoding.HEX }
    );
  }
}
