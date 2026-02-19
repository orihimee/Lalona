import { NativeModules } from 'react-native';
import { SecureFileStorage }    from './SecureFileStorage';
import { FragmentManifest }     from '../security/FragmentEngine';
import { SecureBuffer }         from '../security/RootKeyService';
import { WrappedChapterKey }    from '../security/KeyRotationService';

const { NativeCrypto } = NativeModules;

/**
 * MetadataStore — encrypted metadata persistence.
 *
 * All values are serialized to JSON, then AES-256-GCM encrypted with
 * the appropriate derived key before writing to disk.
 * Nothing in MetadataStore is ever written as plaintext.
 */
export class MetadataStore {

  // ── Fragment manifests ────────────────────────────────────────────────────

  async storeManifest(
    imageId:       string,
    manifest:      FragmentManifest,
    fragmentMapKey: SecureBuffer
  ): Promise<void> {
    const ptB64  = Buffer.from(JSON.stringify(manifest)).toString('base64');
    const keyB64 = Buffer.from(fragmentMapKey).toString('base64');
    const encB64: string = await NativeCrypto.aesGCMEncrypt(keyB64, ptB64, null);
    await SecureFileStorage.writeMeta(`meta:${imageId}`, encB64);
  }

  async loadManifest(
    imageId:       string,
    fragmentMapKey: SecureBuffer
  ): Promise<FragmentManifest> {
    const encB64 = await SecureFileStorage.readMeta(`meta:${imageId}`);
    if (!encB64) throw new Error(`No manifest stored for ${imageId}`);

    const keyB64  = Buffer.from(fragmentMapKey).toString('base64');
    const ptB64:  string = await NativeCrypto.aesGCMDecrypt(keyB64, encB64, null);
    if (!ptB64) throw new Error(`Manifest decryption failed for ${imageId}`);

    return JSON.parse(Buffer.from(ptB64, 'base64').toString('utf8')) as FragmentManifest;
  }

  // ── Wrapped chapter keys ──────────────────────────────────────────────────

  async storeWrappedKey(chapterId: string, wk: WrappedChapterKey): Promise<void> {
    await SecureFileStorage.writeMeta(`wk:${chapterId}`, JSON.stringify(wk));
  }

  async loadWrappedKey(chapterId: string): Promise<WrappedChapterKey | null> {
    const raw = await SecureFileStorage.readMeta(`wk:${chapterId}`);
    return raw ? (JSON.parse(raw) as WrappedChapterKey) : null;
  }

  // ── Chapter metadata ──────────────────────────────────────────────────────

  async storeChapterMeta(
    chapterId:   string,
    meta:        Record<string, unknown>,
    metadataKey: SecureBuffer
  ): Promise<void> {
    const ptB64  = Buffer.from(JSON.stringify(meta)).toString('base64');
    const keyB64 = Buffer.from(metadataKey).toString('base64');
    const encB64: string = await NativeCrypto.aesGCMEncrypt(keyB64, ptB64, null);
    await SecureFileStorage.writeMeta(`cm:${chapterId}`, encB64);
  }

  async loadChapterMeta(
    chapterId:   string,
    metadataKey: SecureBuffer
  ): Promise<Record<string, unknown> | null> {
    const encB64 = await SecureFileStorage.readMeta(`cm:${chapterId}`);
    if (!encB64) return null;

    const keyB64 = Buffer.from(metadataKey).toString('base64');
    const ptB64: string = await NativeCrypto.aesGCMDecrypt(keyB64, encB64, null);
    if (!ptB64) return null;

    return JSON.parse(Buffer.from(ptB64, 'base64').toString('utf8'));
  }
}
