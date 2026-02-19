/**
 * Centralized security constants.
 * All magic numbers live here — never inline in business logic.
 */

export const CRYPTO_CONSTANTS = {
  // ── PBKDF2 ──────────────────────────────────────────────────────────────
  PBKDF2_ITERATIONS:   310_000,
  PBKDF2_KEY_LENGTH:   64,   // 512 bits — root secret
  PBKDF2_HASH:         'SHA-512',

  // ── AES-256-GCM ──────────────────────────────────────────────────────────
  AES_KEY_LENGTH:   32,  // 256 bits
  AES_IV_LENGTH:    12,  // 96-bit nonce
  AES_TAG_LENGTH:   16,  // 128-bit auth tag

  // ── HMAC ─────────────────────────────────────────────────────────────────
  HMAC_LENGTH:      32,  // SHA-256 output

  // ── Fragment sizing ───────────────────────────────────────────────────────
  FRAGMENT_MIN_SIZE:   51_200,   // 50 KB
  FRAGMENT_MAX_SIZE:   204_800,  // 200 KB

  // ── Runtime security ─────────────────────────────────────────────────────
  MAX_DECRYPTED_FRAGMENTS: 2,

  // ── Canary ───────────────────────────────────────────────────────────────
  CANARY_LENGTH:            16,
  CANARY_TRAILING_PAD:      16,  // Total appended = CANARY_LENGTH + TRAILING_PAD = 32
  get CANARY_TOTAL_OVERHEAD() { return this.CANARY_LENGTH + this.CANARY_TRAILING_PAD; },

  // ── Key rotation ─────────────────────────────────────────────────────────
  KEY_ROTATION_INTERVAL_MS: 7 * 24 * 60 * 60 * 1_000, // 7 days

  // ── SecureStore keys ─────────────────────────────────────────────────────
  SECURE_STORE_DEVICE_SALT:   'ls_dsalt_v1',
  SECURE_STORE_USER_ID:       'ls_uid_v1',
  SECURE_STORE_ROTATION_TS:   'ls_rts_v1',
} as const;

export const HKDF_INFO_LABELS = {
  CHAPTER_ROOT:      'chapter-root',
  RUNTIME_EPHEMERAL: 'runtime-ephemeral',
  CANARY_DERIVE:     'canary-derive',
  HMAC_KEY:          'hmac-key',
  METADATA_KEY:      'metadata-key',
  FRAGMENT_MAP:      'fragment-map',
  KEY_WRAP:          'chapter-key-wrap',
} as const;

export const STORAGE_CONSTANTS = {
  ROOT_DIR:              '.ls_v',      // Short, obscure name
  META_DIR:              '.ls_m',
  NOMEDIA_FILE:          '.nomedia',
  FRAGMENT_EXT:          '.dat',
  METADATA_EXT:          '.meta',
  WRAPPED_KEY_EXT:       '.wk',
  CHAPTER_META_EXT:      '.cm',
  MAX_FRAGS_PER_CHAPTER: 512,
} as const;

export const SECURITY_CONSTANTS = {
  WIPE_PASSES: 3,

  // Timing anomaly threshold (ms)
  DEBUG_TIMING_THRESHOLD_MS: 500,

  // Frida default server port
  FRIDA_PORT: 27042,

  KNOWN_ROOT_PATHS: [
    '/system/app/Superuser.apk',
    '/sbin/su',
    '/system/bin/su',
    '/system/xbin/su',
    '/data/local/xbin/su',
    '/data/local/bin/su',
    '/system/sd/xbin/su',
    '/system/bin/failsafe/su',
    '/data/local/su',
    '/su/bin/su',
    '/system/usr/we-need-root/su-backup',
    '/data/adb/su',
  ] as const,

  KNOWN_EMULATOR_PATHS: [
    '/system/lib/libc_malloc_debug_qemu.so',
    '/sys/qemu_trace',
    '/system/bin/qemu-props',
    '/dev/socket/qemud',
    '/dev/qemu_pipe',
    '/system/lib/libdvm.so',
  ] as const,

  FRIDA_ARTIFACTS: [
    'frida',
    'gum-js-loop',
    'gmain',
    're.frida',
    'linjector',
  ] as const,
} as const;
