import { ExpoConfig, ConfigContext } from 'expo/config';

export default ({ config }: ConfigContext): ExpoConfig => ({
  ...config,
  name: 'Lalona',
  slug: 'lalona-secure',
  version: '1.0.0',
  orientation: 'portrait',
  scheme: 'lalona',
  platforms: ['android'],
  android: {
    package: 'com.lalona.secure',
    versionCode: 1,
    adaptiveIcon: {
      foregroundImage: './assets/adaptive-icon.png',
      backgroundColor: '#0a0a0a',
    },
    permissions: [],
    blockedPermissions: [
      'android.permission.READ_EXTERNAL_STORAGE',
      'android.permission.WRITE_EXTERNAL_STORAGE',
      'android.permission.READ_MEDIA_IMAGES',
    ],
  },
  plugins: [
    ['expo-secure-store'],
    ['expo-file-system'],
  ],
  extra: {
    eas: { projectId: 'replace-with-your-eas-project-id' },
  },
  updates: { enabled: false }, // No OTA updates — security-sensitive binary
  jsEngine: 'hermes',
});
