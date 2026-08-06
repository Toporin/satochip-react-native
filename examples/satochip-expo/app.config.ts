import type { ConfigContext, ExpoConfig } from 'expo/config';

export default ({ config }: ConfigContext): ExpoConfig => {
  const appleTeamId = process.env.EXPO_APPLE_TEAM_ID?.trim();

  return {
    ...config,
    name: config.name ?? 'Satochip Expo',
    slug: config.slug ?? 'satochip-expo',
    ios: {
      ...config.ios,
      ...(appleTeamId ? { appleTeamId } : {}),
    },
  };
};
