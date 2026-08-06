const { getDefaultConfig } = require('expo/metro-config');
const path = require('path');

const config = getDefaultConfig(__dirname);
const repositoryRoot = path.resolve(__dirname, '../..');

config.watchFolders = [repositoryRoot];
config.resolver.nodeModulesPaths = [path.resolve(__dirname, 'node_modules')];

config.resolver.resolveRequest = (context, moduleName, platform) => {
  if (moduleName === 'crypto') {
    return {
      type: 'sourceFile',
      filePath: path.resolve(__dirname, 'shims/crypto.js'),
    };
  }

  return context.resolveRequest(context, moduleName, platform);
};

module.exports = config;
