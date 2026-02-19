const { getDefaultConfig } = require('expo/metro-config');

const config = getDefaultConfig(__dirname);

// Production: aggressive minification, no source maps
if (process.env.NODE_ENV === 'production') {
  config.transformer.minifierConfig = {
    keep_classnames: false,
    keep_fnames: false,
    mangle: { toplevel: true },
    compress: {
      drop_console: true,
      drop_debugger: true,
      passes: 3,
      pure_funcs: ['console.log', 'console.warn', 'console.info', 'console.debug'],
    },
  };
  // Disable source map output
  config.serializer.sourceMapUrl = undefined;
  config.serializer.generateSourceMaps = false;
}

// Block asset types that could contain plaintext content
config.resolver.blockList = [/.*\.map$/, /.*\.log$/];

module.exports = config;
