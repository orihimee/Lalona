module.exports = function (api) {
  api.cache(true);
  return {
    presets: ['babel-preset-expo'],
    plugins: [
      // Strip console.* calls in production
      process.env.NODE_ENV === 'production' && [
        'transform-remove-console',
        { exclude: [] },
      ],
    ].filter(Boolean),
  };
};
