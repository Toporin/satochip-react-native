// Minimal stub of the react-native peer dependency for unit tests.
module.exports = {
  Platform: {
    OS: 'android',
    select: (spec) => spec.android ?? spec.default,
  },
};
