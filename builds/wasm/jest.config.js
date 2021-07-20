// For a detailed explanation regarding each configuration property, visit:
// https://jestjs.io/docs/en/configuration.html

// suppress MaxListenersExceededWarning: Possible EventEmitter memory leak detected warning in tests
require('events').EventEmitter.defaultMaxListeners = 100;

module.exports = {
  // Automatically clear mock calls and instances between every test
  clearMocks: true,

  // The directory where Jest should output its coverage files
  coverageDirectory: 'coverage',

  coverageReporters: [
    'cobertura',
  ],

  collectCoverageFrom: [
    '**/*.ts',
  ],

  // use the patterns below to test only certain files
  testMatch: [
    '**/?(*.)+(spec|test).[jt]s?(x)',
    '**/__tests__/**/*.[jt]s?(x)',
  ],

  // The test environment that will be used for testing
  testEnvironment: 'node',

  // default + d.ts for typings
  moduleFileExtensions: ['js', 'json', 'jsx', 'ts', 'tsx', 'node', 'd.ts'],

  moduleNameMapper: {
    '@utils/(.*)': '<rootDir>/src/_utils/$1',
    '@/(.*)': '<rootDir>/src/$1',
  },

};
