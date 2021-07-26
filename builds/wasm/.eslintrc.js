module.exports = {
  extends: [
    'airbnb-typescript/base', // dropped a comment to modify the file
  ],
  env: {
    browser: false,
    'jest/globals': true,
  },
  parser: '@typescript-eslint/parser',
  parserOptions: {
    tsconfigRootDirs: [
      './',
      'src',
      'functions',
    ],
    project: './tsconfig.tslint.json',
  },
  plugins: [
    'import',
    '@typescript-eslint',
    'jest',
  ],
  settings: {
    'import/parsers': {
      '@typescript-eslint/parser': ['.ts', '.spec.ts'],
    },
    'import/resolver': {
      // see: https://github.com/alexgorbatchev/eslint-import-resolver-typescript#readme
      typescript: {
        // alwaysTryTypes: false,
        // project: '.',
      },
    },
  },
  rules: {
    '@typescript-eslint/space-infix-ops': 'off',
    '@typescript-eslint/object-curly-spacing': 'off',
    'no-shadow': 'off',
    '@typescript-eslint/no-shadow': ['error'],
    '@typescript-eslint/indent': ['error', 2],
    '@typescript-eslint/no-explicit-any': 'warn',
    '@typescript-eslint/camelcase': 'off', // not supported in ts-eslint v3, TODO: wait for update from airbnb eslint
    'no-param-reassign': ['error', { props: true, ignorePropertyModificationsFor: ['ctx', 'context'] }],
    'import/prefer-default-export': 'off',
    'import/no-unresolved': 'error',
    'max-len': [
      'warn', {
        code: 120,
        ignoreUrls: true,
        ignoreStrings: true,
        ignoreTemplateLiterals: true,
        // ignore single line return shorthands: (x) => {id: x}
        ignorePattern: '^.*?\(.*?\).=>.\(.*?\).*$', // eslint-disable-line
      },
    ],
    'no-underscore-dangle': ['error', {
      allow: ['_', '__'],
    }],
    'max-classes-per-file': 'off',
    'no-warning-comments': 'error',
  },
  overrides: [
    {
      files: ['src/db/models/*.ts'],
      rules: {
        'import/no-cycle': 'off',
      },
    },
    {
      files: ['src/apollo/graphql/*.ts'],
      rules: {
        'class-methods-use-this': 'off',
      },
    },
    {
      files: ['tests/**', '*.spec.ts', '*.apispec.ts'],
      rules: {
        '@typescript-eslint/no-explicit-any': 'off',
        'jest/no-disabled-tests': 'warn',
        'jest/no-focused-tests': 'error',
        'jest/no-identical-title': 'error',
        'jest/prefer-to-have-length': 'warn',
        'jest/valid-expect': 'error',
      },
    },
    {
      files: ['src/db/migration/**/*.ts'],
      rules: {
        '@typescript-eslint/camelcase': 'off',
        '@typescript-eslint/explicit-module-boundary-types': 'off',
        '@typescript-eslint/no-explicit-any': 'off',
        'class-methods-use-this': 'off',
        'default-case': 'off',
        'jest/no-disabled-tests': 'off',
        'consistent-return': 'off',
        'import/prefer-default-export': 'off',
        'array-callback-return': 'off',
        'no-param-reassign': 'off',
        'prefer-destructuring': 'off',
      },
    },
  ],
};
