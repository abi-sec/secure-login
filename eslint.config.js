'use strict';

const security = require('eslint-plugin-security');
const js = require('@eslint/js');

module.exports = [
  js.configs.recommended,
  security.configs.recommended,
  {
    files: ['src/**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: {
        require: 'readonly',
        module: 'readonly',
        exports: 'readonly',
        process: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        console: 'readonly',
        Buffer: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
      },
    },
    rules: {
      // Security plugin rules
      'security/detect-eval-with-expression':          'error',
      'security/detect-non-literal-regexp':            'warn',
      'security/detect-non-literal-require':           'warn',
      'security/detect-object-injection':              'warn',
      'security/detect-possible-timing-attacks':       'error',
      'security/detect-unsafe-regex':                  'error',
      'security/detect-child-process':                 'error',
      'security/detect-disable-mustache-escape':       'error',
      'security/detect-no-csrf-before-method-override':'error',
      'security/detect-pseudoRandomBytes':             'error',

      // Core ESLint rules
      'no-eval':         'error',
      'no-implied-eval': 'error',
      'no-new-func':     'error',
      'strict':          ['error', 'global'],
    },
  },
];