// Prettier configuration following Airbnb Style Guide principles
module.exports = {
  // Line length that triggers wrapping
  printWidth: 80,

  // Tabs vs spaces - using spaces for consistency across languages
  useTabs: false,
  tabWidth: 2,

  // Trailing commas help with git diffs and are supported in ES5+
  trailingComma: 'es5',

  // Single quotes are more common in JavaScript ecosystem
  singleQuote: true,

  // Quote props only when needed for cleaner code
  quoteProps: 'as-needed',

  // Semicolons prevent ASI issues
  semi: true,

  // Bracket spacing for readability
  bracketSpacing: true,

  // JSX specific settings
  jsxSingleQuote: true,
  bracketSameLine: false,

  // Arrow function parentheses - avoid when possible
  arrowParens: 'avoid',

  // Prose wrap for markdown files
  proseWrap: 'preserve',

  // HTML settings
  htmlWhitespaceSensitivity: 'css',

  // End of line normalization
  endOfLine: 'lf',

  // Embedded language formatting
  embeddedLanguageFormatting: 'auto',

  // Single attribute per line in JSX when it exceeds print width
  singleAttributePerLine: false,

  // Override settings for specific file types
  overrides: [
    {
      files: ['*.json', '.eslintrc', '.prettierrc'],
      options: {
        parser: 'json',
        tabWidth: 2,
      },
    },
    {
      files: '*.md',
      options: {
        parser: 'markdown',
        proseWrap: 'always',
        printWidth: 100,
      },
    },
    {
      files: '*.yaml',
      options: {
        parser: 'yaml',
        tabWidth: 2,
      },
    },
    {
      files: '*.yml',
      options: {
        parser: 'yaml',
        tabWidth: 2,
      },
    },
  ],
};