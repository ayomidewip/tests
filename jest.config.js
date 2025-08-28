module.exports = {
  // Test environment
  testEnvironment: 'node',
  
  // Automatically clear mock calls and instances between every test
  clearMocks: true,
  
  // Indicates whether the coverage information should be collected while executing the test
  collectCoverage: false,
  
  // An array of glob patterns indicating a set of files for which coverage information should be collected
  collectCoverageFrom: [
    '../server/**/*.js',
    '!../server/node_modules/**',
    '!../server/index.js',
    '!**/node_modules/**',
    '!**/coverage/**'
  ],
  
  // The directory where Jest should output its coverage files
  coverageDirectory: 'coverage',
  
  // Coverage reporters
  coverageReporters: [
    'text',
    'lcov',
    'html'
  ],
  
  // A list of reporter names that Jest uses when writing coverage reports
  coverageThreshold: {
    global: {
      branches: 50,
      functions: 50,
      lines: 50,
      statements: 50
    }
  },
  
  // Setup files after environment
  setupFilesAfterEnv: [
    // No setup files needed - using TestStartup class in individual tests
  ],
  
  // Test file patterns
  testMatch: [
    '**/__tests__/**/*.js',
    '**/*.test.js',
    '**/*.spec.js'
  ],

  // Ignore patterns for test files
  testPathIgnorePatterns: [
    '/node_modules/',
    '/coverage/',
    '/logs/'
  ],
  
  // Transform files with babel-jest
  transform: {
    '^.+\\.js$': 'babel-jest'
  },
  
  // Don't transform node_modules except for specific packages that need transformation
  transformIgnorePatterns: [
    'node_modules/(?!(axios|winston)/)'
  ],
  
  // Module file extensions
  moduleFileExtensions: [
    'js',
    'json',
    'node'
  ],
  
  // Test timeout (30 seconds)
  testTimeout: 30000,
  
  // Verbose output
  verbose: true,
  
  // Force exit after tests complete (handles hanging processes)
  forceExit: true,
  
  // Detect open handles (helps identify resource leaks)
  detectOpenHandles: true,
  
  // Maximum number of concurrent workers (use 1 to prevent resource conflicts)
  maxWorkers: 1,
  
  // Module name mapping for path resolution
  moduleNameMapper: {
    '^@server/(.*)$': '<rootDir>/../server/$1',
    '^@tests/(.*)$': '<rootDir>/$1',
    '^@utils/(.*)$': '<rootDir>/utils/$1'
  },
  
  // Roots - where Jest should scan for tests and modules
  roots: [
    '<rootDir>'
  ],
  
  // Reporter configuration
  reporters: ['default'],
  
  // Bail configuration - stop running tests after first test suite failure
  bail: false,
  
  // Cache directory
  cacheDirectory: '<rootDir>/.jest-cache',
  
  // Environment variables for tests
  setupFiles: [],
  
  // Global test configuration
  globals: {
    'NODE_ENV': 'test'
  }
};
