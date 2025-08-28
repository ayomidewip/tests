# App Base Test Suite

A comprehensive test suite for the App Base server with consolidated resource management.

## Overview

This test suite provides a **consolidated resource management system** that eliminates duplication and ensures all test resources (server, database, Redis, users, tokens) are properly managed through a single interface.

## Key Features

- **Single Resource Manager**: All test resources managed through `TestResourceManager`
- **No Resource Duplication**: Uses server's existing Redis, database, and email services
- **Automatic Cleanup**: Proper resource cleanup after test completion
- **User Management**: Pre-created users with different roles and tokens
- **Database Isolation**: Clean database state for each test
- **Cache Management**: Direct access to server's cache instance

## Quick Start

### Basic Test Setup

```javascript
const { TestResourceManager } = require('../utils/test-resource-manager');

describe('My Test Suite', () => {
    let testResources;

    beforeAll(async () => {
        const manager = new TestResourceManager();
        testResources = await manager.initialize({
            userTypes: ['USER', 'ADMIN', 'OWNER'],
            defaultAuth: 'admin'
        });
    });

    afterAll(async () => {
        if (testResources?.server) {
            await testResources.server.instance.stop();
        }
    });

    beforeEach(async () => {
        await testResources.resetDatabase();
    });

    test('should work', async () => {
        const response = await testResources.apiClient.get('/health');
        expect(response.status).toBe(200);
    });
});
```

### Quick Setup for Simple Tests

```javascript
const { TestResourceManager } = require('../utils/test-resource-manager');

describe('Simple Test', () => {
    let testResources;

    beforeAll(async () => {
        const manager = await TestResourceManager.quickSetup('minimal');
        testResources = manager.getResources();
    });

    afterAll(async () => {
        if (testResources?.server) {
            await testResources.server.instance.stop();
        }
    });

    // Tests here...
});
```

## Available Resources

The `TestResourceManager` provides access to:

### Core Resources
- `server`: Complete server instance
- `apiClient`: Pre-configured HTTP client
- `users`: Pre-created users with tokens
- `baseUrl`: Server base URL
- `port`: Server port

### Server Resources (No Duplication!)
- `redisClient`: Server's Redis client
- `dbConnection`: Server's database connection  
- `emailService`: Server's email service

### Helper Methods
- `loginAs(userType)`: Switch authentication
- `clearAuth()`: Remove authentication
- `resetDatabase()`: Clean database and recreate users
- `createTestUser(type, overrides)`: Create new test user
- `getCache()`: Access server's cache instance
- `clearCache()`: Clear server's cache
- `isRedisConnected()`: Check Redis status
- `isEmailReady()`: Check email service status

## Configuration Options

### Initialize Options

```javascript
await manager.initialize({
    userTypes: ['USER', 'ADMIN', 'OWNER', 'CREATOR'], // User types to create
    defaultAuth: 'admin', // Default authentication (or false for none)
    server: { /* server options */ } // Server configuration
});
```

### Quick Setup Scenarios

- `'default'`: USER, ADMIN, OWNER with admin auth
- `'minimal'`: USER only with user auth
- `'full'`: All user types with admin auth
- `'noAuth'`: USER, ADMIN with no default auth

## Best Practices

### 1. Use Resource Manager for All Tests
```javascript
// ✅ Good - Uses consolidated resources
const { TestResourceManager } = require('../utils/test-resource-manager');

// ❌ Bad - Creates duplicate resources
const { startTestServer } = require('../utils/test.utils');
const { createRedisMock } = require('../utils/redis.mock');
```

### 2. Proper Cleanup
```javascript
afterAll(async () => {
    // ✅ Good - Cleans up ALL resources
    if (testResources?.server) {
        await testResources.server.instance.stop();
    }
});
```

### 3. Database Isolation
```javascript
beforeEach(async () => {
    // ✅ Good - Ensures clean state
    await testResources.resetDatabase();
});
```

### 4. User Management
```javascript
// ✅ Good - Use pre-created users
await testResources.loginAs('admin');

// ✅ Good - Create custom users when needed
const customUser = await testResources.createTestUser('USER', {
    firstName: 'Custom'
});
```

### 5. Cache Operations
```javascript
// ✅ Good - Use server's cache (no duplication)
const cache = testResources.getCache();
await cache.set('key', 'value');

// ❌ Bad - Creates separate cache mock
const mockCache = createRedisMock();
```

## Migration from Legacy Tests

### Old Pattern (Creates Duplicates)
```javascript
// ❌ Old way - Multiple resource creation
const server = await startTestServer();
const apiClient = createApiClient(`http://localhost:${server.port}`);
const redisMock = createRedisMock();
const users = await createApprovedUsers(apiClient);
```

### New Pattern (Consolidated)
```javascript
// ✅ New way - Single resource manager
const manager = new TestResourceManager();
const { server, apiClient, users, redisClient } = await manager.initialize();
```

## Environment Variables

The test suite uses `.env.test` for configuration:

```bash
NODE_ENV=test
MONGODB_URI=mongodb+srv://...
PORT_RANGE_MIN=8380
PORT_RANGE_MAX=8389
CACHE_ENABLED=true
# ... other vars
```

## Running Tests

```bash
# All tests
npm test

# Specific test files
npm test example.test.js

# Watch mode
npm run test:watch

# Specific test suites
npm run test:server
npm run test:controllers
```

## Key Benefits

1. **No Resource Duplication**: Uses server's existing Redis, database connections
2. **Proper Cleanup**: All resources cleaned up automatically
3. **Faster Tests**: No need to create duplicate services
4. **Consistency**: All tests use same resource management pattern
5. **Easier Debugging**: Single source of truth for all resources
6. **Better Isolation**: Clean state guaranteed between tests