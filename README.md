# App Base Test Suite

Test suite for the App Base server using `TestStartup` for unified resource management. Built with **Vitest** for fast, parallel test execution.

## Running Tests

```bash
# All tests (runs in parallel)
npm test

# Watch mode (reruns tests on file changes)
npm run test:watch

# Tests with UI (browser-based test viewer)
npm run test:ui

# Run specific test files
npm run test:app          # Health endpoints, logs
npm run test:auth         # Authentication & signup
npm run test:user         # User management
npm run test:file         # File operations
npm run test:cache        # Cache management

# Coverage report
npm run test:coverage
```

## Basic Usage

```javascript
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import TestStartup from '../utils/test.startup.js';

describe('My Test Suite', () => {
    let testStartup;
    let client;

    beforeAll(async () => {
        testStartup = new TestStartup();
        await testStartup.initialize();
        client = testStartup.getClient();
    }, 60000);

    afterAll(async () => {
        await testStartup.cleanup();
    }, 30000);

    test('should authenticate as admin', async () => {
        client.setToken(testStartup.getTokenForUser('admin'));
        const response = await client.get('/api/v1/users');
        expect(response.status).toBe(200);
    });
});
```

## Available Users

- `user` - Basic USER role
- `creator` - CREATOR role
- `superCreator` - SUPER_CREATOR role
- `admin` - ADMIN role
- `owner` - OWNER role (highest permissions)

## Key Methods

```javascript
// Get pre-configured API client
const client = testStartup.getClient();

// Switch user authentication
client.setToken(testStartup.getTokenForUser('admin'));
client.setToken(null); // Clear token

// Create temporary test users
const testUser = await testStartup.createMutableUser({
    role: 'USER',
    firstName: 'Test',
    prefix: 'temp'
});
await testStartup.deleteMutableUser(testUser.id);
```

## Environment

Uses `.env.test` with ports 8380-8389 to avoid conflicts. Tests use real server instance with MongoDB and Redis.

### Database Cleanup

The test suite supports automatic database cleanup through the `DB_CLEANUP` environment variable:

- **`DB_CLEANUP=true`**: Automatically drops all collections after each test suite completes
- **`DB_CLEANUP=false`**: Leaves database state intact (default behavior)

**Additional cleanup methods:**
```javascript
// Full database cleanup (drops all collections)
await testStartup.cleanDatabase();

// Clean specific collections only
await testStartup.cleanCollections(['users', 'files']);

// Reset database (clear documents but keep structure)
await testStartup.resetDatabase();
```
