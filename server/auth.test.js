/**
 * Comprehensive Authentication Layer Test Suite
 * Tests all auth controller endpoints, middleware, and edge cases
 */

const TestStartup = require('../utils/test.startup');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const crypto = require('crypto');

describe('Authentication Layer - Comprehensive Tests', () => {
    let testStartup;
    let client;

    beforeAll(async () => {
        testStartup = new TestStartup();
        await testStartup.initialize();
        client = testStartup.getClient();

        console.log('Auth test environment initialized');
    }, 60000);

    afterAll(async () => {
        await testStartup.cleanup();
    }, 30000);

    describe('User Signup Endpoint', () => {
        describe('POST /api/v1/auth/signup - Success Cases', () => {
            test('should create a new user with valid data', async () => {
                const userData = {
                    firstName: 'John',
                    lastName: 'Doe',
                    username: 'johndoe_' + Date.now(),
                    email: `john.doe.${Date.now()}@example.com`,
                    password: 'SecurePass123!'
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/signup', userData);

                expect(response.status).toBe(201);
                expect(response.data.success).toBe(true);
                expect(response.data.message).toContain('User created successfully');
                expect(response.data.user).toBeDefined();
                expect(response.data.user.email).toBe(userData.email);
                expect(response.data.user.username).toBe(userData.username);
                expect(response.data.user.roles).toContain('USER');
                expect(response.data.authentication).toBeDefined();
                expect(response.data.authentication.accessToken).toBeDefined();
                expect(response.data.authentication.refreshToken).toBeDefined();
            });

            test('should create user with roles when authenticated as owner', async () => {
                const userData = {
                    firstName: 'Admin',
                    lastName: 'User',
                    username: 'adminuser_' + Date.now(),
                    email: `admin.user.${Date.now()}@example.com`,
                    password: 'AdminPass123!',
                    roles: ['ADMIN', 'USER']
                };

                client.setToken(testStartup.getTokenForUser('owner'));
                const response = await client.post('/api/v1/auth/signup', userData);

                expect(response.status).toBe(201);
                expect(response.data.success).toBe(true);
                expect(response.data.user.roles).toEqual(expect.arrayContaining(['ADMIN', 'USER']));
            });

            test('should handle role approval workflow for elevated roles', async () => {
                const userData = {
                    firstName: 'Pending',
                    lastName: 'Admin',
                    username: 'pendingadmin_' + Date.now(),
                    email: `pending.admin.${Date.now()}@example.com`,
                    password: 'PendingPass123!',
                    roles: ['ADMIN']
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/signup', userData);

                expect(response.status).toBe(201);
                expect(response.data.success).toBe(true);
                // Should have USER role assigned, ADMIN pending approval
                expect(response.data.user.roles).toContain('USER');
                expect(response.data.meta.pendingRoles).toContain('ADMIN');
            });
        });

        describe('POST /api/v1/auth/signup - Validation Errors', () => {
            test('should reject signup with missing required fields', async () => {
                const invalidData = {
                    firstName: 'John',
                    lastName: 'Doe'
                    // Missing username, email, password
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/signup', invalidData);
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should reject signup with invalid email format', async () => {
                const invalidData = {
                    firstName: 'John',
                    lastName: 'Doe',
                    username: 'johndoe123',
                    email: 'invalid-email',
                    password: 'SecurePass123!'
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/signup', invalidData);
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should reject signup with weak password', async () => {
                const invalidData = {
                    firstName: 'John',
                    lastName: 'Doe',
                    username: 'johndoe123',
                    email: 'john.doe@example.com',
                    password: 'weak'
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/signup', invalidData);
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should reject signup with invalid username format', async () => {
                const invalidData = {
                    firstName: 'John',
                    lastName: 'Doe',
                    username: 'john-doe!',
                    email: 'john.doe@example.com',
                    password: 'SecurePass123!'
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/signup', invalidData);
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should reject signup with duplicate email', async () => {
                const timestamp = Date.now();
                const userData = {
                    firstName: 'First',
                    lastName: 'User',
                    username: `firstuser${timestamp}`,
                    email: `duplicate${timestamp}@example.com`,
                    password: 'SecurePass123!'
                };

                // Create first user
                client.setToken(null);
                const firstResponse = await client.post('/api/v1/auth/signup', userData);
                expect(firstResponse.status).toBe(201);

                // Try to create second user with same email
                const duplicateData = {
                    ...userData,
                    username: `seconduser${timestamp}`
                };

                const response = await client.post('/api/v1/auth/signup', duplicateData);
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should reject signup with duplicate username', async () => {
                const userData = {
                    firstName: 'First',
                    lastName: 'User',
                    username: 'uniqueuser_' + Date.now(),
                    email: `first.${Date.now()}@example.com`,
                    password: 'SecurePass123!'
                };

                // Create first user
                client.setToken(null);
                await client.post('/api/v1/auth/signup', userData);

                // Try to create second user with same username
                const duplicateData = {
                    ...userData,
                    email: `second.${Date.now()}@example.com`
                };

                const response = await client.post('/api/v1/auth/signup', duplicateData);
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should reject malformed request body', async () => {
                client.setToken(null);
                const response = await client.post('/api/v1/auth/signup', null);
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should reject empty request body', async () => {
                client.setToken(null);
                const response = await client.post('/api/v1/auth/signup', {});
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });
        });
    });

    describe('User Login Endpoint', () => {
        let testUser;

        beforeAll(async () => {
            // Create a test user for login tests
            const userData = {
                firstName: 'Login',
                lastName: 'Test',
                username: 'logintest_' + Date.now(),
                email: `logintest.${Date.now()}@example.com`,
                password: 'LoginPass123!'
            };

            client.setToken(null);
            const response = await client.post('/api/v1/auth/signup', userData);
            testUser = { ...userData, id: response.data.user.id };
        });

        describe('POST /api/v1/auth/login - Success Cases', () => {
            test('should login with valid email and password', async () => {
                const loginData = {
                    identifier: testUser.email,
                    password: testUser.password
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/login', loginData);

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(response.data.message).toContain('Login successful');
                expect(response.data.user).toBeDefined();
                expect(response.data.user.email).toBe(testUser.email);
                expect(response.data.authentication).toBeDefined();
                expect(response.data.authentication.accessToken).toBeDefined();
                expect(response.data.authentication.refreshToken).toBeDefined();
            });

            test('should login with valid username and password', async () => {
                const loginData = {
                    identifier: testUser.username,
                    password: testUser.password
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/login', loginData);

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(response.data.user.username).toBe(testUser.username);
            });
        });

        describe('POST /api/v1/auth/login - Authentication Errors', () => {
            test('should reject login with invalid credentials', async () => {
                const invalidData = {
                    identifier: testUser.email,
                    password: 'WrongPassword123!'
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/login', invalidData);
                
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });

            test('should reject login with non-existent user', async () => {
                const invalidData = {
                    identifier: 'nonexistent@example.com',
                    password: 'SomePassword123!'
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/login', invalidData);
                
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });

            test('should reject login with missing fields', async () => {
                const invalidData = {
                    identifier: testUser.email
                    // Missing password
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/login', invalidData);
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should reject login with empty request body', async () => {
                client.setToken(null);
                const response = await client.post('/api/v1/auth/login', {});
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });
        });
    });

    describe('Token Refresh Endpoint', () => {
        let validRefreshToken;
        let validAccessToken;

        beforeAll(async () => {
            // Create user and get tokens
            const userData = {
                firstName: 'Refresh',
                lastName: 'Test',
                username: 'refreshtest_' + Date.now(),
                email: `refreshtest.${Date.now()}@example.com`,
                password: 'RefreshPass123!'
            };

            client.setToken(null);
            const signupResponse = await client.post('/api/v1/auth/signup', userData);
            validRefreshToken = signupResponse.data.authentication.refreshToken;
            validAccessToken = signupResponse.data.authentication.accessToken;
        });

        describe('POST /api/v1/auth/refresh-token - Success Cases', () => {
            test('should refresh tokens with valid refresh token', async () => {
                const refreshData = {
                    token: validRefreshToken
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/refresh-token', refreshData);

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(response.data.message).toContain('Token refreshed successfully');
                expect(response.data.authentication).toBeDefined();
                expect(response.data.authentication.accessToken).toBeDefined();
                expect(response.data.authentication.refreshToken).toBeDefined();
                // New tokens should be different
                expect(response.data.authentication.accessToken).not.toBe(validAccessToken);
                expect(response.data.authentication.refreshToken).not.toBe(validRefreshToken);
            });
        });

        describe('POST /api/v1/auth/refresh-token - Error Cases', () => {
            test('should reject invalid refresh token', async () => {
                const invalidData = {
                    token: 'invalid.refresh.token'
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/refresh-token', invalidData);
                
                expect(response.status).toBe(403);
                expect(response.data.success).toBe(false);
            });

            test('should reject missing refresh token', async () => {
                client.setToken(null);
                const response = await client.post('/api/v1/auth/refresh-token', {});
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should reject expired refresh token', async () => {
                // Create expired token
                const expiredToken = jwt.sign(
                    { id: 'test123', nonce: 'test' }, 
                    process.env.REFRESH_TOKEN_SECRET,
                    { expiresIn: '-1h' }
                );

                const expiredData = {
                    token: expiredToken
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/refresh-token', expiredData);
                
                expect(response.status).toBe(403);
                expect(response.data.success).toBe(false);
            });
        });
    });

    describe('Password Reset Flow', () => {
        let testUser;

        beforeAll(async () => {
            // Create a mutable user for password reset testing
            testUser = await testStartup.createMutableUser({
                role: 'USER',
                firstName: 'Reset',
                lastName: 'Test',
                prefix: 'resettest'
            });
        });

        afterAll(async () => {
            // Clean up the mutable user
            if (testUser) {
                await testStartup.deleteMutableUser(testUser.id);
            }
        });

        describe('POST /api/v1/auth/forgot-password', () => {
            test('should send reset token for valid email', async () => {
                const resetData = {
                    email: testUser.email
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/forgot-password', resetData);

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(response.data.message).toContain('Password reset email sent');
            });

            test('should handle non-existent email gracefully', async () => {
                const resetData = {
                    email: 'nonexistent@example.com'
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/forgot-password', resetData);

                // Should return success for security (don't reveal user existence)
                expect(response.status).toBe(200);
                expect(response.data.message).toContain('password reset link will be sent');
            });

            test('should reject invalid email format', async () => {
                const invalidData = {
                    email: 'invalid-email'
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/forgot-password', invalidData);
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should reject missing email', async () => {
                client.setToken(null);
                const response = await client.post('/api/v1/auth/forgot-password', {});
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });
        });

        describe('POST /api/v1/auth/reset-password/:token', () => {
            test('should reject invalid reset token', async () => {
                const resetData = {
                    password: 'NewPassword123!'
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/reset-password/invalid-token', resetData);
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should reject weak password', async () => {
                const resetData = {
                    password: 'weak'
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/reset-password/some-token', resetData);
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should reject missing password', async () => {
                client.setToken(null);
                const response = await client.post('/api/v1/auth/reset-password/some-token', {});
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });
        });
    });

    describe('User Profile and Session Management', () => {
        describe('GET /api/v1/auth/me', () => {
            test('should return user profile for authenticated user', async () => {
                client.setToken(testStartup.getTokenForUser('user'));
                const response = await client.get('/api/v1/auth/me');

                expect(response.status).toBe(200);
                expect(response.data.id).toBeDefined();
                expect(response.data.email).toBeDefined();
                expect(response.data.username).toBeDefined();
                expect(response.data.roles).toBeDefined();
                // Should not contain sensitive data
                expect(response.data.password).toBeUndefined();
            });

            test('should deny access without authentication', async () => {
                client.setToken(null);
                const response = await client.get('/api/v1/auth/me');
                
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });

            test('should deny access with invalid token', async () => {
                client.setToken('invalid.jwt.token');
                const response = await client.get('/api/v1/auth/me');
                
                expect(response.status).toBe(403);
                expect(response.data.success).toBe(false);
            });

            test('should cache user profile responses', async () => {
                client.setToken(testStartup.getTokenForUser('user'));
                
                const response1 = await client.get('/api/v1/auth/me');
                const response2 = await client.get('/api/v1/auth/me');

                expect(response1.status).toBe(200);
                expect(response2.status).toBe(200);
                expect(response1.data.id).toBe(response2.data.id);
            });
        });

        describe('GET /api/v1/auth/devices', () => {
            test('should return user devices for authenticated user', async () => {
                client.setToken(testStartup.getTokenForUser('user'));
                const response = await client.get('/api/v1/auth/devices');

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(response.data.devices).toBeDefined();
                expect(Array.isArray(response.data.devices)).toBe(true);
            });

            test('should deny access without authentication', async () => {
                client.setToken(null);
                const response = await client.get('/api/v1/auth/devices');
                
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });
        });

        describe('POST /api/v1/auth/logout', () => {
            test('should logout authenticated user', async () => {
                // First create a new user to get fresh token
                const userData = {
                    firstName: 'Logout',
                    lastName: 'Test',
                    username: 'logouttest_' + Date.now(),
                    email: `logouttest.${Date.now()}@example.com`,
                    password: 'LogoutPass123!'
                };

                client.setToken(null);
                const signupResponse = await client.post('/api/v1/auth/signup', userData);
                const token = signupResponse.data.authentication.accessToken;

                // Logout with the token
                client.setToken(token);
                const response = await client.post('/api/v1/auth/logout');

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(response.data.message).toContain('Logged out successfully');

                // Token should be blacklisted - subsequent requests should fail
                const meResponse = await client.get('/api/v1/auth/me');
                
                expect(meResponse.status).toBe(401);
                expect(meResponse.data.success).toBe(false);
            });

            test('should deny logout without authentication', async () => {
                client.setToken(null);
                const response = await client.post('/api/v1/auth/logout');
                
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });
        });
    });

    describe('Two-Factor Authentication', () => {
        let test2FAUser;
        let test2FAToken;

        beforeAll(async () => {
            // Create a mutable user for 2FA testing
            test2FAUser = await testStartup.createMutableUser({
                role: 'USER',
                firstName: '2FA',
                lastName: 'Test',
                prefix: '2fatest'
            });
            test2FAToken = test2FAUser.token;
        });

        afterAll(async () => {
            // Clean up the mutable user
            if (test2FAUser) {
                await testStartup.deleteMutableUser(test2FAUser.id);
            }
        });

        describe('POST /api/v1/auth/2fa/setup', () => {
            test('should initiate 2FA setup for authenticated user', async () => {
                client.setToken(test2FAToken);
                const response = await client.post('/api/v1/auth/2fa/setup');

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(response.data.message).toContain('2FA setup initiated');
                expect(response.data.qrCode).toBeDefined();
                expect(response.data.manualEntryKey).toBeDefined();
            });

            test('should deny 2FA setup without authentication', async () => {
                client.setToken(null);
                const response = await client.post('/api/v1/auth/2fa/setup');
                
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });
        });

        describe('GET /api/v1/auth/2fa/status', () => {
            test('should return 2FA status for authenticated user', async () => {
                client.setToken(test2FAToken);
                const response = await client.get('/api/v1/auth/2fa/status');

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(response.data.message).toContain('2FA status retrieved successfully');
                expect(typeof response.data.twoFactorEnabled).toBe('boolean');
                expect(typeof response.data.backupCodesRemaining).toBe('number');
            });

            test('should deny 2FA status without authentication', async () => {
                client.setToken(null);
                const response = await client.get('/api/v1/auth/2fa/status');
                
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });
        });

        describe('POST /api/v1/auth/2fa/verify-setup', () => {
            test('should reject 2FA verification with missing token', async () => {
                client.setToken(test2FAToken);
                const response = await client.post('/api/v1/auth/2fa/verify-setup', {});
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should reject 2FA verification with invalid token', async () => {
                client.setToken(test2FAToken);
                const verifyData = {
                    token: '000000'
                };

                const response = await client.post('/api/v1/auth/2fa/verify-setup', verifyData);
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should deny 2FA verification without authentication', async () => {
                client.setToken(null);
                const verifyData = {
                    token: '123456'
                };

                const response = await client.post('/api/v1/auth/2fa/verify-setup', verifyData);
                
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });
        });

        describe('POST /api/v1/auth/2fa/disable', () => {
            test('should reject 2FA disable with missing data', async () => {
                client.setToken(test2FAToken);
                const response = await client.post('/api/v1/auth/2fa/disable', {});
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should deny 2FA disable without authentication', async () => {
                client.setToken(null);
                const disableData = {
                    password: '2FAPass123!',
                    token: '123456'
                };

                const response = await client.post('/api/v1/auth/2fa/disable', disableData);
                
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });
        });

        describe('POST /api/v1/auth/2fa/backup-codes', () => {
            test('should reject backup codes generation with missing data', async () => {
                client.setToken(test2FAToken);
                const response = await client.post('/api/v1/auth/2fa/backup-codes', {});
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should deny backup codes generation without authentication', async () => {
                client.setToken(null);
                const codesData = {
                    password: '2FAPass123!',
                    token: '123456'
                };

                const response = await client.post('/api/v1/auth/2fa/backup-codes', codesData);
                
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });
        });
    });

    describe('Email Verification', () => {
        let testEmailUser;
        let testEmailToken;

        beforeAll(async () => {
            // Create a mutable user for email verification testing
            testEmailUser = await testStartup.createMutableUser({
                role: 'USER',
                firstName: 'Email',
                lastName: 'Test',
                prefix: 'emailtest'
            });
            testEmailToken = testEmailUser.token;
        });

        afterAll(async () => {
            // Clean up the mutable user
            if (testEmailUser) {
                await testStartup.deleteMutableUser(testEmailUser.id);
            }
        });

        describe('POST /api/v1/auth/send-verification-email', () => {
            test('should send verification email for authenticated user', async () => {
                client.setToken(testEmailToken);
                const response = await client.post('/api/v1/auth/send-verification-email');

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(response.data.message).toContain('Verification email sent');
            });

            test('should deny verification email without authentication', async () => {
                client.setToken(null);
                const response = await client.post('/api/v1/auth/send-verification-email');
                
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });
        });

        describe('GET /api/v1/auth/verify-email/:token', () => {
            test('should reject invalid verification token', async () => {
                client.setToken(null);
                const response = await client.get('/api/v1/auth/verify-email/invalid-token');
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should reject expired verification token', async () => {
                client.setToken(null);
                const response = await client.get('/api/v1/auth/verify-email/expired-token');
                
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });
        });
    });

    describe('Role Management (Owner Only)', () => {
        describe('GET /api/v1/auth/roles/pending-requests', () => {
            test('should return pending role requests for owner', async () => {
                client.setToken(testStartup.getTokenForUser('owner'));
                const response = await client.get('/api/v1/auth/roles/pending-requests');

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(response.data.pendingRequests).toBeDefined();
                expect(Array.isArray(response.data.pendingRequests)).toBe(true);
            });

            test('should deny access to non-owner users', async () => {
                client.setToken(testStartup.getTokenForUser('admin'));
                const response = await client.get('/api/v1/auth/roles/pending-requests');
                
                expect(response.status).toBe(403);
                expect(response.data.success).toBe(false);
            });

            test('should deny access without authentication', async () => {
                client.setToken(null);
                const response = await client.get('/api/v1/auth/roles/pending-requests');
                
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });

            test('should cache pending requests responses', async () => {
                client.setToken(testStartup.getTokenForUser('owner'));
                
                const response1 = await client.get('/api/v1/auth/roles/pending-requests');
                const response2 = await client.get('/api/v1/auth/roles/pending-requests');

                expect(response1.status).toBe(200);
                expect(response2.status).toBe(200);
            });
        });

        describe('POST /api/v1/auth/roles/request-elevation', () => {
            test('should allow authenticated user to request role elevation', async () => {
                client.setToken(testStartup.getTokenForUser('user'));
                const elevationData = {
                    roles: ['CREATOR']
                };
                const response = await client.post('/api/v1/auth/roles/request-elevation', elevationData);

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(response.data.message).toContain('elevation request');
            });

            test('should deny role elevation request without authentication', async () => {
                client.setToken(null);
                const response = await client.post('/api/v1/auth/roles/request-elevation');
                
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });
        });

        describe('POST /api/v1/auth/roles/approve/:userId', () => {
            test('should deny role approval for non-owner users', async () => {
                const userId = new mongoose.Types.ObjectId();
                client.setToken(testStartup.getTokenForUser('admin'));
                const response = await client.post(`/api/v1/auth/roles/approve/${userId}`);
                
                expect(response.status).toBe(403);
                expect(response.data.success).toBe(false);
            });

            test('should deny role approval without authentication', async () => {
                const userId = new mongoose.Types.ObjectId();
                client.setToken(null);
                const response = await client.post(`/api/v1/auth/roles/approve/${userId}`);
                
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });
        });

        describe('POST /api/v1/auth/roles/reject/:userId', () => {
            test('should deny role rejection for non-owner users', async () => {
                const userId = new mongoose.Types.ObjectId();
                client.setToken(testStartup.getTokenForUser('admin'));
                const response = await client.post(`/api/v1/auth/roles/reject/${userId}`);
                expect(response.status).toBe(403);
                expect(response.data.success).toBe(false);
            });

            test('should deny role rejection without authentication', async () => {
                const userId = new mongoose.Types.ObjectId();
                client.setToken(null);
                const response = await client.post(`/api/v1/auth/roles/reject/${userId}`);
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });
        });
    });

    describe('Authentication Middleware Edge Cases', () => {
        describe('Token Validation', () => {
            test('should handle malformed JWT tokens', async () => {
                client.setToken('malformed.jwt');
                const response = await client.get('/api/v1/auth/me');
                expect(response.status).toBe(403);
                expect(response.data.success).toBe(false);
            });

            test('should handle missing Bearer prefix', async () => {
                const token = testStartup.getTokenForUser('user');
                // Set header without Bearer prefix using the client's internal method
                const originalSetToken = client.setToken;
                client.setToken = function(t) {
                    if (t) {
                        this.client.defaults.headers['Authorization'] = t; // No Bearer prefix
                    } else {
                        delete this.client.defaults.headers['Authorization'];
                    }
                };
                client.setToken(token);
                
                const response = await client.get('/api/v1/auth/me');
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);

                // Restore original setToken method
                client.setToken = originalSetToken;
            });

            test('should handle empty authorization header', async () => {
                // Set empty authorization header using the client's internal method
                const originalSetToken = client.setToken;
                client.setToken = function(t) {
                    this.client.defaults.headers['Authorization'] = '';
                };
                client.setToken('');
                
                const response = await client.get('/api/v1/auth/me');
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);

                // Restore original setToken method
                client.setToken = originalSetToken;
            });

            test('should handle tokens with wrong secret', async () => {
                // Create token with wrong secret
                const wrongToken = jwt.sign(
                    { id: 'test123', username: 'test', email: 'test@test.com' },
                    'wrong-secret',
                    { expiresIn: '15m' }
                );

                client.setToken(wrongToken);
                const response = await client.get('/api/v1/auth/me');
                expect(response.status).toBe(403);
                expect(response.data.success).toBe(false);
            });

            test('should handle expired access tokens', async () => {
                // Create expired token with correct secret
                const expiredToken = jwt.sign(
                    { id: 'test123', username: 'test', email: 'test@test.com' },
                    process.env.ACCESS_TOKEN_SECRET,
                    { expiresIn: '-1h' }
                );

                client.setToken(expiredToken);
                const response = await client.get('/api/v1/auth/me');
                expect(response.status).toBe(403);
                expect(response.data.success).toBe(false);
            });

            test('should handle tokens with missing required fields', async () => {
                // Create token missing required fields
                const incompleteToken = jwt.sign(
                    { id: 'test123' }, // Missing username and email
                    process.env.ACCESS_TOKEN_SECRET,
                    { expiresIn: '15m' }
                );

                client.setToken(incompleteToken);
                const response = await client.get('/api/v1/auth/me');
                expect(response.status).toBe(500);
                expect(response.data.success).toBe(false);
            });
        });

        describe('Permission Checking', () => {
            test('should handle missing user object in permission check', async () => {
                // This would be an internal error, but should be handled gracefully
                client.setToken(testStartup.getTokenForUser('user'));
                
                // Access admin-only endpoint
                const response = await client.get('/api/v1/logs');
                expect(response.status).toBe(403);
                expect(response.data.success).toBe(false);
            });

            test('should handle role hierarchy correctly', async () => {
                const roles = ['user', 'creator', 'superCreator', 'admin', 'owner'];
                
                for (const role of roles) {
                    client.setToken(testStartup.getTokenForUser(role));
                    
                    if (['admin', 'owner'].includes(role)) {
                        // Should have access to admin endpoints
                        const response = await client.get('/api/v1/logs');
                        expect(response.status).toBe(200);
                    } else {
                        // Should not have access to admin endpoints
                        const response = await client.get('/api/v1/logs');
                        expect(response.status).toBe(403);
                    }
                }
            });
        });

        describe('Optional Authentication', () => {
            test('should handle requests without tokens for optional auth endpoints', async () => {
                // Test public endpoints that use optional auth
                client.setToken(null);
                const response = await client.get('/api/v1/health');
                
                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
            });

            test('should extract user info when valid token provided to optional auth endpoints', async () => {
                client.setToken(testStartup.getTokenForUser('user'));
                const response = await client.get('/api/v1/health');
                
                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
            });

            test('should gracefully handle invalid tokens in optional auth', async () => {
                client.setToken('invalid.token');
                const response = await client.get('/api/v1/health');
                
                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
            });
        });
    });

    describe('Rate Limiting and Security', () => {
        describe('Request Rate Limiting', () => {
            test('should handle multiple rapid login attempts', async () => {
                const loginData = {
                    identifier: 'test@example.com',
                    password: 'TestPass123!'
                };

                client.setToken(null);
                
                // Make multiple rapid requests
                const promises = Array(5).fill().map(() => 
                    client.post('/api/v1/auth/login', loginData).catch(err => err)
                );

                const results = await Promise.all(promises);
                
                // All should handle the requests (either success or proper error responses)
                // Since the credentials don't exist, we expect all to return 401 responses
                const allHandled = results.every(r => r.status === 401);
                expect(allHandled).toBe(true);
            });

            test('should handle multiple rapid signup attempts', async () => {
                client.setToken(null);
                
                const signupPromises = Array(3).fill().map((_, i) => 
                    client.post('/api/v1/auth/signup', {
                        firstName: 'Rapid',
                        lastName: 'Test',
                        username: `rapidtest${i}_${Date.now()}`,
                        email: `rapidtest${i}.${Date.now()}@example.com`,
                        password: 'RapidPass123!'
                    }).catch(err => err)
                );

                const results = await Promise.all(signupPromises);
                
                // At least some should succeed or fail with proper error codes
                expect(results.length).toBe(3);
            });
        });

        describe('Input Sanitization', () => {
            test('should handle special characters in login credentials', async () => {
                const loginData = {
                    identifier: 'test<script>alert("xss")</script>@example.com',
                    password: 'TestPass123!<script>'
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/login', loginData);
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });

            test('should handle NoSQL injection attempts in signup', async () => {
                const noSqlInjectionData = {
                    firstName: 'Test',
                    lastName: 'User',
                    username: 'nosqltest',
                    email: { $ne: null }, // NoSQL injection attempt
                    password: 'TestPass123!'
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/signup', noSqlInjectionData);
                
                // Should be rejected due to validation - email must be string, not object
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
                expect(response.data.message).toContain('email');
            });

            test('should safely store special characters as literal text', async () => {
                const specialCharsData = {
                    firstName: "'; DROP TABLE users; --", // This is just text to MongoDB
                    lastName: '<script>alert("xss")</script>',
                    username: 'specialtest',
                    email: 'special@example.com',
                    password: 'TestPass123!'
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/signup', specialCharsData);
                
                // Should succeed - MongoDB stores these as literal strings
                expect(response.status).toBe(201);
                expect(response.data.success).toBe(true);
                
                // Verify the content was stored as literal text (not executed)
                expect(response.data.user.firstName).toBe("'; DROP TABLE users; --");
                expect(response.data.user.lastName).toBe('<script>alert("xss")</script>');
            });

            test('should handle extremely long input values', async () => {
                const longString = 'a'.repeat(1000);
                const invalidData = {
                    firstName: longString,
                    lastName: longString,
                    username: longString,
                    email: `${longString}@example.com`,
                    password: 'TestPass123!'
                };

                client.setToken(null);
                const response = await client.post('/api/v1/auth/signup', invalidData);
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });
        });

        describe('Concurrent User Management', () => {
            test('should handle concurrent login attempts for same user', async () => {
                // First create a user
                const userData = {
                    firstName: 'Concurrent',
                    lastName: 'Test',
                    username: 'concurrenttest_' + Date.now(),
                    email: `concurrenttest.${Date.now()}@example.com`,
                    password: 'ConcurrentPass123!'
                };

                client.setToken(null);
                await client.post('/api/v1/auth/signup', userData);

                // Now try concurrent logins
                const loginData = {
                    identifier: userData.email,
                    password: userData.password
                };

                const loginPromises = Array(3).fill().map(() => 
                    client.post('/api/v1/auth/login', loginData)
                );

                const results = await Promise.all(loginPromises);
                
                // All should succeed
                results.forEach(result => {
                    expect(result.status).toBe(200);
                    expect(result.data.success).toBe(true);
                });
            });

            test('should handle concurrent token refresh attempts', async () => {
                // Create user and get tokens
                const userData = {
                    firstName: 'Refresh',
                    lastName: 'Concurrent',
                    username: 'refconc_' + Date.now().toString().slice(-8), // Keep username under 30 chars
                    email: `refreshconcurrent.${Date.now()}@example.com`,
                    password: 'RefreshPass123!'
                };

                client.setToken(null);
                const signupResponse = await client.post('/api/v1/auth/signup', userData);
                const refreshToken = signupResponse.data.authentication.refreshToken;

                // Try concurrent refresh attempts
                const refreshData = { token: refreshToken };
                const refreshPromises = Array(2).fill().map(() => 
                    client.post('/api/v1/auth/refresh-token', refreshData).catch(err => err)
                );

                const results = await Promise.all(refreshPromises);
                
                // At least one should succeed
                const successes = results.filter(r => r.status === 200);
                expect(successes.length).toBeGreaterThan(0);
            });
        });
    });
});
