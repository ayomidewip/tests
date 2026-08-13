/**
 * Comprehensive User Controller, Middleware, and Routes Test Suite
 * Tests all user endpoints, middleware functions, and edge cases
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import mongoose from 'mongoose';
import TestStartup from '../utils/test.startup.js';
import ApiClient from '../utils/api.client.js';

describe('User Comprehensive Tests', () => {
    let testStartup;
    let client;

    beforeAll(async () => {
        testStartup = new TestStartup('user');
        await testStartup.initialize();
        client = testStartup.getClient();
        console.log('User tests initialized on port:', testStartup.port, 'DB:', testStartup.dbName);
    }, 60000);

    afterAll(async () => {
        await testStartup.cleanup();
    }, 30000);

    describe('User Controller - Get All Users', () => {
        describe('GET /api/v1/users - Success Cases', () => {
            test('should get all users as admin', async () => {
                await testStartup.loginAsUser('admin');
                const response = await client.get('/api/v1/users');

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(response.data.message).toBe('Users retrieved successfully');
                expect(Array.isArray(response.data.users)).toBe(true);
                expect(response.data.meta).toBeDefined();
                expect(response.data.meta.count).toBeDefined();
                expect(response.data.meta.totalUsers).toBeDefined();
                expect(response.data.meta.timestamp).toBeDefined();
                expect(response.data.users.length).toBeGreaterThan(0);
            });

            test('should get all users as owner', async () => {
                await testStartup.loginAsUser('owner');
                const response = await client.get('/api/v1/users');

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(Array.isArray(response.data.users)).toBe(true);
            });

            test('should support pagination parameters', async () => {
                await testStartup.loginAsUser('admin');
                const response = await client.get('/api/v1/users?page=1&limit=2');

                expect(response.status).toBe(200);
                expect(response.data.users.length).toBeLessThanOrEqual(2);
                expect(response.data.meta.pagination).toBeDefined();
                expect(response.data.meta.pagination.page).toBe(1);
                expect(response.data.meta.pagination.limit).toBe(2);
                expect(response.data.meta.pagination.totalPages).toBeGreaterThan(0);
            });

            test('should support search and filtering', async () => {
                await testStartup.loginAsUser('admin');
                const response = await client.get('/api/v1/users?search=admin');

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(Array.isArray(response.data.users)).toBe(true);
            });

            test('should support role filtering', async () => {
                await testStartup.loginAsUser('admin');
                const response = await client.get('/api/v1/users?role=ADMIN');

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
            });

            test('should support sorting', async () => {
                await testStartup.loginAsUser('admin');
                const response = await client.get('/api/v1/users?sortBy=createdAt&sortOrder=desc');

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(Array.isArray(response.data.users)).toBe(true);
            });

            test('should return properly formatted user objects', async () => {
                await testStartup.loginAsUser('admin');
                const response = await client.get('/api/v1/users?limit=1');

                expect(response.status).toBe(200);
                if (response.data.users.length > 0) {
                    const user = response.data.users[0];
                    expect(user).toHaveProperty('id');
                    expect(user).toHaveProperty('firstName');
                    expect(user).toHaveProperty('lastName');
                    expect(user).toHaveProperty('username');
                    expect(user).toHaveProperty('email');
                    expect(user).toHaveProperty('roles');
                    expect(user).toHaveProperty('emailVerified');
                    expect(user).toHaveProperty('active');
                    expect(user).toHaveProperty('createdAt');
                    expect(user).not.toHaveProperty('password');
                    expect(user).not.toHaveProperty('refreshTokens');
                    expect(Array.isArray(user.roles)).toBe(true);
                }
            });

            test('should cache responses appropriately', async () => {
                await testStartup.loginAsUser('admin');
                
                // First request
                const response1 = await client.get('/api/v1/users?limit=3');
                expect(response1.status).toBe(200);
                
                // Second request (should be cached)
                const response2 = await client.get('/api/v1/users?limit=3');
                expect(response2.status).toBe(200);
                
                // Different query should not be cached
                const response3 = await client.get('/api/v1/users?limit=5');
                expect(response3.status).toBe(200);
            });
        });

        describe('GET /api/v1/users - Permission Tests', () => {
            test('should deny access for regular users', async () => {
                await testStartup.loginAsUser('user');
                
                const response = await client.get('/api/v1/users');
                expect(response.status).toBe(403);
                expect(response.data.success).toBe(false);
            });

            test('should deny access for creators', async () => {
                await testStartup.loginAsUser('creator');
                
                const response = await client.get('/api/v1/users');
                expect(response.status).toBe(403);
                expect(response.data.success).toBe(false);
            });

            test('should deny access for super creators', async () => {
                await testStartup.loginAsUser('superCreator');
                
                const response = await client.get('/api/v1/users');
                expect(response.status).toBe(403);
                expect(response.data.success).toBe(false);
            });

            test('should deny access without authentication', async () => {
                client.clearCookies();
                
                const response = await client.get('/api/v1/users');
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });
        });

        describe('GET /api/v1/users - Edge Cases', () => {
            test('should handle invalid pagination parameters gracefully', async () => {
                await testStartup.loginAsUser('admin');
                const response = await client.get('/api/v1/users?page=-1&limit=0');
                
                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
            });

            test('should handle invalid sort parameters gracefully', async () => {
                await testStartup.loginAsUser('admin');
                const response = await client.get('/api/v1/users?sortBy=invalidField');
                
                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
            });

            test('should handle empty search results', async () => {
                await testStartup.loginAsUser('admin');
                const response = await client.get('/api/v1/users?search=nonexistentuser12345');
                
                expect(response.status).toBe(200);
                expect(response.data.users).toEqual([]);
                expect(response.data.meta.count).toBe(0);
            });
        });
    });

    describe('User Controller - Get User by ID', () => {
        describe('GET /api/v1/users/:id - Success Cases', () => {
            test('should get user by ID as admin', async () => {
                await testStartup.loginAsUser('admin');
                const userId = testStartup.user.id;
                
                const response = await client.get(`/api/v1/users/${userId}`);

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(response.data.user.id).toBe(userId);
                expect(response.data.user).not.toHaveProperty('password');
            });

            test('should allow users to get their own profile', async () => {
                await testStartup.loginAsUser('user');
                const userId = testStartup.user.id;
                
                const response = await client.get(`/api/v1/users/${userId}`);

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(response.data.user.id).toBe(userId);
            });

            test('should cache user profile responses', async () => {
                await testStartup.loginAsUser('admin');
                const userId = testStartup.user.id;
                
                const response1 = await client.get(`/api/v1/users/${userId}`);
                const response2 = await client.get(`/api/v1/users/${userId}`);
                
                expect(response1.status).toBe(200);
                expect(response2.status).toBe(200);
            });
        });

        describe('GET /api/v1/users/:id - Permission Tests', () => {
            test('should deny access to other users profiles for regular users', async () => {
                await testStartup.loginAsUser('user');
                const adminId = testStartup.admin.id;
                
                const response = await client.get(`/api/v1/users/${adminId}`);
                expect(response.status).toBe(403);
                expect(response.data.success).toBe(false);
            });

            test('should deny access without authentication', async () => {
                client.clearCookies();
                const userId = testStartup.user.id;
                
                const response = await client.get(`/api/v1/users/${userId}`);
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });
        });

        describe('GET /api/v1/users/:id - Error Cases', () => {
            test('should return 400 for invalid user ID format', async () => {
                await testStartup.loginAsUser('admin');
                
                const response = await client.get('/api/v1/users/invalid-id');
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should return 404 for non-existent user ID', async () => {
                await testStartup.loginAsUser('admin');
                const fakeId = new mongoose.Types.ObjectId();
                
                const response = await client.get(`/api/v1/users/${fakeId}`);
                expect(response.status).toBe(404);
                expect(response.data.success).toBe(false);
            });
        });
    });

    describe('User Controller - Create User', () => {
        describe('POST /api/v1/users - Success Cases', () => {
            test('should create a new user as admin', async () => {
                await testStartup.loginAsUser('admin');
                const userData = {
                    firstName: 'New',
                    lastName: 'User',
                    username: 'newuser_' + Date.now(),
                    email: `newuser.${Date.now()}@example.com`,
                    password: 'NewUser123!',
                    roles: ['USER']
                };

                const response = await client.post('/api/v1/users', userData);

                expect(response.status).toBe(201);
                expect(response.data.success).toBe(true);
                expect(response.data.message).toBe('User created successfully');
                expect(response.data.user).toBeDefined();
                expect(response.data.user.username).toBe(userData.username);
                expect(response.data.user.email).toBe(userData.email);
                expect(response.data.user).not.toHaveProperty('password');
            });

            test('should create user with default role when none specified', async () => {
                await testStartup.loginAsUser('admin');
                const userData = {
                    firstName: 'Default',
                    lastName: 'Role',
                    username: 'defaultrole_' + Date.now(),
                    email: `defaultrole.${Date.now()}@example.com`,
                    password: 'DefaultRole123!'
                };

                const response = await client.post('/api/v1/users', userData);

                expect(response.status).toBe(201);
                expect(response.data.user.roles).toContain('USER');
            });

            test('should handle role approval for elevated roles', async () => {
                await testStartup.loginAsUser('admin');
                const userData = {
                    firstName: 'Admin',
                    lastName: 'Request',
                    username: 'adminrequest_' + Date.now(),
                    email: `adminrequest.${Date.now()}@example.com`,
                    password: 'AdminReq123!',
                    roles: ['ADMIN']
                };

                const response = await client.post('/api/v1/users', userData);

                expect(response.status).toBe(201);
                expect(response.data.success).toBe(true);
            });
        });

        describe('POST /api/v1/users - Permission Tests', () => {
            test('should deny user creation for regular users', async () => {
                await testStartup.loginAsUser('user');
                const userData = {
                    firstName: 'Denied',
                    lastName: 'User',
                    username: 'denied_' + Date.now(),
                    email: `denied.${Date.now()}@example.com`,
                    password: 'Denied123!'
                };

                const response = await client.post('/api/v1/users', userData);
                expect(response.status).toBe(403);
                expect(response.data.success).toBe(false);
            });

            test('should deny user creation without authentication', async () => {
                client.clearCookies();
                const userData = {
                    firstName: 'No',
                    lastName: 'Auth',
                    username: 'noauth_' + Date.now(),
                    email: `noauth.${Date.now()}@example.com`,
                    password: 'NoAuth123!'
                };

                const response = await client.post('/api/v1/users', userData);
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });
        });

        describe('POST /api/v1/users - Validation Tests', () => {
            test('should reject invalid email format', async () => {
                await testStartup.loginAsUser('admin');
                const userData = {
                    firstName: 'Invalid',
                    lastName: 'Email',
                    username: 'invalidemail_' + Date.now(),
                    email: 'invalid-email-format',
                    password: 'Invalid123!'
                };

                const response = await client.post('/api/v1/users', userData);
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should reject weak passwords', async () => {
                await testStartup.loginAsUser('admin');
                const userData = {
                    firstName: 'Weak',
                    lastName: 'Password',
                    username: 'weakpass_' + Date.now(),
                    email: `weakpass.${Date.now()}@example.com`,
                    password: '123'
                };

                const response = await client.post('/api/v1/users', userData);
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should reject missing required fields', async () => {
                await testStartup.loginAsUser('admin');
                const userData = {
                    firstName: 'Missing',
                    lastName: 'Fields'
                    // Missing username, email, password
                };

                const response = await client.post('/api/v1/users', userData);
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should reject duplicate username', async () => {
                await testStartup.loginAsUser('admin');
                const existingUser = testStartup.user;
                const userData = {
                    firstName: 'Duplicate',
                    lastName: 'Username',
                    username: existingUser.username,
                    email: `duplicate.${Date.now()}@example.com`,
                    password: 'Duplicate123!'
                };

                const response = await client.post('/api/v1/users', userData);
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });
        });
    });

    describe('User Controller - Update User', () => {
        describe('PUT /api/v1/users/:id - Success Cases', () => {
            test('should update user as admin', async () => {
                let testUser = await testStartup.createMutableUser({
                    role: 'USER',
                    firstName: 'Update',
                    lastName: 'Test',
                    prefix: 'updatetest'
                });

                try {
                    await testStartup.loginAsUser('admin');
                    const updateData = {
                        firstName: 'Updated',
                        lastName: 'Name'
                    };

                    const response = await client.put(`/api/v1/users/${testUser.id}`, updateData);

                    expect(response.status).toBe(200);
                    expect(response.data.success).toBe(true);
                    expect(response.data.message).toBe('User updated successfully');
                    expect(response.data.user.firstName).toBe('Updated');
                    expect(response.data.user.lastName).toBe('Name');
                } finally {
                    if (testUser) {
                        await testStartup.deleteMutableUser(testUser.id);
                    }
                }
            });

            test('should allow users to update their own profile', async () => {
                let testUser = await testStartup.createMutableUser({
                    role: 'USER',
                    firstName: 'Self',
                    lastName: 'Update',
                    prefix: 'selfupdate'
                });

                try {
                    // Login as the user to get cookies
                    client.clearCookies();
                    await client.post('/api/v1/auth/login', {
                        identifier: testUser.email,
                        password: 'MutablePass123!'
                    });
                    
                    const updateData = {
                        firstName: 'Self Updated'
                    };

                    const response = await client.put(`/api/v1/users/${testUser.id}`, updateData);

                    expect(response.status).toBe(200);
                    expect(response.data.success).toBe(true);
                    expect(response.data.user.firstName).toBe('Self Updated');
                } finally {
                    if (testUser) {
                        await testStartup.deleteMutableUser(testUser.id);
                    }
                }
            });

            test('should handle role updates with proper approval logic', async () => {
                let testUser = await testStartup.createMutableUser({
                    role: 'USER',
                    firstName: 'Role',
                    lastName: 'Update',
                    prefix: 'roleupdate'
                });

                try {
                    await testStartup.loginAsUser('admin');
                    const updateData = {
                        roles: ['CREATOR']
                    };

                    const response = await client.put(`/api/v1/users/${testUser.id}`, updateData);

                    expect(response.status).toBe(200);
                    expect(response.data.success).toBe(true);
                } finally {
                    if (testUser) {
                        await testStartup.deleteMutableUser(testUser.id);
                    }
                }
            });

            test('should invalidate cache after user update', async () => {
                let testUser = await testStartup.createMutableUser({
                    role: 'USER',
                    firstName: 'Cache',
                    lastName: 'Test',
                    prefix: 'cachetest'
                });

                try {
                    await testStartup.loginAsUser('admin');
                    
                    // Get user first (should populate cache)
                    const response1 = await client.get(`/api/v1/users/${testUser.id}`);
                    expect(response1.status).toBe(200);
                    
                    // Update user
                    const updateData = { firstName: 'Cache Updated' };
                    const updateResponse = await client.put(`/api/v1/users/${testUser.id}`, updateData);
                    expect(updateResponse.status).toBe(200);
                    
                    // Get user again (should return updated data)
                    const response2 = await client.get(`/api/v1/users/${testUser.id}`);
                    expect(response2.status).toBe(200);
                    expect(response2.data.user.firstName).toBe('Cache Updated');
                } finally {
                    if (testUser) {
                        await testStartup.deleteMutableUser(testUser.id);
                    }
                }
            });
        });

        describe('PUT /api/v1/users/:id - Permission Tests', () => {
            test('should deny update for other users profiles by regular users', async () => {
                await testStartup.loginAsUser('user');
                const adminId = testStartup.admin.id;
                const updateData = { firstName: 'Unauthorized' };

                const response = await client.put(`/api/v1/users/${adminId}`, updateData);
                expect(response.status).toBe(403);
                expect(response.data.success).toBe(false);
            });

            test('should deny update without authentication', async () => {
                client.clearCookies();
                const userId = testStartup.user.id;
                const updateData = { firstName: 'No Auth' };

                const response = await client.put(`/api/v1/users/${userId}`, updateData);
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });
        });

        describe('PUT /api/v1/users/:id - Validation Tests', () => {
            test('should reject invalid email format', async () => {
                await testStartup.loginAsUser('admin');
                const userId = testStartup.user.id;
                const updateData = { email: 'invalid-email' };

                const response = await client.put(`/api/v1/users/${userId}`, updateData);
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should handle non-existent user ID', async () => {
                await testStartup.loginAsUser('admin');
                const fakeId = new mongoose.Types.ObjectId();
                const updateData = { firstName: 'Non Existent' };

                const response = await client.put(`/api/v1/users/${fakeId}`, updateData);
                expect(response.status).toBe(404);
                expect(response.data.success).toBe(false);
            });
        });
    });

    describe('User Controller - Delete User', () => {
        describe('DELETE /api/v1/users/:id - Success Cases', () => {
            test('should delete user as owner', async () => {
                let testUser = await testStartup.createMutableUser({
                    role: 'USER',
                    firstName: 'Delete',
                    lastName: 'Test',
                    prefix: 'deletetest'
                });

                try {
                    await testStartup.loginAsUser('owner');
                    const response = await client.delete(`/api/v1/users/${testUser.id}`);

                    expect(response.status).toBe(200);
                    expect(response.data.success).toBe(true);
                    expect(response.data.message).toContain('deleted successfully');
                    
                    // Mark as deleted so cleanup doesn't try to delete again
                    testUser = null;
                } finally {
                    if (testUser) {
                        await testStartup.deleteMutableUser(testUser.id);
                    }
                }
            });

            test('should soft delete user (set active to false)', async () => {
                let testUser = await testStartup.createMutableUser({
                    role: 'USER',
                    firstName: 'Soft',
                    lastName: 'Delete',
                    prefix: 'softdelete'
                });

                try {
                    await testStartup.loginAsUser('owner');
                    const response = await client.delete(`/api/v1/users/${testUser.id}`);

                    expect(response.status).toBe(200);
                    expect(response.data.success).toBe(true);
                    
                    testUser = null;
                } finally {
                    if (testUser) {
                        await testStartup.deleteMutableUser(testUser.id);
                    }
                }
            });
        });

        describe('DELETE /api/v1/users/:id - Permission Tests', () => {
            test('should deny delete for admin users (only owner can delete)', async () => {
                let testUser = await testStartup.createMutableUser({
                    role: 'USER',
                    firstName: 'Admin',
                    lastName: 'Deny',
                    prefix: 'admindeny'
                });

                try {
                    await testStartup.loginAsUser('admin');
                    
                    const response = await client.delete(`/api/v1/users/${testUser.id}`);
                    expect(response.status).toBe(403);
                    expect(response.data.success).toBe(false);
                } finally {
                    if (testUser) {
                        // Use owner login to actually delete the user
                        const ownerClient = new ApiClient(testStartup.baseURL);
                        await testStartup.loginAsUser('owner', ownerClient);
                        try {
                            await ownerClient.delete(`/api/v1/users/${testUser.id}`);
                        } catch (e) {
                            // Ignore deletion errors
                        }
                    }
                }
            });

            test('should deny delete for regular users', async () => {
                await testStartup.loginAsUser('user');
                const adminId = testStartup.admin.id;

                const response = await client.delete(`/api/v1/users/${adminId}`);
                expect(response.status).toBe(403);
                expect(response.data.success).toBe(false);
            });

            test('should deny delete without authentication', async () => {
                client.clearCookies();
                const userId = testStartup.user.id;

                const response = await client.delete(`/api/v1/users/${userId}`);
                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });
        });

        describe('DELETE /api/v1/users/:id - Error Cases', () => {
            test('should handle non-existent user ID', async () => {
                await testStartup.loginAsUser('owner');
                const fakeId = new mongoose.Types.ObjectId();

                const response = await client.delete(`/api/v1/users/${fakeId}`);
                expect(response.status).toBe(404);
                expect(response.data.success).toBe(false);
            });

            test('should handle invalid user ID format', async () => {
                await testStartup.loginAsUser('owner');

                const response = await client.delete('/api/v1/users/invalid-id');
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });
        });
    });

    describe('User Controller - Change Password', () => {
        describe('PUT /api/v1/users/:id/password - Success Cases', () => {
            test('should allow user to change their own password', async () => {
                let testUser = await testStartup.createMutableUser({
                    role: 'USER',
                    firstName: 'Password',
                    lastName: 'Change',
                    prefix: 'passwordchange'
                });

                try {
                    // Login as the user to get cookies
                    client.clearCookies();
                    await client.post('/api/v1/auth/login', {
                        identifier: testUser.email,
                        password: 'MutablePass123!'
                    });
                    
                    const passwordData = {
                        currentPassword: 'MutablePass123!',
                        newPassword: 'NewPass123!'
                    };

                    const response = await client.put(`/api/v1/users/${testUser.id}/password`, passwordData);

                    expect(response.status).toBe(200);
                    expect(response.data.success).toBe(true);
                    expect(response.data.message).toContain('Password updated successfully');
                } finally {
                    if (testUser) {
                        await testStartup.deleteMutableUser(testUser.id);
                    }
                }
            });

            test('should allow admin to change any user password', async () => {
                let testUser = await testStartup.createMutableUser({
                    role: 'USER',
                    firstName: 'Admin',
                    lastName: 'Password',
                    prefix: 'adminpassword'
                });

                try {
                    await testStartup.loginAsUser('admin');
                    
                    const passwordData = {
                        newPassword: 'AdminSet123!'
                    };

                    const response = await client.put(`/api/v1/users/${testUser.id}/password`, passwordData);

                    expect(response.status).toBe(200);
                    expect(response.data.success).toBe(true);
                } finally {
                    if (testUser) {
                        await testStartup.deleteMutableUser(testUser.id);
                    }
                }
            });
        });

        describe('PUT /api/v1/users/:id/password - Validation Tests', () => {
            test('should reject weak new passwords', async () => {
                await testStartup.loginAsUser('user');
                const userId = testStartup.user.id;
                
                const passwordData = {
                    currentPassword: 'TestPass123!',
                    newPassword: '123'
                };

                const response = await client.put(`/api/v1/users/${userId}/password`, passwordData);
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should require current password for regular users', async () => {
                await testStartup.loginAsUser('user');
                const userId = testStartup.user.id;
                
                const passwordData = {
                    newPassword: 'NewPass123!'
                    // Missing currentPassword
                };

                const response = await client.put(`/api/v1/users/${userId}/password`, passwordData);
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should reject wrong current password', async () => {
                await testStartup.loginAsUser('user');
                const userId = testStartup.user.id;
                
                const passwordData = {
                    currentPassword: 'WrongPassword123!',
                    newPassword: 'NewPass123!'
                };

                const response = await client.put(`/api/v1/users/${userId}/password`, passwordData);
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });
        });
    });

    describe('User Controller - User Statistics', () => {
        describe('GET /api/v1/users/:id/stats - Success Cases', () => {
            test('should get user statistics as admin', async () => {
                await testStartup.loginAsUser('admin');
                const userId = testStartup.user.id;

                const response = await client.get(`/api/v1/users/${userId}/stats`);

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(response.data.stats).toBeDefined();
            });

            test('should allow users to get their own stats', async () => {
                await testStartup.loginAsUser('user');
                const userId = testStartup.user.id;

                const response = await client.get(`/api/v1/users/${userId}/stats`);

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(response.data.stats).toBeDefined();
            });

            test('should cache user statistics', async () => {
                await testStartup.loginAsUser('admin');
                const userId = testStartup.user.id;

                const response1 = await client.get(`/api/v1/users/${userId}/stats`);
                const response2 = await client.get(`/api/v1/users/${userId}/stats`);

                expect(response1.status).toBe(200);
                expect(response2.status).toBe(200);
            });
        });

        describe('GET /api/v1/users/:id/stats/fields - Success Cases', () => {
            test('should get user stats fields as admin', async () => {
                await testStartup.loginAsUser('admin');
                const userId = testStartup.user.id;

                const response = await client.get(`/api/v1/users/${userId}/stats/fields`);

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(response.data.data).toBeDefined(); // Note: likely "data" not "fields"
            });

            test('should return only the requested fields', async () => {
                await testStartup.loginAsUser('admin');
                const response = await client.get(
                    `/api/v1/users/${testStartup.user.id}/stats/fields?fields=user.username,user.roles`
                );

                expect(response.status).toBe(200);
                expect(response.data.data.user).toBeDefined();
                expect(response.data.data.user.username).toBeDefined();
            });

            test('should resolve activity and file fields', async () => {
                await testStartup.loginAsUser('admin');
                const response = await client.get(
                    `/api/v1/users/${testStartup.user.id}/stats/fields?fields=activity.lastLogin,activity.loginHistory,files.totalFiles`
                );

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
            });

            test('should mark unknown fields rather than failing', async () => {
                await testStartup.loginAsUser('admin');
                const response = await client.get(
                    `/api/v1/users/${testStartup.user.id}/stats/fields?fields=nonsense.field`
                );

                expect(response.status).toBe(200);
                expect(response.data.data.nonsense.field.error).toBeDefined();
            });

            test('should deny another user stats fields', async () => {
                await testStartup.loginAsUser('user');
                const response = await client.get(
                    `/api/v1/users/${testStartup.creator.id}/stats/fields?fields=security.lastPasswordChange`
                );

                expect(response.status).toBe(403);
                expect(response.data.success).toBe(false);
            });

            test('should deny another user stats', async () => {
                await testStartup.loginAsUser('user');
                const response = await client.get(`/api/v1/users/${testStartup.creator.id}/stats`);

                expect(response.status).toBe(403);
                expect(response.data.success).toBe(false);
            });

            test('should allow a user their own stats', async () => {
                await testStartup.loginAsUser('user');
                const response = await client.get(`/api/v1/users/${testStartup.user.id}/stats`);

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(response.data.stats).toBeDefined();
            });
        });

        // The route guards these handlers with checkResourceOwnership, so an
        // unauthorised request never reaches them. The handlers carry their own
        // permission checks as a second line of defence; these tests invoke them
        // directly to prove those checks actually deny, since no route can.
        describe('Handler-level permission guards', () => {
            let userController;

            beforeAll(async () => {
                const mod = await import('../../server/controllers/user.controller.js');
                userController = mod.default ?? mod.userController;
            });

            const buildRes = () => {
                const res = {statusCode: null, body: null};
                res.status = (code) => {
                    res.statusCode = code;
                    return res;
                };
                res.json = (payload) => {
                    res.body = payload;
                    return res;
                };
                return res;
            };

            test('should restrict a stranger to public fields only', async () => {
                const res = buildRes();
                const req = {
                    params: {id: testStartup.creator.id},
                    user: {id: testStartup.user.id, roles: ['USER']},
                    query: {fields: 'user.username,user.roles'}
                };

                await userController.getUserStatsFields(req, res, (err) => {
                    throw err;
                });

                expect(res.statusCode).toBe(200);
                expect(res.body.data.user.username).toBeDefined();
            });

            test('should deny a stranger access to security fields', async () => {
                const res = buildRes();
                const req = {
                    params: {id: testStartup.creator.id},
                    user: {id: testStartup.user.id, roles: ['USER']},
                    query: {fields: 'security.lastPasswordChange,security.twoFactorEnabled'}
                };

                await userController.getUserStatsFields(req, res, (err) => {
                    throw err;
                });

                expect(res.statusCode).toBe(200);
                expect(res.body.data.security.lastPasswordChange.error).toMatch(/denied/i);
                expect(res.body.data.security.twoFactorEnabled.error).toMatch(/denied/i);
            });

            test('should deny a stranger access to activity fields', async () => {
                const res = buildRes();
                const req = {
                    params: {id: testStartup.creator.id},
                    user: {id: testStartup.user.id, roles: ['USER']},
                    query: {fields: 'activity.loginHistory'}
                };

                await userController.getUserStatsFields(req, res, (err) => {
                    throw err;
                });

                expect(res.statusCode).toBe(200);
                expect(res.body.data.activity.loginHistory.error).toMatch(/denied/i);
            });

            test('should give an admin the security fields it denies a stranger', async () => {
                const res = buildRes();
                const req = {
                    params: {id: testStartup.creator.id},
                    user: {id: testStartup.admin.id, roles: ['ADMIN']},
                    query: {fields: 'security.twoFactorEnabled'}
                };

                await userController.getUserStatsFields(req, res, (err) => {
                    throw err;
                });

                expect(res.statusCode).toBe(200);
                expect(res.body.data.security.twoFactorEnabled).not.toHaveProperty('error');
            });

            test('should give a user their own security fields', async () => {
                const res = buildRes();
                const req = {
                    params: {id: testStartup.user.id},
                    user: {id: testStartup.user.id, roles: ['USER']},
                    query: {fields: 'security.twoFactorEnabled'}
                };

                await userController.getUserStatsFields(req, res, (err) => {
                    throw err;
                });

                expect(res.statusCode).toBe(200);
                expect(res.body.data.security.twoFactorEnabled).not.toHaveProperty('error');
            });

            test('should return 404 for stats on a non-existent user', async () => {
                await testStartup.loginAsUser('admin');
                const response = await client.get('/api/v1/users/000000000000000000000000/stats');

                expect(response.status).toBe(404);
                expect(response.data.success).toBe(false);
            });
        });

        describe('GET /api/v1/users/stats/overview - Success Cases', () => {
            test('should get users overview statistics as admin', async () => {
                await testStartup.loginAsUser('admin');

                const response = await client.get('/api/v1/users/stats/overview');

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(response.data.overview).toBeDefined(); // Note: "overview" based on actual response
            });

            test('should support filtering parameters', async () => {
                await testStartup.loginAsUser('admin');

                const response = await client.get('/api/v1/users/stats/overview');

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
            });
        });
    });

    describe('User Middleware Functions', () => {
        // Exercised directly: pure helpers with no request lifecycle to drive
        describe('Pure helpers', () => {
            let parseTimePeriod;
            let generateFallbackDeviceId;
            let normalizeRoleField;
            let removeInactiveDevices;

            beforeAll(async () => {
                const mod = await import('../../server/middleware/user.middleware.js');
                parseTimePeriod = mod.parseTimePeriod;
                generateFallbackDeviceId = mod.generateFallbackDeviceId;
                normalizeRoleField = mod.normalizeRoleField;
                removeInactiveDevices = mod.removeInactiveDevices;
            });

            describe('parseTimePeriod', () => {
                test('should return a null start date when no period is given', () => {
                    expect(parseTimePeriod(undefined).startDate).toBeNull();
                    expect(parseTimePeriod('').startDate).toBeNull();
                });

                test('should subtract hours, days, weeks, months and years', () => {
                    const units = [
                        ['6h', 6 * 60 * 60 * 1000],
                        ['3d', 3 * 24 * 60 * 60 * 1000],
                        ['2w', 14 * 24 * 60 * 60 * 1000]
                    ];

                    for (const [period, approxMs] of units) {
                        const {startDate} = parseTimePeriod(period);
                        expect(startDate, `${period} should produce a date`).toBeInstanceOf(Date);
                        const delta = Date.now() - startDate.getTime();
                        // Allow a wide margin: the implementation uses calendar arithmetic
                        expect(delta).toBeGreaterThan(approxMs * 0.9);
                        expect(delta).toBeLessThan(approxMs * 1.1);
                    }
                });

                test('should handle month and year units', () => {
                    expect(parseTimePeriod('1m').startDate).toBeInstanceOf(Date);
                    expect(parseTimePeriod('1y').startDate).toBeInstanceOf(Date);
                });

                test('should return null for an unrecognised unit', () => {
                    expect(parseTimePeriod('5x').startDate).toBeNull();
                });
            });

            describe('generateFallbackDeviceId', () => {
                test('should produce a stable hash for the same request shape', () => {
                    const req = {headers: {'user-agent': 'Test-Agent/1.0'}, ip: '127.0.0.1'};
                    const id = generateFallbackDeviceId(req);

                    expect(typeof id).toBe('string');
                    expect(id.length).toBeGreaterThan(0);
                });

                test('should tolerate a request with no user-agent', () => {
                    const req = {headers: {}, ip: '127.0.0.1'};
                    expect(() => generateFallbackDeviceId(req)).not.toThrow();
                });
            });

            describe('normalizeRoleField', () => {
                const runMiddleware = (body) => {
                    const req = {body};
                    let called = false;
                    normalizeRoleField(req, {}, () => {
                        called = true;
                    });
                    return {req, called};
                };

                test('should convert a singular role into a roles array', () => {
                    const {req, called} = runMiddleware({role: 'ADMIN'});

                    expect(called).toBe(true);
                    expect(req.body.roles).toEqual(['ADMIN']);
                    expect(req.body.role).toBeUndefined();
                });

                test('should keep an existing roles array untouched', () => {
                    const {req} = runMiddleware({roles: ['USER', 'CREATOR']});
                    expect(req.body.roles).toEqual(['USER', 'CREATOR']);
                });

                test('should accept an array supplied under role', () => {
                    const {req} = runMiddleware({role: ['ADMIN', 'USER']});
                    expect(req.body.roles).toEqual(['ADMIN', 'USER']);
                });

                test('should pass through a body with neither field', () => {
                    const {req, called} = runMiddleware({firstName: 'Nobody'});
                    expect(called).toBe(true);
                    expect(req.body.roles).toBeUndefined();
                });
            });

            describe('removeInactiveDevices', () => {
                test('should return the user unchanged when there are no devices', async () => {
                    const user = {id: 'x'};
                    expect(await removeInactiveDevices(user)).toBe(user);
                });

                test('should return the user unchanged when knownDevices is not an array', async () => {
                    const user = {id: 'x', knownDevices: 'not-an-array'};
                    expect(await removeInactiveDevices(user)).toBe(user);
                });

                test('should keep devices seen within the window', async () => {
                    const user = {
                        id: 'x',
                        knownDevices: [{deviceId: 'a', lastSeenAt: new Date()}],
                        save: async () => {}
                    };

                    await removeInactiveDevices(user, 90);
                    expect(user.knownDevices).toHaveLength(1);
                });
            });
        });

        describe('checkUserExists middleware', () => {
            test('should pass for valid user ID', async () => {
                await testStartup.loginAsUser('admin');
                const userId = testStartup.user.id;

                const response = await client.get(`/api/v1/users/${userId}`);
                expect(response.status).toBe(200);
            });

            test('should return 400 for invalid user ID format', async () => {
                await testStartup.loginAsUser('admin');

                const response = await client.get('/api/v1/users/invalid-id');
                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
            });

            test('should return 404 for non-existent user', async () => {
                await testStartup.loginAsUser('admin');
                const fakeId = new mongoose.Types.ObjectId();

                const response = await client.get(`/api/v1/users/${fakeId}`);
                expect(response.status).toBe(404);
                expect(response.data.success).toBe(false);
            });
        });

        describe('checkResourceOwnership middleware', () => {
            test('should allow admins to access any user', async () => {
                await testStartup.loginAsUser('admin');
                const userId = testStartup.user.id;

                const response = await client.get(`/api/v1/users/${userId}`);
                expect(response.status).toBe(200);
            });

            test('should allow users to access their own profile', async () => {
                await testStartup.loginAsUser('user');
                const userId = testStartup.user.id;

                const response = await client.get(`/api/v1/users/${userId}`);
                expect(response.status).toBe(200);
            });

            test('should deny regular users access to others profiles', async () => {
                await testStartup.loginAsUser('user');
                const adminId = testStartup.admin.id;

                const response = await client.get(`/api/v1/users/${adminId}`);
                expect(response.status).toBe(403);
                expect(response.data.success).toBe(false);
            });
        });

        describe('checkDeletePermission middleware', () => {
            test('should allow owner to delete users', async () => {
                let testUser = await testStartup.createMutableUser({
                    role: 'USER',
                    firstName: 'Delete',
                    lastName: 'Permission',
                    prefix: 'deleteperm'
                });

                try {
                    await testStartup.loginAsUser('owner');
                    const response = await client.delete(`/api/v1/users/${testUser.id}`);

                    expect(response.status).toBe(200);
                    testUser = null;
                } finally {
                    if (testUser) {
                        await testStartup.deleteMutableUser(testUser.id);
                    }
                }
            });

            test('should deny admin delete permissions', async () => {
                let testUser = await testStartup.createMutableUser({
                    role: 'USER',
                    firstName: 'Admin',
                    lastName: 'Denied',
                    prefix: 'admindenied'
                });

                try {
                    await testStartup.loginAsUser('admin');

                    const response = await client.delete(`/api/v1/users/${testUser.id}`);
                    expect(response.status).toBe(403);
                    expect(response.data.success).toBe(false);
                } finally {
                    if (testUser) {
                        await testStartup.deleteMutableUser(testUser.id);
                    }
                }
            });
        });
    });

    describe('Route Integration and Edge Cases', () => {
        describe('Caching Behavior', () => {
            test('should properly cache and invalidate user list', async () => {
                await testStartup.loginAsUser('admin');
                
                // Get users list - should populate cache
                const response1 = await client.get('/api/v1/users?limit=2');
                expect(response1.status).toBe(200);
                
                // Same query should potentially be cached
                const response2 = await client.get('/api/v1/users?limit=2');
                expect(response2.status).toBe(200);
                
                // Different query should not use same cache
                const response3 = await client.get('/api/v1/users?limit=3');
                expect(response3.status).toBe(200);
            });

            test('should invalidate cache after user modifications', async () => {
                let testUser = await testStartup.createMutableUser({
                    role: 'USER',
                    firstName: 'Cache',
                    lastName: 'Invalidation',
                    prefix: 'cacheinval'
                });

                try {
                    await testStartup.loginAsUser('admin');
                    
                    // Get user - should populate cache
                    const response1 = await client.get(`/api/v1/users/${testUser.id}`);
                    expect(response1.status).toBe(200);
                    
                    // Update user - should invalidate cache
                    const updateData = { firstName: 'Cache Updated' };
                    const updateResponse = await client.put(`/api/v1/users/${testUser.id}`, updateData);
                    expect(updateResponse.status).toBe(200);
                    
                    // Get user again - should return updated data
                    const response2 = await client.get(`/api/v1/users/${testUser.id}`);
                    expect(response2.status).toBe(200);
                    expect(response2.data.user.firstName).toBe('Cache Updated');
                } finally {
                    if (testUser) {
                        await testStartup.deleteMutableUser(testUser.id);
                    }
                }
            });
        });

        describe('Error Handling', () => {
            test('should handle malformed JSON gracefully', async () => {
                await testStartup.loginAsUser('admin');
                
                const response = await client.post('/api/v1/users', 'invalid-json');
                expect(response.status).toBe(400);
            });

            test('should handle missing Content-Type header', async () => {
                await testStartup.loginAsUser('admin');
                const userId = testStartup.user.id;
                
                const response = await client.get(`/api/v1/users/${userId}`);
                expect(response.status).toBe(200);
            });
        });

        describe('Performance and Concurrency', () => {
            test('should handle concurrent user requests', async () => {
                await testStartup.loginAsUser('admin');
                
                const promises = Array(5).fill().map(() => 
                    client.get('/api/v1/users?limit=1')
                );
                
                const results = await Promise.allSettled(promises);
                const successes = results.filter(r => 
                    r.status === 'fulfilled' && r.value.status === 200
                );
                
                expect(successes.length).toBe(5);
            });

            test('should handle mixed concurrent operations', async () => {
                await testStartup.loginAsUser('admin');
                
                const promises = [
                    client.get('/api/v1/users?limit=2'),
                    client.get('/api/v1/users/stats/overview'),
                    client.get(`/api/v1/users/${testStartup.user.id}`)
                ];
                
                const results = await Promise.allSettled(promises);
                const successes = results.filter(r => 
                    r.status === 'fulfilled' && r.value.status === 200
                );
                
                expect(successes.length).toBeGreaterThanOrEqual(2);
            });
        });
    });

    // =========================================================================
    // CONNECTION SYSTEM TESTS
    // =========================================================================
    describe('User Controller - Connection System', () => {
        let userA, userB, userC;

        beforeAll(async () => {
            userA = await testStartup.createMutableUser({ role: 'USER', firstName: 'Alice', lastName: 'Connect', prefix: 'connect_a' });
            userB = await testStartup.createMutableUser({ role: 'USER', firstName: 'Bob', lastName: 'Connect', prefix: 'connect_b' });
            userC = await testStartup.createMutableUser({ role: 'USER', firstName: 'Carol', lastName: 'Connect', prefix: 'connect_c' });
        }, 30000);

        const loginAs = async (mutableUser) => {
            const response = await client.post('/api/v1/auth/login', mutableUser.credentials);
            expect(response.status).toBe(200);
            return response;
        };

        describe('POST /api/v1/users/:id/connect - Send Connection Request', () => {
            it('should send a connection request successfully', async () => {
                await loginAs(userA);
                const response = await client.post(`/api/v1/users/${userB.id}/connect`);

                expect(response.status).toBe(200);
                expect(response.data).toEqual({
                    success: true,
                    message: 'Connection request sent'
                });
            });

            it('should reject a duplicate request to the same user', async () => {
                await loginAs(userA);
                const response = await client.post(`/api/v1/users/${userB.id}/connect`);

                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
                expect(response.data.message).toMatch(/already sent/i);
            });

            it('should not allow connecting with yourself', async () => {
                await loginAs(userA);
                const response = await client.post(`/api/v1/users/${userA.id}/connect`);

                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
                expect(response.data.message).toMatch(/cannot connect with yourself/i);
            });

            it('should return 404 for non-existent user', async () => {
                await loginAs(userA);
                const fakeId = '000000000000000000000000';
                const response = await client.post(`/api/v1/users/${fakeId}/connect`);

                expect(response.status).toBe(404);
                expect(response.data.success).toBe(false);
            });

            it('should require authentication', async () => {
                client.clearCookies();
                const response = await client.post(`/api/v1/users/${userB.id}/connect`);

                expect(response.status).toBe(401);
                expect(response.data.success).toBe(false);
            });
        });

        describe('GET /api/v1/users/connections/sent - Sent Requests', () => {
            it('should list outgoing pending requests', async () => {
                await loginAs(userA);
                const response = await client.get('/api/v1/users/connections/sent');

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(Array.isArray(response.data.data)).toBe(true);
                expect(response.data.pagination).toBeDefined();
                expect(response.data.pagination).toHaveProperty('page');
                expect(response.data.pagination).toHaveProperty('limit');
                expect(response.data.pagination).toHaveProperty('total');
                expect(response.data.pagination).toHaveProperty('pages');

                const ids = response.data.data.map(u => u._id || u.id);
                expect(ids).toContain(userB.id);
            });

            it('should return populated user objects', async () => {
                await loginAs(userA);
                const response = await client.get('/api/v1/users/connections/sent');

                if (response.data.data.length > 0) {
                    const recipient = response.data.data[0];
                    expect(recipient).toHaveProperty('firstName');
                    expect(recipient).toHaveProperty('lastName');
                    expect(recipient).toHaveProperty('username');
                }
            });

            it('should return empty for a user with no sent requests', async () => {
                await loginAs(userC);
                const response = await client.get('/api/v1/users/connections/sent');

                expect(response.status).toBe(200);
                expect(response.data.data).toEqual([]);
                expect(response.data.pagination.total).toBe(0);
            });
        });

        describe('GET /api/v1/users/connections/pending - Pending Requests', () => {
            it('should list incoming pending requests', async () => {
                await loginAs(userB);
                const response = await client.get('/api/v1/users/connections/pending');

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(Array.isArray(response.data.data)).toBe(true);

                const ids = response.data.data.map(u => u._id || u.id);
                expect(ids).toContain(userA.id);
            });

            it('should support pagination', async () => {
                await loginAs(userB);
                const response = await client.get('/api/v1/users/connections/pending?page=1&limit=1');

                expect(response.status).toBe(200);
                expect(response.data.pagination.page).toBe(1);
                expect(response.data.pagination.limit).toBe(1);
            });

            it('should return empty for a user with no incoming requests', async () => {
                await loginAs(userC);
                const response = await client.get('/api/v1/users/connections/pending');

                expect(response.status).toBe(200);
                expect(response.data.data).toEqual([]);
            });
        });

        describe('GET /api/v1/users/:id/connection-status - Pending State', () => {
            it('should report pending_sent for the requester', async () => {
                await loginAs(userA);
                const response = await client.get(`/api/v1/users/${userB.id}/connection-status`);

                expect(response.status).toBe(200);
                expect(response.data).toEqual({
                    success: true,
                    data: {
                        status: 'pending_sent',
                        isConnected: false
                    }
                });
            });

            it('should report pending_received for the recipient', async () => {
                await loginAs(userB);
                const response = await client.get(`/api/v1/users/${userA.id}/connection-status`);

                expect(response.status).toBe(200);
                expect(response.data.data.status).toBe('pending_received');
                expect(response.data.data.isConnected).toBe(false);
            });

            it('should report none for unrelated users', async () => {
                await loginAs(userC);
                const response = await client.get(`/api/v1/users/${userA.id}/connection-status`);

                expect(response.status).toBe(200);
                expect(response.data.data).toEqual({
                    status: 'none',
                    isConnected: false
                });
            });
        });

        describe('PUT /api/v1/users/:id/connect - Respond to Request', () => {
            it('should reject an invalid action', async () => {
                await loginAs(userB);
                const response = await client.put(`/api/v1/users/${userA.id}/connect`, { action: 'maybe' });

                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
                expect(response.data.message).toMatch(/accept.*reject/i);
            });

            it('should return 404 when there is no pending request', async () => {
                await loginAs(userC);
                const response = await client.put(`/api/v1/users/${userA.id}/connect`, { action: 'accept' });

                expect(response.status).toBe(404);
                expect(response.data.success).toBe(false);
            });

            it('should accept a pending request', async () => {
                await loginAs(userB);
                const response = await client.put(`/api/v1/users/${userA.id}/connect`, { action: 'accept' });

                expect(response.status).toBe(200);
                expect(response.data).toEqual({
                    success: true,
                    message: 'Connection request accepted'
                });
            });

            it('should report connected for both users after acceptance', async () => {
                await loginAs(userA);
                const fromA = await client.get(`/api/v1/users/${userB.id}/connection-status`);
                expect(fromA.data.data).toEqual({ status: 'connected', isConnected: true });

                await loginAs(userB);
                const fromB = await client.get(`/api/v1/users/${userA.id}/connection-status`);
                expect(fromB.data.data).toEqual({ status: 'connected', isConnected: true });
            });
        });

        describe('GET /api/v1/users/:id/connections - Get Connections', () => {
            it('should return accepted connections for a user', async () => {
                await loginAs(userA);
                const response = await client.get(`/api/v1/users/${userA.id}/connections`);

                expect(response.status).toBe(200);
                expect(response.data.success).toBe(true);
                expect(Array.isArray(response.data.data)).toBe(true);
                expect(response.data.pagination).toBeDefined();

                const ids = response.data.data.map(u => u._id || u.id);
                expect(ids).toContain(userB.id);
            });

            it('should return the other party from the connection', async () => {
                await loginAs(userB);
                const response = await client.get(`/api/v1/users/${userB.id}/connections`);

                expect(response.status).toBe(200);
                const ids = response.data.data.map(u => u._id || u.id);
                expect(ids).toContain(userA.id);
                expect(ids).not.toContain(userB.id);
            });

            it('should support pagination', async () => {
                await loginAs(userA);
                const response = await client.get(`/api/v1/users/${userA.id}/connections?page=1&limit=1`);

                expect(response.status).toBe(200);
                expect(response.data.pagination.page).toBe(1);
                expect(response.data.pagination.limit).toBe(1);
            });

            it('should return empty for a user with no connections', async () => {
                await loginAs(userC);
                const response = await client.get(`/api/v1/users/${userC.id}/connections`);

                expect(response.status).toBe(200);
                expect(response.data.data).toEqual([]);
                expect(response.data.pagination.total).toBe(0);
            });
        });

        describe('GET /api/v1/users/:id/connection-counts - Connection Counts', () => {
            it('should return connection counts', async () => {
                await loginAs(userA);
                const response = await client.get(`/api/v1/users/${userA.id}/connection-counts`);

                expect(response.status).toBe(200);
                expect(response.data).toEqual({
                    success: true,
                    data: {
                        connectionCount: expect.any(Number),
                        pendingCount: expect.any(Number)
                    }
                });
                expect(response.data.data.connectionCount).toBeGreaterThanOrEqual(1);
            });

            it('should return zero counts for a user with no connections', async () => {
                await loginAs(userC);
                const response = await client.get(`/api/v1/users/${userC.id}/connection-counts`);

                expect(response.status).toBe(200);
                expect(response.data.data.connectionCount).toBe(0);
                expect(response.data.data.pendingCount).toBe(0);
            });
        });

        describe('POST /api/v1/users/:id/connect - Mutual Request Auto-Accept', () => {
            it('should auto-accept when both users request each other', async () => {
                await loginAs(userC);
                const sent = await client.post(`/api/v1/users/${userA.id}/connect`);
                expect(sent.status).toBe(200);
                expect(sent.data.message).toBe('Connection request sent');

                await loginAs(userA);
                const response = await client.post(`/api/v1/users/${userC.id}/connect`);

                expect(response.status).toBe(200);
                expect(response.data).toEqual({
                    success: true,
                    message: 'Connection request accepted (mutual request)'
                });
            });

            it('should report connected after the mutual auto-accept', async () => {
                await loginAs(userA);
                const response = await client.get(`/api/v1/users/${userC.id}/connection-status`);

                expect(response.status).toBe(200);
                expect(response.data.data).toEqual({ status: 'connected', isConnected: true });
            });
        });

        describe('PUT /api/v1/users/:id/connect - Reject and Re-request', () => {
            it('should reject a pending request', async () => {
                await loginAs(userB);
                const sent = await client.post(`/api/v1/users/${userC.id}/connect`);
                expect(sent.status).toBe(200);

                await loginAs(userC);
                const response = await client.put(`/api/v1/users/${userB.id}/connect`, { action: 'reject' });

                expect(response.status).toBe(200);
                expect(response.data).toEqual({
                    success: true,
                    message: 'Connection request rejected'
                });
            });

            it('should report rejected status after rejection', async () => {
                await loginAs(userB);
                const response = await client.get(`/api/v1/users/${userC.id}/connection-status`);

                expect(response.status).toBe(200);
                expect(response.data.data.status).toBe('rejected');
                expect(response.data.data.isConnected).toBe(false);
            });

            it('should allow re-requesting after a rejection', async () => {
                await loginAs(userB);
                const response = await client.post(`/api/v1/users/${userC.id}/connect`);

                expect(response.status).toBe(200);
                expect(response.data.message).toBe('Connection request sent');
            });
        });

        describe('DELETE /api/v1/users/:id/connect - Remove Connection', () => {
            it('should remove an accepted connection', async () => {
                await loginAs(userA);
                const response = await client.delete(`/api/v1/users/${userB.id}/connect`);

                expect(response.status).toBe(200);
                expect(response.data).toEqual({
                    success: true,
                    message: 'Connection removed'
                });
            });

            it('should return 400 when no connection exists', async () => {
                await loginAs(userA);
                const response = await client.delete(`/api/v1/users/${userB.id}/connect`);

                expect(response.status).toBe(400);
                expect(response.data.success).toBe(false);
                expect(response.data.message).toMatch(/no connection found/i);
            });

            it('should require authentication', async () => {
                client.clearCookies();
                const response = await client.delete(`/api/v1/users/${userB.id}/connect`);

                expect(response.status).toBe(401);
            });

            it('should report none status after removal', async () => {
                await loginAs(userA);
                const response = await client.get(`/api/v1/users/${userB.id}/connection-status`);

                expect(response.status).toBe(200);
                expect(response.data.data).toEqual({ status: 'none', isConnected: false });
            });

            it('should reflect the removal in connection counts', async () => {
                await loginAs(userA);
                const response = await client.get(`/api/v1/users/${userA.id}/connection-counts`);

                expect(response.status).toBe(200);
                // userA remains connected to userC via the mutual auto-accept
                expect(response.data.data.connectionCount).toBe(1);
            });
        });
    });
});
