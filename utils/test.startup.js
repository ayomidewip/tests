/**
 * Test Startup Class - Handles all test server and user management
 * This class manages server startup/cleanup and creates all user types with tokens
 */

// Load environment variables from .env.test file FIRST
const path = require('path');
require('dotenv').config({
    path: path.join(__dirname, '..', '.env.test')
});

const ApiClient = require('./api.client');
const { Server } = require('../../server/server.js');
const mongoose = require('mongoose');

class TestStartup {
    constructor() {
        this.serverInstance = null;
        this.baseURL = null;
        this.port = this.getRandomPort(); // Random port from allowed range
        
        // User objects with tokens
        this.owner = null;
        this.admin = null;
        this.superCreator = null;
        this.creator = null;
        this.user = null;
        
        // Default API client with admin token
        this.client = null;
        
        // Mutable test users for operations that modify data
        this.mutableUsers = new Map(); // Store created mutable users
        this.mutableUserCounter = 0; // Counter for unique user generation
    }

    /**
     * Get a random port from the allowed test port range
     */
    getRandomPort() {
        const minPort = parseInt(process.env.PORT_RANGE_MIN) || 8380;
        const maxPort = parseInt(process.env.PORT_RANGE_MAX) || 8389;
        return Math.floor(Math.random() * (maxPort - minPort + 1)) + minPort;
    }

    /**
     * Initialize everything - start server and create all users
     */
    async initialize() {
        await this.startServer();
        await this.createAllUsers();
        this.setupDefaultClient();
        return this;
    }

    /**
     * Start the test server
     */
    async startServer() {
        // Override the PORT environment variable for this test instance
        const originalPort = process.env.PORT;
        process.env.PORT = this.port.toString();
        
        const server = new Server({ port: this.port, logLevel: 'error' });
        await server.start();
        this.serverInstance = { server, port: this.port };
        this.baseURL = `http://localhost:${this.port}`;
        
        // Restore original PORT (though not strictly necessary in tests)
        if (originalPort) {
            process.env.PORT = originalPort;
        }
    }

    /**
     * Create all test users and extract their tokens
     */
    async createAllUsers() {
        // Wait a moment for server to be fully ready
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        const client = new ApiClient(this.baseURL);
        
        // Use timestamp to make emails unique for each test run
        const timestamp = Date.now().toString().slice(-6); // Last 6 digits
        const randomStr = Math.random().toString(36).substring(2, 4);
        
        try {
            console.log(`Creating test users on ${this.baseURL}`);
            
            // Step 1: Create OWNER user directly in database to bootstrap permissions
            const bcrypt = require('bcryptjs');
            const User = require('../../server/models/user.model');
            
            console.log('Creating OWNER user directly in database to bootstrap permissions');
            const ownerUser = new User({
                firstName: 'Owner',
                lastName: 'Test',
                username: `owner${timestamp}${randomStr}`,
                email: `owner${timestamp}${randomStr}@test.com`,
                password: await bcrypt.hash('TestPass123!', 12),
                roles: ['OWNER'],
                emailVerified: true,
                active: true
            });
            await ownerUser.save();

            // Login to get proper JWT token
            const loginResponse = await client.post('/api/v1/auth/login', {
                identifier: ownerUser.username,
                password: 'TestPass123!'
            });
            
            if (loginResponse?.status === 200 && loginResponse.data?.success) {
                const ownerData = loginResponse.data;
                this.owner = {
                    ...ownerData.user,
                    token: ownerData.authentication.accessToken,
                    refreshToken: ownerData.authentication.refreshToken,
                    credentials: { identifier: ownerUser.username, password: 'TestPass123!' }
                };
                console.log('✅ OWNER user created and authenticated successfully');
            } else {
                throw new Error('Failed to authenticate OWNER user');
            }

            // Set owner token for creating other users
            client.setToken(this.owner.token);

            // Create ADMIN user
            const adminData = {
                firstName: 'Admin',
                lastName: 'User',
                username: `admin${timestamp}${randomStr}`,
                email: `admin${timestamp}${randomStr}@test.com`,
                password: 'TestPass123!',
                roles: ['ADMIN']
            };
            
            const adminResponse = await client.post('/api/v1/auth/signup', adminData);
            this.admin = {
                ...adminResponse.data.user,
                token: adminResponse.data.authentication.accessToken,
                refreshToken: adminResponse.data.authentication.refreshToken,
                credentials: { identifier: adminData.username, password: adminData.password }
            };

            // Create SUPER_CREATOR user
            const superCreatorData = {
                firstName: 'Super',
                lastName: 'Creator',
                username: `super${timestamp}${randomStr}`,
                email: `super${timestamp}${randomStr}@test.com`,
                password: 'TestPass123!',
                roles: ['SUPER_CREATOR']
            };
            
            const superCreatorResponse = await client.post('/api/v1/auth/signup', superCreatorData);
            this.superCreator = {
                ...superCreatorResponse.data.user,
                token: superCreatorResponse.data.authentication.accessToken,
                refreshToken: superCreatorResponse.data.authentication.refreshToken,
                credentials: { identifier: superCreatorData.username, password: superCreatorData.password }
            };

            // Create CREATOR user
            const creatorData = {
                firstName: 'Creator',
                lastName: 'User',
                username: `creator${timestamp}${randomStr}`,
                email: `creator${timestamp}${randomStr}@test.com`,
                password: 'TestPass123!',
                roles: ['CREATOR']
            };
            
            const creatorResponse = await client.post('/api/v1/auth/signup', creatorData);
            this.creator = {
                ...creatorResponse.data.user,
                token: creatorResponse.data.authentication.accessToken,
                refreshToken: creatorResponse.data.authentication.refreshToken,
                credentials: { identifier: creatorData.username, password: creatorData.password }
            };

            // Create regular USER
            const userData = {
                firstName: 'Regular',
                lastName: 'User',
                username: `user${timestamp}${randomStr}`,
                email: `user${timestamp}${randomStr}@test.com`,
                password: 'TestPass123!',
                roles: ['USER']
            };
            
            const userResponse = await client.post('/api/v1/auth/signup', userData);
            this.user = {
                ...userResponse.data.user,
                token: userResponse.data.authentication.accessToken,
                refreshToken: userResponse.data.authentication.refreshToken,
                credentials: { identifier: userData.username, password: userData.password }
            };

        } catch (error) {
            console.error('Failed to create test users:', error.message);
            console.error('Error details:', {
                status: error.response?.status,
                statusText: error.response?.statusText,
                data: error.response?.data,
                url: error.config?.url,
                method: error.config?.method
            });
            throw error;
        }
    }

    /**
     * Setup default API client
     */
    setupDefaultClient() {
        this.client = new ApiClient(this.baseURL);
    }

    /**
     * Get the main client (reusable)
     */
    getClient() {
        return this.client;
    }

    /**
     * Get token for a specific user type
     */
    getTokenForUser(userType) {
        const user = this[userType];
        if (!user) {
            throw new Error(`User type '${userType}' not found`);
        }
        return user.token;
    }

    /**
     * Set token on the main client
     */
    setClientToken(token) {
        this.client.setToken(token);
    }

    /**
     * Clear token from the main client (for public endpoints)
     */
    clearClientToken() {
        this.client.setToken(null);
    }

    /**
     * Create a mutable test user that can be modified/deleted without affecting main users
     * @param {Object} options - User creation options
     * @param {string} options.role - User role (USER, CREATOR, SUPER_CREATOR, ADMIN)
     * @param {string} options.firstName - Optional first name
     * @param {string} options.lastName - Optional last name
     * @param {string} options.prefix - Optional username/email prefix
     * @param {Object} options.additionalData - Any additional user data
     * @returns {Object} - Created user object with token and credentials
     */
    async createMutableUser(options = {}) {
        const {
            role = 'USER',
            firstName = 'Mutable',
            lastName = 'User',
            prefix = 'mutable',
            additionalData = {}
        } = options;

        this.mutableUserCounter++;
        const timestamp = Date.now().toString().slice(-6);
        const userSuffix = `${this.mutableUserCounter}_${timestamp}`;
        
        const userData = {
            firstName: firstName,
            lastName: lastName,
            username: `${prefix}${userSuffix}`,
            email: `${prefix}${userSuffix}@test.com`,
            password: 'MutablePass123!',
            roles: [role],
            ...additionalData
        };

        try {
            // Use owner token to create user with any role
            const client = new ApiClient(this.baseURL);
            client.setToken(this.owner.token);
            
            const response = await client.post('/api/v1/auth/signup', userData);
            
            const mutableUser = {
                id: response.data.user.id,
                ...response.data.user,
                token: response.data.authentication.accessToken,
                refreshToken: response.data.authentication.refreshToken,
                credentials: { 
                    identifier: userData.username, 
                    password: userData.password 
                },
                originalData: userData,
                createdAt: new Date(),
                mutable: true
            };

            // Store in mutable users map
            this.mutableUsers.set(mutableUser.id, mutableUser);
            
            console.log(`✅ Created mutable user: ${mutableUser.username} (${role}) with ID: ${mutableUser.id}`);
            return mutableUser;
        } catch (error) {
            console.error(`❌ Failed to create mutable user:`, error.message);
            throw error;
        }
    }

    /**
     * Create multiple mutable users at once
     * @param {Array} userConfigs - Array of user configuration objects
     * @returns {Array} - Array of created user objects
     */
    async createMultipleMutableUsers(userConfigs) {
        const users = [];
        for (const config of userConfigs) {
            const user = await this.createMutableUser(config);
            users.push(user);
        }
        return users;
    }

    /**
     * Get a mutable user by ID
     * @param {string} userId - User ID
     * @returns {Object|null} - User object or null if not found
     */
    getMutableUser(userId) {
        return this.mutableUsers.get(userId) || null;
    }

    /**
     * Get all mutable users
     * @returns {Array} - Array of all mutable users
     */
    getAllMutableUsers() {
        return Array.from(this.mutableUsers.values());
    }

    /**
     * Get mutable users by role
     * @param {string} role - Role to filter by
     * @returns {Array} - Array of users with specified role
     */
    getMutableUsersByRole(role) {
        return this.getAllMutableUsers().filter(user => 
            user.roles && user.roles.includes(role)
        );
    }

    /**
     * Update a mutable user's data
     * @param {string} userId - User ID
     * @param {Object} updateData - Data to update
     * @returns {Object} - Updated user object
     */
    async updateMutableUser(userId, updateData) {
        const user = this.mutableUsers.get(userId);
        if (!user) {
            throw new Error(`Mutable user with ID ${userId} not found`);
        }

        try {
            const client = new ApiClient(this.baseURL);
            client.setToken(this.admin.token); // Use admin token for updates
            
            const response = await client.put(`/api/v1/users/${userId}`, updateData);
            
            // Update stored user data
            const updatedUser = {
                ...user,
                ...response.data.user,
                lastUpdated: new Date()
            };
            
            this.mutableUsers.set(userId, updatedUser);
            
            console.log(`✅ Updated mutable user: ${updatedUser.username}`);
            return updatedUser;
        } catch (error) {
            console.error(`❌ Failed to update mutable user ${userId}:`, error.message);
            throw error;
        }
    }

    /**
     * Delete a mutable user
     * @param {string} userId - User ID to delete
     * @returns {boolean} - Success status
     */
    async deleteMutableUser(userId) {
        const user = this.mutableUsers.get(userId);
        if (!user) {
            console.warn(`Mutable user with ID ${userId} not found for deletion`);
            return false;
        }

        try {
            const client = new ApiClient(this.baseURL);
            client.setToken(this.admin.token); // Use admin token for deletion
            
            await client.delete(`/api/v1/users/${userId}`);
            
            // Remove from stored users
            this.mutableUsers.delete(userId);
            
            console.log(`✅ Deleted mutable user: ${user.username} (${userId})`);
            return true;
        } catch (error) {
            console.error(`❌ Failed to delete mutable user ${userId}:`, error.message);
            // Remove from map even if API call failed (user might already be deleted)
            this.mutableUsers.delete(userId);
            return false;
        }
    }

    /**
     * Clean up all mutable users
     * @returns {Object} - Cleanup results
     */
    async cleanupAllMutableUsers() {
        const results = {
            total: this.mutableUsers.size,
            deleted: 0,
            failed: 0,
            errors: []
        };

        console.log(`🧹 Cleaning up ${results.total} mutable users...`);

        const userIds = Array.from(this.mutableUsers.keys());
        
        for (const userId of userIds) {
            try {
                const success = await this.deleteMutableUser(userId);
                if (success) {
                    results.deleted++;
                } else {
                    results.failed++;
                }
            } catch (error) {
                results.failed++;
                results.errors.push({ userId, error: error.message });
            }
        }

        console.log(`✅ Mutable user cleanup completed: ${results.deleted} deleted, ${results.failed} failed`);
        return results;
    }

    /**
     * Create a client authenticated as a specific mutable user
     * @param {string} userId - Mutable user ID
     * @returns {ApiClient} - Authenticated API client
     */
    getClientForMutableUser(userId) {
        const user = this.mutableUsers.get(userId);
        if (!user) {
            throw new Error(`Mutable user with ID ${userId} not found`);
        }

        const client = new ApiClient(this.baseURL);
        client.setToken(user.token);
        return client;
    }

    /**
     * Refresh token for a mutable user
     * @param {string} userId - User ID
     * @returns {Object} - Updated user object with new tokens
     */
    async refreshMutableUserToken(userId) {
        const user = this.mutableUsers.get(userId);
        if (!user) {
            throw new Error(`Mutable user with ID ${userId} not found`);
        }

        try {
            const client = new ApiClient(this.baseURL);
            const response = await client.post('/api/v1/auth/refresh-token', {
                token: user.refreshToken
            });

            const updatedUser = {
                ...user,
                token: response.data.authentication.accessToken,
                refreshToken: response.data.authentication.refreshToken,
                lastTokenRefresh: new Date()
            };

            this.mutableUsers.set(userId, updatedUser);
            
            console.log(`🔄 Refreshed token for mutable user: ${user.username}`);
            return updatedUser;
        } catch (error) {
            console.error(`❌ Failed to refresh token for mutable user ${userId}:`, error.message);
            throw error;
        }
    }

    /**
     * Create test data for mutable user testing
     * @param {Object} options - Options for test data creation
     * @returns {Object} - Test data templates
     */
    createMutableTestData(options = {}) {
        const timestamp = Date.now().toString().slice(-6);
        const randomId = Math.random().toString(36).substring(2, 8);
        
        return {
            // User profiles for testing different scenarios
            profiles: {
                basicUser: {
                    role: 'USER',
                    firstName: 'Basic',
                    lastName: 'TestUser',
                    prefix: 'basic'
                },
                contentCreator: {
                    role: 'CREATOR',
                    firstName: 'Content',
                    lastName: 'Creator',
                    prefix: 'creator'
                },
                superCreator: {
                    role: 'SUPER_CREATOR',
                    firstName: 'Super',
                    lastName: 'Creator',
                    prefix: 'super'
                },
                adminUser: {
                    role: 'ADMIN',
                    firstName: 'Admin',
                    lastName: 'TestUser',
                    prefix: 'admin'
                }
            },
            
            // File data for testing
            files: {
                textFile: {
                    filename: `test_${timestamp}_${randomId}.txt`,
                    content: 'This is test file content for mutable user testing',
                    mimeType: 'text/plain'
                },
                jsonFile: {
                    filename: `data_${timestamp}_${randomId}.json`,
                    content: JSON.stringify({ test: true, timestamp, randomId }),
                    mimeType: 'application/json'
                },
                largeFile: {
                    filename: `large_${timestamp}_${randomId}.txt`,
                    content: 'A'.repeat(1000), // 1KB of 'A' characters
                    mimeType: 'text/plain'
                }
            },
            
            // Update scenarios for testing user modifications
            updateScenarios: {
                nameChange: {
                    firstName: 'Updated',
                    lastName: 'Name'
                },
                emailChange: {
                    email: `updated_${timestamp}@test.com`
                },
                profileUpdate: {
                    firstName: 'Complete',
                    lastName: 'Update',
                    profilePhoto: 'updated-avatar.jpg'
                }
            },
            
            // Batch operations data
            batchData: {
                multipleUsers: [
                    { role: 'USER', firstName: 'Batch1', lastName: 'User', prefix: 'batch1' },
                    { role: 'USER', firstName: 'Batch2', lastName: 'User', prefix: 'batch2' },
                    { role: 'CREATOR', firstName: 'Batch3', lastName: 'Creator', prefix: 'batch3' }
                ]
            },
            
            // Metadata
            metadata: {
                timestamp,
                randomId,
                testSuite: options.testSuite || 'unknown',
                description: options.description || 'Mutable test data'
            }
        };
    }

    /**
     * Execute operations with temporary mutable users
     * Automatically creates users, runs operations, and cleans up
     * @param {Array} userConfigs - Array of user configurations
     * @param {Function} operations - Async function to run with created users
     * @returns {*} - Result of operations function
     */
    async withTemporaryMutableUsers(userConfigs, operations) {
        const createdUsers = [];
        
        try {
            // Create all requested users
            for (const config of userConfigs) {
                const user = await this.createMutableUser(config);
                createdUsers.push(user);
            }
            
            // Run the operations with the created users
            const result = await operations(createdUsers);
            
            return result;
        } finally {
            // Always clean up created users
            for (const user of createdUsers) {
                await this.deleteMutableUser(user.id);
            }
        }
    }

    /**
     * Get helper to use client with specific user token
     */
    withUser(userType, callback) {
        const originalToken = this.client.token;
        const userToken = this.getTokenForUser(userType);
        this.client.setToken(userToken);
        const result = callback(this.client);
        this.client.setToken(originalToken);
        return result;
    }

    /**
     * Helper to use client without token (public)
     */
    withPublic(callback) {
        const originalToken = this.client.token;
        this.client.setToken(null);
        const result = callback(this.client);
        this.client.setToken(originalToken);
        return result;
    }

    /**
     * Test user permissions across different roles
     */
    async testUserPermissions(endpoint, method = 'get', data = null) {
        const results = {};
        const userTypes = ['owner', 'admin', 'superCreator', 'creator', 'user'];

        for (const userType of userTypes) {
            const client = this.getClientForUser(userType);
            try {
                let response;
                switch (method.toLowerCase()) {
                    case 'post':
                        response = await client.post(endpoint, data);
                        break;
                    case 'put':
                        response = await client.put(endpoint, data);
                        break;
                    case 'delete':
                        response = await client.delete(endpoint);
                        break;
                    default:
                        response = await client.get(endpoint);
                }
                results[userType] = {
                    success: true,
                    status: response.status,
                    data: response.data
                };
            } catch (error) {
                results[userType] = {
                    success: false,
                    status: error.response?.status || 500,
                    error: error.response?.data || error.message
                };
            }
        }

        return results;
    }

    /**
     * Helper to create test file data
     */
    createTestFileData(filename = 'test.txt', content = 'Test file content') {
        return {
            filename,
            content,
            mimeType: 'text/plain',
            metadata: {
                description: `Test file: ${filename}`,
                tags: ['test', 'automation']
            }
        };
    }

    /**
     * Cleanup - stop server and clean resources
     */
    async cleanup() {
        try {
            // Clean up all mutable users first (they need to be deleted properly via API)
            if (this.mutableUsers && this.mutableUsers.size > 0) {
                console.log('🧹 Cleaning up mutable users before shutdown...');
                await this.cleanupAllMutableUsers();
            }

            // Clean database if flag is enabled - do this IMMEDIATELY while server is still running
            if (process.env.DB_CLEANUP === 'true') {
                console.log('🗄️ Cleaning database as DB_CLEANUP is enabled...');
                // Do database cleanup before ANY server shutdown activities
                await this.performImmediateDatabaseCleanup();
            }

            // Gracefully stop cache operations before server shutdown
            await this.stopCacheOperations();

            // Stop server (this will close database and Redis connections)
            if (this.serverInstance && this.serverInstance.server) {
                await this.serverInstance.server.stop();
            }
            
            // Reset all properties
            this.serverInstance = null;
            this.baseURL = null;
            this.owner = null;
            this.admin = null;
            this.superCreator = null;
            this.creator = null;
            this.user = null;
            this.client = null;
        } catch (error) {
            console.error('❌ Error during cleanup:', error.message);
            // Don't throw - we want cleanup to be as graceful as possible
        }
    }

    /**
     * Perform immediate database cleanup before any server shutdown begins
     */
    async performImmediateDatabaseCleanup() {
        if (process.env.DB_CLEANUP !== 'true') {
            return;
        }

        try {
            // First try to use the server's database connection
            let dbConnection = null;
            
            console.log('🔍 Server instance debug info:');
            console.log('   - serverInstance exists:', !!this.serverInstance);
            console.log('   - serverInstance.server exists:', !!this.serverInstance?.server);
            console.log('   - getDbConnection method exists:', typeof this.serverInstance?.server?.getDbConnection);
            
            if (this.serverInstance && this.serverInstance.server && this.serverInstance.server.getDbConnection) {
                dbConnection = this.serverInstance.server.getDbConnection();
                console.log('   - dbConnection object:', !!dbConnection);
                console.log('   - dbConnection type:', typeof dbConnection);
                console.log('   - dbConnection.readyState:', dbConnection?.readyState);
                console.log('   - Global mongoose.connection.readyState:', mongoose.connection.readyState);
                console.log(`🔍 Using server's database connection (readyState: ${dbConnection ? dbConnection.readyState : 'null'})`);
            } else {
                // Fallback to global mongoose connection
                dbConnection = mongoose.connection;
                console.log(`🔍 Using global mongoose connection (readyState: ${dbConnection.readyState})`);
            }
            
            if (dbConnection && dbConnection.readyState === 1) {
                // We have an active connection, proceed with cleanup
                const collections = await dbConnection.db.collections();
                
                console.log(`🗑️ Dropping ${collections.length} collections immediately...`);
                
                let dropped = 0;
                for (const collection of collections) {
                    try {
                        await collection.drop();
                        console.log(`   ✅ Dropped collection: ${collection.collectionName}`);
                        dropped++;
                    } catch (error) {
                        // Collection might not exist, ignore the error
                        if (error.code !== 26) { // NamespaceNotFound
                            console.warn(`   ⚠️ Warning dropping collection ${collection.collectionName}:`, error.message);
                        }
                    }
                }
                
                console.log(`✅ Database cleanup completed: ${dropped}/${collections.length} collections dropped`);
            } else {
                console.error('❌ Database connection not available for cleanup!');
                console.error(`   Connection state: ${dbConnection ? dbConnection.readyState : 'null'}`);
                console.error('   Database cleanup cannot proceed - test data will remain!');
                
                // This is a critical issue that should be addressed
                throw new Error('Database cleanup failed: No active connection');
            }
        } catch (error) {
            console.error('❌ Critical error during database cleanup:', error.message);
            throw error; // Re-throw to signal this is a serious issue
        }
    }

    /**
     * Stop cache operations and services before server shutdown
     * This prevents Redis cache errors when the server is closed
     */
    async stopCacheOperations() {
        try {
            console.log('🔄 Stopping cache operations...');
            
            // Stop any active cache cleanup services
            try {
                // Access the server's cache cleanup service if available
                if (this.serverInstance && this.serverInstance.server) {
                    // Try to get access to the cache cleanup service through the server
                    const serverConfig = this.serverInstance.server.getConfig();
                    if (serverConfig && serverConfig.cacheEnabled) {
                        console.log('   ⏹️ Stopping cache cleanup services...');
                        // The server's stop() method will handle this, but we log it for clarity
                    }
                }
            } catch (error) {
                console.warn('   ⚠️ Could not stop cache cleanup service:', error.message);
            }

            // Wait a moment to allow any in-flight cache operations to complete
            await new Promise(resolve => setTimeout(resolve, 100));

            console.log('✅ Cache operations stopped');
        } catch (error) {
            console.warn('⚠️ Warning during cache operations stop:', error.message);
        }
    }

    /**
     * Clean the database by dropping all collections
     * Only runs if DB_CLEANUP environment variable is set to 'true'
     */
    async cleanDatabase() {
        if (process.env.DB_CLEANUP !== 'true') {
            return;
        }

        try {
            // First try to use the server's database connection
            let dbConnection = null;
            
            if (this.serverInstance && this.serverInstance.server && this.serverInstance.server.getDbConnection) {
                dbConnection = this.serverInstance.server.getDbConnection();
                console.log(`🔍 Using server's database connection (readyState: ${dbConnection ? dbConnection.readyState : 'null'})`);
            } else {
                // Fallback to global mongoose connection
                dbConnection = mongoose.connection;
                console.log(`🔍 Using global mongoose connection (readyState: ${dbConnection.readyState})`);
            }
            
            if (dbConnection && dbConnection.readyState === 1) {
                const collections = await dbConnection.db.collections();
                
                console.log(`🗑️ Dropping ${collections.length} collections...`);
                
                for (const collection of collections) {
                    try {
                        await collection.drop();
                        console.log(`   ✅ Dropped collection: ${collection.collectionName}`);
                    } catch (error) {
                        // Collection might not exist, ignore the error
                        if (error.code !== 26) { // NamespaceNotFound
                            console.warn(`   ⚠️ Warning dropping collection ${collection.collectionName}:`, error.message);
                        }
                    }
                }
                
                console.log('✅ Database cleanup completed successfully');
            } else {
                console.log('ℹ️ Database connection not available, skipping cleanup');
            }
        } catch (error) {
            console.error('❌ Error during database cleanup:', error.message);
            // Don't throw - we don't want cleanup failures to break tests
        }
    }

    /**
     /**
     * Clean specific collections from the database
     * @param {Array<string>} collectionNames - Array of collection names to clean
     */
    async cleanCollections(collectionNames = []) {
        if (!Array.isArray(collectionNames) || collectionNames.length === 0) {
            console.warn('⚠️ No collections specified for cleanup');
            return;
        }

        try {
            // First try to use the server's database connection
            let dbConnection = null;
            
            if (this.serverInstance && this.serverInstance.server && this.serverInstance.server.getDbConnection) {
                dbConnection = this.serverInstance.server.getDbConnection();
            } else {
                // Fallback to global mongoose connection
                dbConnection = mongoose.connection;
            }
            
            if (dbConnection && dbConnection.readyState === 1) {
                console.log(`🗑️ Cleaning ${collectionNames.length} specific collections...`);
                
                for (const collectionName of collectionNames) {
                    try {
                        const collection = dbConnection.db.collection(collectionName);
                        await collection.drop();
                        console.log(`   ✅ Dropped collection: ${collectionName}`);
                    } catch (error) {
                        if (error.code !== 26) { // NamespaceNotFound
                            console.warn(`   ⚠️ Warning dropping collection ${collectionName}:`, error.message);
                        } else {
                            console.log(`   ℹ️ Collection ${collectionName} doesn't exist, skipping`);
                        }
                    }
                }
                
                console.log('✅ Selective collection cleanup completed');
            } else {
                console.log('ℹ️ Database not connected, skipping collection cleanup');
            }
        } catch (error) {
            console.error('❌ Error during selective collection cleanup:', error.message);
        }
    }

    /**
     * Reset database to clean state (alternative to full cleanup)
     * Removes all documents but keeps collections and indexes
     */
    async resetDatabase() {
        try {
            // First try to use the server's database connection
            let dbConnection = null;
            
            if (this.serverInstance && this.serverInstance.server && this.serverInstance.server.getDbConnection) {
                dbConnection = this.serverInstance.server.getDbConnection();
            } else {
                // Fallback to global mongoose connection
                dbConnection = mongoose.connection;
            }
            
            if (dbConnection && dbConnection.readyState === 1) {
                const collections = await dbConnection.db.collections();
                
                console.log(`🔄 Resetting ${collections.length} collections (clearing documents)...`);
                
                for (const collection of collections) {
                    try {
                        const result = await collection.deleteMany({});
                        console.log(`   ✅ Cleared ${result.deletedCount} documents from: ${collection.collectionName}`);
                    } catch (error) {
                        console.warn(`   ⚠️ Warning clearing collection ${collection.collectionName}:`, error.message);
                    }
                }
                
                console.log('✅ Database reset completed successfully');
            } else {
                console.log('ℹ️ Database not connected, skipping reset');
            }
        } catch (error) {
            console.error('❌ Error during database reset:', error.message);
        }
    }

    /**
     * Get all users object for easy access
     */
    getAllUsers() {
        return {
            owner: this.owner,
            admin: this.admin,
            superCreator: this.superCreator,
            creator: this.creator,
            user: this.user
        };
    }

    /**
     * Get server info
     */
    getServerInfo() {
        return {
            baseURL: this.baseURL,
            port: this.port,
            serverInstance: this.serverInstance
        };
    }
}

module.exports = TestStartup;
