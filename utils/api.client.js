/**
 * Simple API Client for Tests
 */

const axios = require('axios');

class ApiClient {
    constructor(baseURL, token = null) {
        const headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Origin': baseURL,
            'User-Agent': 'Test-Client/1.0'
        };
        
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        
        this.client = axios.create({
            baseURL,
            headers,
            timeout: 10000
        });
    }

    setToken(token) {
        if (token) {
            this.client.defaults.headers['Authorization'] = `Bearer ${token}`;
        } else {
            delete this.client.defaults.headers['Authorization'];
        }
    }

    clearToken() {
        delete this.client.defaults.headers['Authorization'];
    }

    async get(url) {
        try {
            return await this.client.get(url);
        } catch (error) {
            return error.response;
        }
    }

    async post(url, data) {
        try {
            return await this.client.post(url, data);
        } catch (error) {
            return error.response;
        }
    }

    async put(url, data) {
        try {
            return await this.client.put(url, data);
        } catch (error) {
            return error.response;
        }
    }

    async delete(url) {
        try {
            return await this.client.delete(url);
        } catch (error) {
            return error.response;
        }
    }
}

module.exports = ApiClient;
