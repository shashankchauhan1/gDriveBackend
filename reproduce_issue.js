
import fs from 'fs';

const API_URL = 'http://localhost:7500';
const LOG_FILE = 'debug_output.txt';

function log(msg) {
    console.log(msg);
    fs.appendFileSync(LOG_FILE, msg + '\n');
}

async function testBackend() {
    fs.writeFileSync(LOG_FILE, 'Starting Debug Session\n');
    log('Testing Backend Connectivity...');
    try {
        const res = await fetch(`${API_URL}/api/test`);
        if (!res.ok) {
            throw new Error(`Health Check Failed: ${res.status} ${res.statusText}`);
        }
        const data = await res.json();
        log('✅ Health Check Passed: ' + JSON.stringify(data));
    } catch (error) {
        log('❌ Health Check Failed: ' + error.message);
        return; // Stop if health check fails
    }

    log('\nTesting Login...');
    try {
        const testUser = {
            username: 'debug_user_' + Date.now(),
            email: `debug_${Date.now()}@test.com`,
            password: 'password123'
        };

        log('Registering test user: ' + testUser.username);
        const regRes = await fetch(`${API_URL}/api/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(testUser)
        });

        if (regRes.ok) {
            log('✅ Registration Successful');
        } else {
            const errData = await regRes.json();
            log('❌ Registration Failed: ' + regRes.status + ' ' + JSON.stringify(errData, null, 2));
        }

        log('Logging in with test user...');
        const loginRes = await fetch(`${API_URL}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email: testUser.email,
                password: testUser.password
            })
        });

        if (loginRes.ok) {
            const loginData = await loginRes.json();
            if (loginData.token) {
                log('✅ Login Successful! Token received.');
            } else {
                log('❌ Login Failed: No token in response ' + JSON.stringify(loginData, null, 2));
            }
        } else {
            const errData = await loginRes.json();
            log('❌ Login Failed: ' + loginRes.status + ' ' + JSON.stringify(errData, null, 2));
        }

    } catch (error) {
        log('❌ Login/Register Failed: ' + error.message);
    }
}

testBackend();
