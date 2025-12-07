// Environment variables for configuration
// Note: In Vite, env vars must start with VITE_
const USE_MOCK = import.meta.env.VITE_USE_MOCK === 'true';
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3000/api';

/**
 * Validates the audit configuration before sending.
 * @param {Object} config 
 * @returns {string|null} Error message or null if valid.
 */
const validateConfig = (config) => {
    if (!config.server) return "Target server is required.";
    // Basic regex for IP or Hostname (matches Audits.jsx)
    const serverRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^localhost$/;
    if (!serverRegex.test(config.server)) return "Invalid server format.";

    if (config.port < 1 || config.port > 65535) return "Port must be between 1 and 65535.";
    if (!config.user) return "User is required.";
    return null;
};

/**
 * Runs the security audit.
 * @param {Object} config - Audit configuration (server, user, port, fast, silent, etc.)
 * @returns {Promise<Object>} Audit results.
 */
export const runAudit = async (config) => {
    // 1. Client-side Validation
    const validationError = validateConfig(config);
    if (validationError) {
        throw new Error(validationError);
    }

    // 2. Prepare Request Payload
    const payload = {
        server: config.server,
        user: config.user,
        port: parseInt(config.port, 10),
        mode: config.mode || 'json',
        lines: parseInt(config.lines, 10) || 100,
        services: config.services || '',
        passphrase: config.passphrase || null,
        password: config.password || null,
        options: {
            fast: !!config.fast,
            silent: !!config.silent
        }
    };

    // 3. Mock Mode
    if (USE_MOCK) {
        console.log("Running in MOCK mode (Client-side)...");
        return mockAudit(payload);
    }

    // 4. Real API Call
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 60000); // 60s timeout

    try {
        console.log(`Sending audit request to ${API_BASE_URL}/audit`, payload);

        const response = await fetch(`${API_BASE_URL}/audit`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload),
            signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            let errorData = {};
            try {
                errorData = await response.json();
            } catch (e) { /* ignore JSON parse error */ }

            // Handle specific PassphraseRequired error
            if (response.status === 401 && errorData.code === 'PASSPHRASE_REQUIRED') {
                const err = new Error(errorData.message);
                err.code = 'PASSPHRASE_REQUIRED';
                throw err;
            }
            if (response.status === 401 && errorData.code === 'SUDO_PASSWORD_REQUIRED') {
                const err = new Error(errorData.message);
                err.code = 'SUDO_PASSWORD_REQUIRED';
                throw err;
            }

            let errorMessage = `Audit failed: ${response.statusText}`;
            if (errorData.detail) errorMessage = errorData.detail;
            else if (errorData.message) errorMessage = errorData.message;

            throw new Error(errorMessage);
        }

        return await response.json();
    } catch (error) {
        clearTimeout(timeoutId);
        if (error.name === 'AbortError') {
            throw new Error('Audit request timed out (60s limit).');
        }
        if (error.message === 'Failed to fetch') {
            throw new Error(`Cannot connect to backend at ${API_BASE_URL}. Is it running?`);
        }
        throw error;
    }
};

// --- Mock Data Generator (Client-Side Fallback) ---
const mockAudit = (payload) => {
    return new Promise((resolve) => {
        setTimeout(() => {
            resolve({
                id: Date.now().toString(),
                status: "completed",
                timestamp: new Date().toISOString(),
                server: payload.server,
                summary: {
                    critical: Math.floor(Math.random() * 3),
                    warning: Math.floor(Math.random() * 5),
                    info: Math.floor(Math.random() * 10),
                },
                metrics: {
                    cpu: '15%',
                    ram: '4.2GB / 16GB',
                    disk: '45% used',
                    connections: 23,
                },
                services: [
                    { name: 'SSH', status: 'active', version: 'OpenSSH_8.2p1' },
                    { name: 'Nginx', status: 'active', version: '1.18.0' },
                    { name: 'Fail2Ban', status: 'active', version: '0.11.1' },
                    { name: 'UFW', status: 'active', version: '0.36' },
                ],
                findings: [
                    { severity: 'Critical', description: 'Root login enabled via SSH' },
                    { severity: 'Warning', description: 'UFW is active but allowing port 8080' },
                    { severity: 'Info', description: 'System uptime: 14 days' }
                ],
                logs: [
                    'Dec 05 10:00:01 server systemd[1]: Started Session 1 of user root.',
                    'Dec 05 10:05:23 server sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 22 ssh2',
                    'Dec 05 10:10:00 server CRON[5678]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)',
                ],
                ips: [
                    { ip: '192.168.1.50', country: 'Unknown', reason: 'Failed SSH login' },
                    { ip: '10.0.0.5', country: 'Local', reason: 'High traffic' },
                ],
            });
        }, 2000);
    });
};
