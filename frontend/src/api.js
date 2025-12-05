// Toggle this to switch between Real API and Mock Data
const USE_MOCK = true;
const API_BASE_URL = 'http://localhost:3000/api'; // Replace with actual backend URL

/**
 * Runs a security audit on the specified server.
 * @param {Object} config - Audit configuration (server, user, port, mode, options).
 * @returns {Promise<Object>} - The audit results.
 */
export const runAudit = async (config) => {
    if (USE_MOCK) {
        return mockAudit(config);
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30s timeout

    try {
        const response = await fetch(`${API_BASE_URL}/audit`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(config),
            signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            throw new Error(`Audit failed: ${response.statusText}`);
        }

        return await response.json();
    } catch (error) {
        clearTimeout(timeoutId);
        throw error;
    }
};

// --- Mock Data Generator ---

const mockAudit = (config) => {
    return new Promise((resolve) => {
        setTimeout(() => {
            resolve({
                id: Date.now(),
                timestamp: new Date().toISOString(),
                server: config.server,
                summary: {
                    critical: Math.floor(Math.random() * 3),
                    warning: Math.floor(Math.random() * 5),
                    info: Math.floor(Math.random() * 10),
                },
                services: [
                    { name: 'SSH', status: 'active', version: 'OpenSSH_8.2p1' },
                    { name: 'Nginx', status: 'active', version: '1.18.0' },
                    { name: 'Fail2Ban', status: 'active', version: '0.11.1' },
                    { name: 'UFW', status: 'active', version: '0.36' },
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
                metrics: {
                    cpu: '15%',
                    ram: '4.2GB / 16GB',
                    disk: '45% used',
                    connections: 23,
                },
            });
        }, 2000); // Simulate 2s delay
    });
};
