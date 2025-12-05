export const STORAGE_KEY = 'lastAuditResults';

/**
 * Saves audit results to local storage with optimization.
 * Truncates logs to the last 50 entries to save space.
 * @param {Object} data - The audit results to save.
 */
export const saveResults = (data) => {
    try {
        const resultsToSave = {
            ...data,
            logs: Array.isArray(data.logs) ? data.logs.slice(-50) : [],
        };
        localStorage.setItem(STORAGE_KEY, JSON.stringify(resultsToSave));
    } catch (error) {
        console.error('Failed to save results to localStorage:', error);
    }
};

/**
 * Loads audit results from local storage.
 * @returns {Object|null} The saved results or null if not found or error.
 */
export const loadResults = () => {
    try {
        const savedResults = localStorage.getItem(STORAGE_KEY);
        return savedResults ? JSON.parse(savedResults) : null;
    } catch (error) {
        console.error('Failed to load results from localStorage:', error);
        return null;
    }
};
