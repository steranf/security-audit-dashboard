import { describe, it, expect, vi, beforeEach } from 'vitest';
import { saveResults, loadResults, STORAGE_KEY } from '../storage';

describe('Storage Utility', () => {
    beforeEach(() => {
        localStorage.clear();
        vi.clearAllMocks();
    });

    it('saves results to localStorage', () => {
        const data = { id: 1, logs: [] };
        saveResults(data);
        expect(localStorage.getItem(STORAGE_KEY)).toBe(JSON.stringify(data));
    });

    it('truncates logs if they exceed 50 entries', () => {
        const longLogs = Array.from({ length: 100 }, (_, i) => `Log ${i}`);
        const data = { id: 1, logs: longLogs };

        saveResults(data);

        const saved = JSON.parse(localStorage.getItem(STORAGE_KEY));
        expect(saved.logs).toHaveLength(50);
        expect(saved.logs[0]).toBe('Log 0');
        expect(saved.logs[49]).toBe('Log 49');
    });

    it('handles missing logs array safely', () => {
        const data = { id: 1 }; // No logs property
        saveResults(data);

        const saved = JSON.parse(localStorage.getItem(STORAGE_KEY));
        expect(saved.logs).toEqual([]);
    });

    it('loads results from localStorage', () => {
        const data = { id: 1, logs: [] };
        localStorage.setItem(STORAGE_KEY, JSON.stringify(data));

        const loaded = loadResults();
        expect(loaded).toEqual(data);
    });

    it('returns null if no results found', () => {
        const loaded = loadResults();
        expect(loaded).toBeNull();
    });
});
