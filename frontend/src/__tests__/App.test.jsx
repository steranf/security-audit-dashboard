import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import App from '../App';
import * as api from '../api';
import * as storage from '../utils/storage';

// Mock dependencies
vi.mock('../api');
vi.mock('../utils/storage');

// Mock child components to isolate App logic
vi.mock('../components/ResultViewer', () => ({
    default: () => <div data-testid="result-viewer">Audit Results</div>
}));

vi.mock('../components/Audits', () => ({
    default: ({ onRunAudit, isRunning }) => (
        <div data-testid="audits">
            <button onClick={() => onRunAudit({ server: 'test' })} disabled={isRunning}>
                Start Audit
            </button>
            {isRunning && <span>Running Audit...</span>}
        </div>
    )
}));

vi.mock('../components/Notification', () => ({
    default: ({ message }) => <div data-testid="notification">{message}</div>
}));

vi.mock('../components/Layout', () => ({
    default: ({ children }) => <div data-testid="layout">{children}</div>
}));

describe('App Component', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('renders correctly', () => {
        render(<App />);
        expect(screen.getByTestId('layout')).toBeInTheDocument();
        expect(screen.getByTestId('audits')).toBeInTheDocument();
    });

    it('loads saved results on mount', () => {
        const mockResults = {
            id: '123',
            mode: 'text',
            summary: { critical: 0, warning: 0, info: 0 },
            logs: []
        };
        storage.loadResults.mockReturnValue(mockResults);

        render(<App />);

        expect(storage.loadResults).toHaveBeenCalledTimes(1);
        expect(screen.getByTestId('result-viewer')).toBeInTheDocument();
    });

    it('runs audit and saves results', async () => {
        const mockData = {
            id: '456',
            mode: 'text',
            summary: { critical: 1, warning: 0, info: 0 },
            logs: []
        };
        api.runAudit.mockResolvedValue(mockData);

        render(<App />);

        // Find and click start button (from mocked Audits)
        const button = screen.getByText('Start Audit');
        fireEvent.click(button);

        // Should show loading state (from mocked Audits)
        expect(screen.getByText('Running Audit...')).toBeInTheDocument();

        await waitFor(() => {
            expect(api.runAudit).toHaveBeenCalled();
        });

        // Should save results
        expect(storage.saveResults).toHaveBeenCalledWith(mockData);

        // Should show success notification
        await waitFor(() => {
            expect(screen.getByTestId('notification')).toHaveTextContent('Audit completed successfully!');
        });
    });

    it('handles audit error', async () => {
        const errorMessage = 'Network Error';
        api.runAudit.mockRejectedValue(new Error(errorMessage));

        render(<App />);

        const button = screen.getByText('Start Audit');
        fireEvent.click(button);

        await waitFor(() => {
            expect(screen.getByTestId('notification')).toHaveTextContent(`Audit failed: ${errorMessage}`);
        });
    });
});
