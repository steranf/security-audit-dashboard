import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import Audits from '../Audits';

describe('Audits Component', () => {
    it('renders correctly', () => {
        render(<Audits onRunAudit={() => { }} isRunning={false} />);
        expect(screen.getByText('New Security Audit')).toBeInTheDocument();
        expect(screen.getByLabelText('Target Server IP or Hostname')).toBeInTheDocument();
    });

    it('updates input fields', () => {
        render(<Audits onRunAudit={() => { }} isRunning={false} />);
        const serverInput = screen.getByLabelText('Target Server IP or Hostname');

        fireEvent.change(serverInput, { target: { value: '10.0.0.1' } });
        expect(serverInput.value).toBe('10.0.0.1');
    });

    it('calls onRunAudit with config on submit', () => {
        const handleRunAudit = vi.fn();
        render(<Audits onRunAudit={handleRunAudit} isRunning={false} />);

        const button = screen.getByRole('button', { name: /Start Audit/i });
        fireEvent.click(button);

        expect(handleRunAudit).toHaveBeenCalledTimes(1);
        // Check if called with default config
        expect(handleRunAudit).toHaveBeenCalledWith(expect.objectContaining({
            server: '192.168.1.100',
            user: 'root',
            port: '22'
        }));
    });

    it('disables button when running', () => {
        render(<Audits onRunAudit={() => { }} isRunning={true} />);
        const button = screen.getByRole('button'); // The button text changes, so get by role is safer
        expect(button).toBeDisabled();
        expect(screen.getByText('Running Audit...')).toBeInTheDocument();
    });
});
