import { render, screen, fireEvent, act } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import Notification from '../Notification';

describe('Notification Component', () => {
    it('renders correctly with message', () => {
        render(<Notification type="success" message="Test Message" onClose={() => { }} />);
        expect(screen.getByText('Test Message')).toBeInTheDocument();
        expect(screen.getByText('Success')).toBeInTheDocument();
    });

    it('calls onClose when close button is clicked', () => {
        const handleClose = vi.fn();
        render(<Notification type="error" message="Error!" onClose={handleClose} />);

        const button = screen.getByRole('button');
        fireEvent.click(button);

        expect(handleClose).toHaveBeenCalledTimes(1);
    });

    it('auto-closes after duration', () => {
        vi.useFakeTimers();
        const handleClose = vi.fn();

        render(<Notification type="success" message="Auto close" onClose={handleClose} duration={3000} />);

        act(() => {
            vi.advanceTimersByTime(3000);
        });

        expect(handleClose).toHaveBeenCalledTimes(1);
        vi.useRealTimers();
    });
});
