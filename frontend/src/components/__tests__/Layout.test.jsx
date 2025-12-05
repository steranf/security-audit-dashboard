import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import Layout from '../Layout';

describe('Layout Component', () => {
    it('renders children correctly', () => {
        render(
            <Layout>
                <div data-testid="child">Child Content</div>
            </Layout>
        );
        expect(screen.getByTestId('child')).toBeInTheDocument();
    });

    it('renders header and footer', () => {
        render(<Layout>Content</Layout>);
        // Match the full text content "Innova Security"
        expect(screen.getByText(/Innova Security/i)).toBeInTheDocument();
        expect(screen.getByText(/All rights reserved/i)).toBeInTheDocument();
    });

    it('passes extra props to main element', () => {
        render(<Layout data-testid="main-layout" id="main-content">Content</Layout>);
        const main = screen.getByTestId('main-layout');
        expect(main).toHaveAttribute('id', 'main-content');
    });
});
