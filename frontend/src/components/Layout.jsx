import React from 'react';
import Header from './Header';
import Footer from './Footer';

/**
 * Main Layout component that wraps the application content.
 * Provides a consistent structure with Header and Footer.
 * 
 * @param {Object} props
 * @param {React.ReactNode} props.children - The content to render within the layout.
 * @param {string} [props.className] - Additional CSS classes for the main container.
 * @param {...Object} [props.rest] - Additional props passed to the <main> element (e.g., id, aria-*, data-*).
 */
const Layout = ({ children, className = '', ...rest }) => {
    return (
        <div className="flex flex-col min-h-screen bg-gray-50 font-sans text-gray-900">
            <Header />
            <main
                role="main"
                className={`flex-grow container mx-auto px-4 py-8 max-w-7xl ${className}`}
                {...rest}
            >
                {children}
            </main>
            <Footer />
        </div>
    );
};

export default Layout;
