import React, { useState } from 'react';
import { ShieldCheck, Menu, X } from 'lucide-react';

const Header = () => {
    const [isMenuOpen, setIsMenuOpen] = useState(false);

    return (
        <header className="bg-brand-dark text-white shadow-lg relative">
            <div className="container mx-auto px-4 py-4 flex justify-between items-center">
                {/* Logo / Brand */}
                <div className="flex items-center space-x-2">
                    <ShieldCheck className="w-8 h-8 text-brand-orange" />
                    <span className="text-xl font-bold tracking-wide">
                        Innova <span className="text-brand-blue font-light">Security</span>
                    </span>
                </div>

                {/* Desktop Nav */}
                <nav className="hidden md:flex space-x-6">
                    <a href="#" className="hover:text-brand-orange transition-colors">Dashboard</a>
                    <a href="#" className="hover:text-brand-orange transition-colors">History</a>
                    <a href="#" className="hover:text-brand-orange transition-colors">Settings</a>
                </nav>

                {/* Mobile Menu Button */}
                <button
                    onClick={() => setIsMenuOpen(!isMenuOpen)}
                    className="md:hidden text-gray-300 hover:text-white focus:outline-none"
                    aria-label={isMenuOpen ? "Close menu" : "Open menu"}
                    aria-expanded={isMenuOpen}
                >
                    {isMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
                </button>
            </div>

            {/* Mobile Nav Dropdown */}
            {isMenuOpen && (
                <div className="md:hidden bg-gray-800 py-2 absolute w-full z-50 shadow-xl">
                    <a href="#" className="block px-4 py-2 hover:bg-gray-700 transition-colors">Dashboard</a>
                    <a href="#" className="block px-4 py-2 hover:bg-gray-700 transition-colors">History</a>
                    <a href="#" className="block px-4 py-2 hover:bg-gray-700 transition-colors">Settings</a>
                </div>
            )}
        </header>
    );
};

export default Header;
