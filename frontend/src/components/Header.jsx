import React from 'react';
import { ShieldCheck, Menu } from 'lucide-react';

const Header = () => {
    return (
        <header className="bg-brand-dark text-white shadow-lg">
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
                <button className="md:hidden text-gray-300 hover:text-white">
                    <Menu className="w-6 h-6" />
                </button>
            </div>
        </header>
    );
};

export default Header;
