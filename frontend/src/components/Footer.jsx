import React from 'react';

const Footer = () => {
    return (
        <footer className="bg-gray-800 text-gray-400 py-6 mt-auto">
            <div className="container mx-auto px-4 text-center">
                <p className="text-sm">
                    &copy; {new Date().getFullYear()} Innova Security. All rights reserved.
                </p>
                <div className="flex justify-center space-x-4 mt-2">
                    <a href="#" className="hover:text-white transition-colors">Privacy Policy</a>
                    <a href="#" className="hover:text-white transition-colors">Terms of Service</a>
                    <a href="#" className="hover:text-white transition-colors">Support</a>
                </div>
            </div>
        </footer>
    );
};

export default Footer;
