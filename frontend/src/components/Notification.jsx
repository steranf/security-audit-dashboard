import React, { useEffect } from 'react';
import { AlertCircle, CheckCircle, X, Info, AlertTriangle } from 'lucide-react';

const Notification = ({ type, message, onClose, duration = 5000 }) => {
    useEffect(() => {
        if (duration > 0) {
            const timer = setTimeout(() => {
                onClose();
            }, duration);
            return () => clearTimeout(timer);
        }
    }, [onClose, duration]);

    const getIcon = () => {
        switch (type) {
            case 'success': return <CheckCircle className="w-6 h-6 mr-3" aria-hidden="true" />;
            case 'error': return <AlertCircle className="w-6 h-6 mr-3" aria-hidden="true" />;
            case 'warning': return <AlertTriangle className="w-6 h-6 mr-3" aria-hidden="true" />;
            case 'info': return <Info className="w-6 h-6 mr-3" aria-hidden="true" />;
            default: return <Info className="w-6 h-6 mr-3" aria-hidden="true" />;
        }
    };

    const getBgColor = () => {
        switch (type) {
            case 'success': return 'bg-green-600';
            case 'error': return 'bg-red-600';
            case 'warning': return 'bg-yellow-600';
            case 'info': return 'bg-blue-600';
            default: return 'bg-blue-600';
        }
    };

    const getTitle = () => {
        switch (type) {
            case 'success': return 'Success';
            case 'error': return 'Error';
            case 'warning': return 'Warning';
            case 'info': return 'Info';
            default: return 'Info';
        }
    };

    return (
        <div
            role="alert"
            className={`fixed top-20 right-4 z-50 px-6 py-4 rounded shadow-lg flex items-center transition-all duration-500 animate-fade-in ${getBgColor()} text-white`}
        >
            {getIcon()}
            <div className="flex-1 mr-4">
                <h4 className="font-bold">{getTitle()}</h4>
                <p className="text-sm">{message}</p>
            </div>
            <button
                onClick={onClose}
                className="text-white hover:text-gray-200 focus:outline-none focus:ring-2 focus:ring-white rounded"
                aria-label="Close notification"
            >
                <X className="w-4 h-4" />
            </button>
        </div>
    );
};

export default Notification;
