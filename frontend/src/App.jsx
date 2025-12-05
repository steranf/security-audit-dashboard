import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import Footer from './components/Footer';
import Audits from './components/Audits';
import ResultViewer from './components/ResultViewer';
import { runAudit } from './api';
import { AlertCircle, CheckCircle } from 'lucide-react';

function App() {
    const [results, setResults] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [notification, setNotification] = useState(null); // { type: 'success' | 'error', message: string }

    // Load last audit from local storage on mount
    useEffect(() => {
        const savedResults = localStorage.getItem('lastAuditResults');
        if (savedResults) {
            try {
                setResults(JSON.parse(savedResults));
            } catch (e) {
                console.error('Failed to parse saved results', e);
            }
        }
    }, []);

    const showNotification = (type, message) => {
        setNotification({ type, message });
        setTimeout(() => setNotification(null), 5000); // Hide after 5s
    };

    const handleRunAudit = async (config) => {
        setLoading(true);
        setError(null);
        setNotification(null);

        try {
            const data = await runAudit(config);
            setResults(data);
            localStorage.setItem('lastAuditResults', JSON.stringify(data));
            showNotification('success', 'Audit completed successfully!');
        } catch (err) {
            console.error(err);
            setError(err.message);
            showNotification('error', `Audit failed: ${err.message}`);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="flex flex-col min-h-screen bg-gray-50 font-sans text-gray-900">
            <Header />

            <main className="flex-grow container mx-auto px-4 py-8">
                {/* Notification Toast */}
                {notification && (
                    <div className={`fixed top-20 right-4 z-50 px-6 py-4 rounded shadow-lg flex items-center transition-all duration-500 ${notification.type === 'success' ? 'bg-green-600 text-white' : 'bg-red-600 text-white'
                        }`}>
                        {notification.type === 'success' ? (
                            <CheckCircle className="w-6 h-6 mr-3" />
                        ) : (
                            <AlertCircle className="w-6 h-6 mr-3" />
                        )}
                        <div>
                            <h4 className="font-bold">{notification.type === 'success' ? 'Success' : 'Error'}</h4>
                            <p className="text-sm">{notification.message}</p>
                        </div>
                    </div>
                )}

                <Audits onRunAudit={handleRunAudit} isRunning={loading} />

                {error && (
                    <div className="bg-red-50 border-l-4 border-red-500 p-4 mb-8">
                        <div className="flex">
                            <div className="flex-shrink-0">
                                <AlertCircle className="h-5 w-5 text-red-400" />
                            </div>
                            <div className="ml-3">
                                <p className="text-sm text-red-700">
                                    {error}
                                </p>
                            </div>
                        </div>
                    </div>
                )}

                {results && (
                    <ResultViewer results={results} mode={results.mode || 'text'} />
                )}
            </main>

            <Footer />
        </div>
    );
}

export default App;
