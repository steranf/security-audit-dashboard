import React, { useState, useEffect } from 'react';
import Layout from './components/Layout';
import Audits from './components/Audits';
import ResultViewer from './components/ResultViewer';
import Notification from './components/Notification';
import { runAudit } from './api';
import { loadResults, saveResults } from './utils/storage';
import { AlertCircle } from 'lucide-react';

function App() {
    const [results, setResults] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [notification, setNotification] = useState(null); // { type: 'success' | 'error' | 'warning' | 'info', message: string }

    // Load last audit from local storage on mount
    useEffect(() => {
        const saved = loadResults();
        if (saved) {
            setResults(saved);
        }
    }, []);

    const closeNotification = () => setNotification(null);

    const handleRunAudit = async (config) => {
        setLoading(true);
        setError(null);
        setNotification(null);

        try {
            const data = await runAudit(config);
            setResults(data);
            saveResults(data);
            setNotification({ type: 'success', message: 'Audit completed successfully!' });
        } catch (err) {
            console.error(err);
            setError(err?.message || "Unexpected error occurred");
            setNotification({ type: 'error', message: `Audit failed: ${err?.message || "Unknown error"}` });
        } finally {
            setLoading(false);
        }
    };

    return (
        <Layout>
            {/* Notification Toast */}
            {notification && (
                <Notification
                    type={notification.type}
                    message={notification.message}
                    onClose={closeNotification}
                    duration={5000}
                />
            )}

            {/* Global Loading Indicator */}
            {loading && (
                <div className="bg-blue-50 border-l-4 border-blue-500 p-4 mb-6 animate-pulse">
                    <div className="flex">
                        <div className="flex-shrink-0">
                            <div className="h-5 w-5 rounded-full border-2 border-blue-400 border-t-transparent animate-spin"></div>
                        </div>
                        <div className="ml-3">
                            <p className="text-sm text-blue-700">
                                Audit in progress... Please wait while we scan the target server.
                            </p>
                        </div>
                    </div>
                </div>
            )}

            <Audits onRunAudit={handleRunAudit} isRunning={loading} />

            {error && (
                <div role="alert" className="bg-red-50 border-l-4 border-red-500 p-4 mb-8">
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
                <ResultViewer
                    results={results}
                    mode={['text', 'json', 'html', 'csv'].includes(results.mode) ? results.mode : 'text'}
                />
            )}
        </Layout>
    );
}

export default App;
