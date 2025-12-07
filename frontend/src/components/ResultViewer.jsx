import React from 'react';
import { AlertTriangle, CheckCircle, Info, Activity, HardDrive, Cpu, Globe, Download, FileText, Code, Server } from 'lucide-react';

const ResultViewer = ({ results, mode }) => {
    if (!results) return null;

    const escapeHtml = (unsafe) => {
        return String(unsafe)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    };

    const escapeCsv = (field) => {
        const stringField = String(field);
        // Prevent Excel Formula Injection
        if (['=', '+', '-', '@'].includes(stringField.charAt(0))) {
            return `"'${stringField.replace(/"/g, '""')}"`;
        }
        // Standard CSV escaping: wrap in quotes and escape internal quotes
        return `"${stringField.replace(/"/g, '""')}"`;
    };

    if (results.status === 'debug') {
        return (
            <div className="bg-white rounded-lg shadow-md p-6 border-l-4 border-yellow-500">
                <div className="flex items-center mb-4">
                    <AlertTriangle className="w-8 h-8 text-yellow-500 mr-3" />
                    <h2 className="text-2xl font-bold text-gray-800">DIAGNÓSTICO DE VERSIÓN COMPLETADO (DEBUG MODE)</h2>
                </div>
                <div className="bg-gray-900 text-gray-100 p-4 rounded-md overflow-x-auto font-mono text-sm whitespace-pre-wrap">
                    {results.raw_output}
                </div>
            </div>
        );
    }

    const handleExport = (format) => {
        // Use the same base URL logic as api.js
        const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3000/api';
        const exportUrl = `${API_BASE_URL}/audit/${results.id}/export?format=${format}`;

        // Trigger download
        window.open(exportUrl, '_blank');
    };

    if (mode === 'json') {
        return (
            <div className="bg-white rounded-lg shadow-md p-6">
                <div className="flex justify-between items-center mb-4">
                    <h3 className="text-xl font-bold text-gray-800 flex items-center">
                        <Code className="w-5 h-5 mr-2 text-brand-blue" />
                        Raw JSON Output
                    </h3>
                    <button
                        onClick={() => handleExport('json')}
                        className="flex items-center px-4 py-2 text-sm font-medium text-brand-blue border border-brand-blue rounded-md hover:bg-blue-50"
                    >
                        <Download className="w-4 h-4 mr-2" />
                        Download JSON
                    </button>
                </div>
                <pre className="bg-gray-900 text-green-400 p-4 rounded-md overflow-x-auto text-sm font-mono">
                    {JSON.stringify(results, null, 2)}
                </pre>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* Header & Actions */}
            <div className="flex flex-col md:flex-row justify-between items-center bg-white p-4 rounded-lg shadow-sm">
                <div>
                    <h2 className="text-2xl font-bold text-gray-800">Audit Results</h2>
                    <p className="text-sm text-gray-500">Server: {results.server} | ID: {results.id}</p>
                </div>
                <div className="flex space-x-3 mt-4 md:mt-0">
                    <button onClick={() => handleExport('csv')} className="flex items-center px-3 py-2 text-sm text-gray-700 bg-gray-100 rounded hover:bg-gray-200">
                        <FileText className="w-4 h-4 mr-2" /> CSV
                    </button>
                    <button onClick={() => handleExport('html')} className="flex items-center px-3 py-2 text-sm text-gray-700 bg-gray-100 rounded hover:bg-gray-200">
                        <Globe className="w-4 h-4 mr-2" /> HTML
                    </button>
                </div>
            </div>

            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-red-50 border-l-4 border-red-500 p-4 rounded shadow-sm">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-red-700 font-medium">Critical Issues</p>
                            <p className="text-3xl font-bold text-red-800">{results.summary.critical}</p>
                        </div>
                        <AlertTriangle className="w-8 h-8 text-red-400" />
                    </div>
                </div>
                <div className="bg-yellow-50 border-l-4 border-yellow-500 p-4 rounded shadow-sm">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-yellow-700 font-medium">Warnings</p>
                            <p className="text-3xl font-bold text-yellow-800">{results.summary.warning}</p>
                        </div>
                        <Info className="w-8 h-8 text-yellow-400" />
                    </div>
                </div>
                <div className="bg-blue-50 border-l-4 border-blue-500 p-4 rounded shadow-sm">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-blue-700 font-medium">Info / Passed</p>
                            <p className="text-3xl font-bold text-blue-800">{results.summary.info}</p>
                        </div>
                        <CheckCircle className="w-8 h-8 text-blue-400" />
                    </div>
                </div>
            </div>

            {/* Metrics & Services Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* System Metrics */}
                <div className="bg-white rounded-lg shadow-md p-6">
                    <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center">
                        <Activity className="w-5 h-5 mr-2 text-brand-blue" /> System Metrics
                    </h3>
                    <div className="grid grid-cols-2 gap-4">
                        <div className="p-3 bg-gray-50 rounded">
                            <p className="text-xs text-gray-500 uppercase">CPU Usage</p>
                            <div className="flex items-center mt-1">
                                <Cpu className="w-4 h-4 text-gray-400 mr-2" />
                                <span className="font-mono font-medium">{results.metrics.cpu}</span>
                            </div>
                        </div>
                        <div className="p-3 bg-gray-50 rounded">
                            <p className="text-xs text-gray-500 uppercase">RAM Usage</p>
                            <div className="flex items-center mt-1">
                                <HardDrive className="w-4 h-4 text-gray-400 mr-2" />
                                <span className="font-mono font-medium">{results.metrics.ram}</span>
                            </div>
                        </div>
                        <div className="p-3 bg-gray-50 rounded">
                            <p className="text-xs text-gray-500 uppercase">Disk Usage</p>
                            <div className="flex items-center mt-1">
                                <HardDrive className="w-4 h-4 text-gray-400 mr-2" />
                                <span className="font-mono font-medium">{results.metrics.disk}</span>
                            </div>
                        </div>
                        <div className="p-3 bg-gray-50 rounded">
                            <p className="text-xs text-gray-500 uppercase">Active Conn.</p>
                            <div className="flex items-center mt-1">
                                <Activity className="w-4 h-4 text-gray-400 mr-2" />
                                <span className="font-mono font-medium">{results.metrics.connections}</span>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Services Status */}
                <div className="bg-white rounded-lg shadow-md p-6">
                    <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center">
                        <Server className="w-5 h-5 mr-2 text-brand-blue" /> Services Status
                    </h3>
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y divide-gray-200">
                            <thead>
                                <tr>
                                    <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Service</th>
                                    <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                    <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Version</th>
                                </tr>
                            </thead>
                            <tbody className="bg-white divide-y divide-gray-200">
                                {results.services.map((service, idx) => (
                                    <tr key={idx}>
                                        <td className="px-3 py-2 whitespace-nowrap text-sm font-medium text-gray-900">
                                            {service.name}
                                        </td>
                                        <td className="px-3 py-2 whitespace-nowrap text-sm text-gray-500">
                                            <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${service.status === 'active' || service.status === 'running'
                                                ? 'bg-green-100 text-green-800'
                                                : 'bg-red-100 text-red-800'
                                                }`}>
                                                {service.status}
                                            </span>
                                        </td>
                                        <td className="px-3 py-2 whitespace-nowrap text-sm text-gray-500">
                                            {service.version}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            {/* Logs & IPs */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Recent Logs */}
                <div className="bg-white rounded-lg shadow-md p-6">
                    <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center">
                        <FileText className="w-5 h-5 mr-2 text-brand-blue" /> Recent Logs
                    </h3>
                    <div className="bg-gray-900 text-gray-300 p-3 rounded text-xs font-mono h-48 overflow-y-auto">
                        {results.logs.length > 100 && (
                            <div className="text-gray-500 italic mb-2 sticky top-0 bg-gray-900 pb-1 border-b border-gray-800">
                                Showing last 100 of {results.logs.length} logs...
                            </div>
                        )}
                        {results.logs.slice(-100).map((log, idx) => (
                            <div key={idx} className="mb-1 border-b border-gray-800 pb-1 last:border-0">
                                {log}
                            </div>
                        ))}
                    </div>
                </div>

                {/* Suspicious IPs */}
                <div className="bg-white rounded-lg shadow-md p-6">
                    <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center">
                        <Globe className="w-5 h-5 mr-2 text-brand-blue" /> Suspicious IPs
                    </h3>
                    <ul className="divide-y divide-gray-200">
                        {results.ips.map((item, idx) => (
                            <li key={idx} className="py-3 flex justify-between items-center">
                                <div>
                                    <p className="text-sm font-medium text-gray-900">{item.ip}</p>
                                    <p className="text-xs text-gray-500">{item.country}</p>
                                </div>
                                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                    {item.reason}
                                </span>
                            </li>
                        ))}
                    </ul>
                </div>
            </div>
        </div >
    );
};

export default ResultViewer;
