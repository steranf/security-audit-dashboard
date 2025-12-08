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
                    <button onClick={() => handleExport('json')} className="flex items-center px-3 py-2 text-sm text-gray-700 bg-gray-100 rounded hover:bg-gray-200">
                        <Code className="w-4 h-4 mr-2" /> JSON
                    </button>
                    <button onClick={() => handleExport('html')} className="flex items-center px-3 py-2 text-sm text-gray-700 bg-gray-100 rounded hover:bg-gray-200">
                        <Globe className="w-4 h-4 mr-2" /> HTML
                    </button>
                </div>
            </div>

            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                {/* Security Score Card */}
                <div className={`border-l-4 p-4 rounded shadow-sm flex flex-col justify-between ${(() => {
                    const score = Math.max(0, 100 - (
                        (results.summary.critical || 0) * 15 +
                        (results.findings.filter(f => f.severity === 'High').length) * 10 +
                        (results.summary.warning || 0) * 3
                    ));
                    if (score >= 90) return 'bg-green-50 border-green-500';
                    if (score >= 70) return 'bg-yellow-50 border-yellow-500';
                    if (score >= 50) return 'bg-orange-50 border-orange-500';
                    return 'bg-red-50 border-red-500';
                })()
                    }`}>
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="font-medium text-gray-600">Security Score</p>
                            <div className="flex items-baseline">
                                <span className={`text-3xl font-bold ${(() => {
                                    const score = Math.max(0, 100 - (
                                        (results.summary.critical || 0) * 15 +
                                        (results.findings.filter(f => f.severity === 'High').length) * 10 +
                                        (results.summary.warning || 0) * 3
                                    ));
                                    if (score >= 90) return 'text-green-700';
                                    if (score >= 70) return 'text-yellow-800';
                                    if (score >= 50) return 'text-orange-800';
                                    return 'text-red-800';
                                })()
                                    }`}>
                                    {Math.max(0, 100 - (
                                        (results.summary.critical || 0) * 15 +
                                        (results.findings.filter(f => f.severity === 'High').length) * 10 +
                                        (results.summary.warning || 0) * 3
                                    ))}
                                </span>
                                <span className="text-sm text-gray-500 ml-1">/ 100</span>
                            </div>
                        </div>
                        <Activity className={`w-8 h-8 ${(() => {
                            const score = Math.max(0, 100 - (
                                (results.summary.critical || 0) * 15 +
                                (results.findings.filter(f => f.severity === 'High').length) * 10 +
                                (results.summary.warning || 0) * 3
                            ));
                            if (score >= 90) return 'text-green-400';
                            if (score >= 70) return 'text-yellow-400';
                            if (score >= 50) return 'text-orange-400';
                            return 'text-red-400';
                        })()
                            }`} />
                    </div>
                    <div className="mt-2 text-xs font-semibold text-gray-500">
                        {(() => {
                            const score = Math.max(0, 100 - (
                                (results.summary.critical || 0) * 15 +
                                (results.findings.filter(f => f.severity === 'High').length) * 10 +
                                (results.summary.warning || 0) * 3
                            ));
                            if (score >= 90) return 'EXCELLENT';
                            if (score >= 70) return 'GOOD / REVIEW';
                            if (score >= 50) return 'AT RISK';
                            return 'CRITICAL STATE';
                        })()}
                    </div>
                </div>

                {/* Risk Distribution Chart */}
                <div className="bg-white border p-4 rounded shadow-sm flex flex-col justify-between">
                    <p className="font-medium text-gray-600 mb-2">Risk Distribution</p>
                    <div className="flex items-center justify-center">
                        {(() => {
                            const critical = results.summary.critical || 0;
                            const high = results.findings.filter(f => f.severity === 'High').length;
                            const warning = results.summary.warning || 0;
                            const info = results.summary.info || 0;
                            const total = critical + high + warning + info;

                            if (total === 0) return <div className="text-gray-400 text-sm">No Data</div>;

                            // Calculate segments (circumference = 100)
                            const cPer = (critical / total) * 100;
                            const hPer = (high / total) * 100;
                            const wPer = (warning / total) * 100;
                            const iPer = (info / total) * 100;

                            return (
                                <div className="relative w-24 h-24">
                                    <svg viewBox="0 0 36 36" className="w-full h-full transform -rotate-90">
                                        {/* Background Circle */}
                                        <path className="text-gray-100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="currentColor" strokeWidth="4" />

                                        {/* Segments */}
                                        {critical > 0 && (
                                            <path className="text-red-500" strokeDasharray={`${cPer}, 100`} d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="currentColor" strokeWidth="4" />
                                        )}
                                        {high > 0 && (
                                            <path className="text-orange-500" strokeDasharray={`${hPer}, 100`} strokeDashoffset={`-${cPer}`} d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="currentColor" strokeWidth="4" />
                                        )}
                                        {warning > 0 && (
                                            <path className="text-yellow-400" strokeDasharray={`${wPer}, 100`} strokeDashoffset={`-${cPer + hPer}`} d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="currentColor" strokeWidth="4" />
                                        )}
                                        {info > 0 && (
                                            <path className="text-blue-400" strokeDasharray={`${iPer}, 100`} strokeDashoffset={`-${cPer + hPer + wPer}`} d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="currentColor" strokeWidth="4" />
                                        )}
                                    </svg>
                                    <div className="absolute inset-0 flex items-center justify-center flex-col">
                                        <span className="text-xs font-bold text-gray-700">{total}</span>
                                        <span className="text-[8px] text-gray-500">ISSUES</span>
                                    </div>
                                </div>
                            );
                        })()}
                    </div>
                </div>

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

            {/* Security Findings Detail Table */}
            <div className="bg-white rounded-lg shadow-md p-6">
                <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center">
                    <AlertTriangle className="w-5 h-5 mr-2 text-brand-blue" /> Security Findings Detail
                </h3>
                {results.findings && results.findings.length > 0 ? (
                    <div className="overflow-x-auto max-h-[500px] overflow-y-auto border rounded-md">
                        <table className="min-w-full divide-y divide-gray-200">
                            <thead className="bg-gray-50 sticky top-0 z-10 shadow-sm">
                                <tr>
                                    <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider bg-gray-50">Severity</th>
                                    <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider bg-gray-50">Standard</th>
                                    <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider bg-gray-50">Description</th>
                                    <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider bg-gray-50">Recomendation</th>
                                </tr>
                            </thead>
                            <tbody className="bg-white divide-y divide-gray-200">
                                {[...results.findings].sort((a, b) => {
                                    const getScore = (s) => {
                                        if (!s) return 99;
                                        const sev = s.toString().trim().toLowerCase();
                                        if (sev === 'critical') return 0;
                                        if (sev === 'high') return 0;
                                        if (sev === 'warning') return 2;
                                        if (sev === 'info') return 3;
                                        return 99;
                                    };
                                    return getScore(a.severity) - getScore(b.severity);
                                }).map((f, idx) => (
                                    <tr key={idx}>
                                        <td className="px-3 py-2 whitespace-nowrap">
                                            <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${f.severity === 'Critical' || f.severity === 'High' ? 'bg-red-100 text-red-800' :
                                                f.severity === 'Warning' ? 'bg-yellow-100 text-yellow-800' :
                                                    'bg-blue-100 text-blue-800'
                                                }`}>
                                                {f.severity}
                                            </span>
                                        </td>
                                        <td className="px-3 py-2 whitespace-nowrap">
                                            {f.standard_ref ? (
                                                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-gray-100 text-gray-600 border border-gray-200">
                                                    {f.standard_ref}
                                                </span>
                                            ) : (
                                                <span className="text-gray-300">-</span>
                                            )}
                                        </td>
                                        <td className="px-3 py-2 text-sm text-gray-700">
                                            {f.description}
                                        </td>
                                        <td className="px-3 py-2 text-sm text-gray-500 italic">
                                            {f.recommendation || (f.severity === 'Critical' ? 'Immediate action required' : 'Review and mitigate')}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                ) : (
                    <div className="text-center p-4 text-gray-500 bg-gray-50 rounded">
                        <CheckCircle className="w-8 h-8 mx-auto text-green-400 mb-2" />
                        <p>No issues found. Great job!</p>
                    </div>
                )}
            </div>

            {/* Network Attack Surface Table */}
            <div className="bg-white rounded-lg shadow-md p-6 mt-6">
                <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center">
                    <Globe className="w-5 h-5 mr-2 text-purple-600" /> Network Attack Surface (Open Ports)
                </h3>
                {results.open_ports && results.open_ports.length > 0 ? (
                    <div className="overflow-x-auto max-h-[500px] overflow-y-auto border rounded-md">
                        <table className="min-w-full divide-y divide-gray-200">
                            <thead className="bg-gray-50 sticky top-0 z-10 shadow-sm">
                                <tr>
                                    <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Service</th>
                                    <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Port</th>
                                    <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol</th>
                                    <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Binding (IP)</th>
                                    <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status / Risk</th>
                                </tr>
                            </thead>
                            <tbody className="bg-white divide-y divide-gray-200">
                                {[...results.open_ports].sort((a, b) => {
                                    const serviceDiff = a.service.localeCompare(b.service);
                                    if (serviceDiff !== 0) return serviceDiff;
                                    return parseInt(a.port || 0) - parseInt(b.port || 0);
                                }).map((p, idx) => (
                                    <tr key={idx} className="hover:bg-gray-50">
                                        <td className="px-3 py-2 text-sm font-medium text-gray-900">
                                            {p.service}
                                        </td>
                                        <td className="px-3 py-2 text-sm text-gray-500 font-mono">
                                            {p.port}
                                        </td>
                                        <td className="px-3 py-2 text-sm text-gray-500">
                                            <span className="uppercase text-xs font-semibold bg-gray-100 text-gray-600 px-2 py-0.5 rounded">
                                                {p.proto}
                                            </span>
                                        </td>
                                        <td className="px-3 py-2 text-sm text-gray-700 font-mono">
                                            {p.ip}
                                            {p.family && (
                                                <span className={`ml-2 text-[10px] px-1.5 py-0.5 rounded border ${p.family === 'IPv6' ? 'bg-blue-50 text-blue-600 border-blue-200' : 'bg-gray-50 text-gray-500 border-gray-200'}`}>
                                                    {p.family}
                                                </span>
                                            )}
                                        </td>
                                        <td className="px-3 py-2 whitespace-nowrap">
                                            <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${p.risk === 'High' ? 'bg-red-100 text-red-800' :
                                                p.risk === 'Medium' ? 'bg-yellow-100 text-yellow-800' :
                                                    p.status === 'Public' ? 'bg-green-100 text-green-800' :
                                                        'bg-gray-100 text-gray-800'
                                                }`}>
                                                {p.status === 'Public' && p.risk === 'High' ? '⛔ Exposed (High Risk)' :
                                                    p.status === 'Public' ? '✅ Public (Standard)' :
                                                        '🛡️ Localhost Only'}
                                            </span>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                ) : (
                    <div className="text-center p-4 text-gray-500 bg-gray-50 rounded">
                        <Activity className="w-8 h-8 mx-auto text-gray-400 mb-2" />
                        <p>No listening ports detected (or scan failed).</p>
                    </div>
                )}
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
        </div>
    );
};

export default ResultViewer;
