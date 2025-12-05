import React, { useState } from 'react';
import { Play, Server, User, Terminal, Settings } from 'lucide-react';

const Audits = ({ onRunAudit, isRunning }) => {
    const [config, setConfig] = useState({
        server: '192.168.1.100',
        user: 'root',
        port: '22',
        mode: 'text',
        options: {
            fast: false,
            silent: false,
        },
    });

    const handleChange = (e) => {
        const { name, value, type, checked } = e.target;
        if (type === 'checkbox') {
            setConfig((prev) => ({
                ...prev,
                options: { ...prev.options, [name]: checked },
            }));
        } else {
            setConfig((prev) => ({ ...prev, [name]: value }));
        }
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        onRunAudit(config);
    };

    return (
        <div className="bg-white rounded-lg shadow-md p-6 mb-8 border-t-4 border-brand-blue">
            <div className="flex items-center mb-6">
                <Terminal className="w-6 h-6 text-brand-blue mr-2" />
                <h2 className="text-2xl font-bold text-gray-800">New Security Audit</h2>
            </div>

            <form onSubmit={handleSubmit}>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
                    {/* Server IP */}
                    <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Target Server</label>
                        <div className="relative">
                            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <Server className="h-5 w-5 text-gray-400" />
                            </div>
                            <input
                                type="text"
                                name="server"
                                value={config.server}
                                onChange={handleChange}
                                className="pl-10 block w-full rounded-md border-gray-300 shadow-sm focus:border-brand-blue focus:ring-brand-blue sm:text-sm p-2 border"
                                placeholder="192.168.1.1"
                                required
                            />
                        </div>
                    </div>

                    {/* SSH User */}
                    <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">SSH User</label>
                        <div className="relative">
                            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <User className="h-5 w-5 text-gray-400" />
                            </div>
                            <input
                                type="text"
                                name="user"
                                value={config.user}
                                onChange={handleChange}
                                className="pl-10 block w-full rounded-md border-gray-300 shadow-sm focus:border-brand-blue focus:ring-brand-blue sm:text-sm p-2 border"
                                placeholder="root"
                                required
                            />
                        </div>
                    </div>

                    {/* SSH Port */}
                    <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">SSH Port</label>
                        <input
                            type="number"
                            name="port"
                            value={config.port}
                            onChange={handleChange}
                            className="block w-full rounded-md border-gray-300 shadow-sm focus:border-brand-blue focus:ring-brand-blue sm:text-sm p-2 border"
                            placeholder="22"
                        />
                    </div>

                    {/* Output Mode */}
                    <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Output Mode</label>
                        <select
                            name="mode"
                            value={config.mode}
                            onChange={handleChange}
                            className="block w-full rounded-md border-gray-300 shadow-sm focus:border-brand-blue focus:ring-brand-blue sm:text-sm p-2 border"
                        >
                            <option value="text">Text Report</option>
                            <option value="json">JSON Data</option>
                            <option value="html">HTML Page</option>
                            <option value="csv">CSV Export</option>
                        </select>
                    </div>
                </div>

                {/* Options & Action */}
                <div className="flex flex-col md:flex-row justify-between items-center border-t pt-4">
                    <div className="flex space-x-6 mb-4 md:mb-0">
                        <label className="inline-flex items-center">
                            <input
                                type="checkbox"
                                name="fast"
                                checked={config.options.fast}
                                onChange={handleChange}
                                className="rounded border-gray-300 text-brand-blue focus:ring-brand-blue h-4 w-4"
                            />
                            <span className="ml-2 text-gray-700 text-sm">Fast Mode (Skip deep scans)</span>
                        </label>
                        <label className="inline-flex items-center">
                            <input
                                type="checkbox"
                                name="silent"
                                checked={config.options.silent}
                                onChange={handleChange}
                                className="rounded border-gray-300 text-brand-blue focus:ring-brand-blue h-4 w-4"
                            />
                            <span className="ml-2 text-gray-700 text-sm">Silent (No external pings)</span>
                        </label>
                    </div>

                    <button
                        type="submit"
                        disabled={isRunning}
                        className={`flex items-center justify-center px-6 py-2 border border-transparent text-base font-medium rounded-md text-white bg-brand-orange hover:bg-orange-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-brand-orange transition-all ${isRunning ? 'opacity-75 cursor-not-allowed' : ''
                            }`}
                    >
                        {isRunning ? (
                            <>
                                <div className="spinner w-5 h-5 border-2 mr-2 border-white border-l-transparent"></div>
                                Running Audit...
                            </>
                        ) : (
                            <>
                                <Play className="w-5 h-5 mr-2" />
                                Start Audit
                            </>
                        )}
                    </button>
                </div>
            </form>
        </div>
    );
};

export default Audits;
