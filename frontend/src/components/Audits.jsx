import React, { useState } from 'react';
import { Play, Server, User, Terminal } from 'lucide-react';

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

  const auditOptions = [
    { id: 'fast', label: 'Fast Mode (Skip deep scans)' },
    { id: 'silent', label: 'Silent (No external pings)' },
  ];

  return (
    <div className="bg-white rounded-lg shadow-md p-6 mb-8 border-t-4 border-brand-blue">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center">
          <Terminal className="w-6 h-6 text-brand-blue mr-2" aria-hidden="true" />
          <h2 className="text-2xl font-bold text-gray-800">New Security Audit</h2>
        </div>
        {isRunning && (
          <span className="text-sm font-medium text-brand-blue animate-pulse">
            Audit in progress...
          </span>
        )}
      </div>

      <form onSubmit={handleSubmit}>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
          {/* Server IP */}
          <div>
            <label htmlFor="server" className="block text-sm font-medium text-gray-700 mb-1">Target Server</label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Server className="h-5 w-5 text-gray-400" aria-hidden="true" />
              </div>
              <input
                type="text"
                id="server"
                name="server"
                value={config.server}
                onChange={handleChange}
                className="pl-10 block w-full rounded-md border-gray-300 shadow-sm focus:border-brand-blue focus:ring-brand-blue sm:text-sm p-2 border"
                placeholder="192.168.1.1"
                required
                // Stricter regex for IPs, Domains, and Localhost.
                pattern="^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^localhost$"
                title="Please enter a valid IP address (e.g., 192.168.1.1) or hostname (e.g., example.com)"
                aria-label="Target Server IP or Hostname"
              />
            </div>
          </div>

          {/* SSH User */}
          <div>
            <label htmlFor="user" className="block text-sm font-medium text-gray-700 mb-1">SSH User</label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <User className="h-5 w-5 text-gray-400" aria-hidden="true" />
              </div>
              <input
                type="text"
                id="user"
                name="user"
                value={config.user}
                onChange={handleChange}
                className="pl-10 block w-full rounded-md border-gray-300 shadow-sm focus:border-brand-blue focus:ring-brand-blue sm:text-sm p-2 border"
                placeholder="root"
                required
                aria-label="SSH Username"
              />
            </div>
          </div>

          {/* SSH Port */}
          <div>
            <label htmlFor="port" className="block text-sm font-medium text-gray-700 mb-1">SSH Port</label>
            <input
              type="number"
              id="port"
              name="port"
              min="1"
              max="65535"
              value={config.port}
              onChange={handleChange}
              className="block w-full rounded-md border-gray-300 shadow-sm focus:border-brand-blue focus:ring-brand-blue sm:text-sm p-2 border"
              placeholder="22"
              aria-label="SSH Port Number"
            />
          </div>

          {/* Output Mode */}
          <div>
            <label htmlFor="mode" className="block text-sm font-medium text-gray-700 mb-1">Output Mode</label>
            <select
              id="mode"
              name="mode"
              value={config.mode}
              onChange={handleChange}
              className="block w-full rounded-md border-gray-300 shadow-sm focus:border-brand-blue focus:ring-brand-blue sm:text-sm p-2 border"
              aria-label="Audit Output Format"
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
            {auditOptions.map((opt) => (
              <label key={opt.id} className="inline-flex items-center">
                <input
                  type="checkbox"
                  name={opt.id}
                  checked={config.options[opt.id]}
                  onChange={handleChange}
                  className="rounded border-gray-300 text-brand-blue focus:ring-brand-blue h-4 w-4"
                />
                <span className="ml-2 text-gray-700 text-sm">{opt.label}</span>
              </label>
            ))}
          </div>

          <button
            type="submit"
            disabled={isRunning}
            className={`flex items-center justify-center px-6 py-2 border border-transparent text-base font-medium rounded-md text-white bg-brand-orange hover:bg-orange-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-brand-orange transition-all ${isRunning ? 'opacity-75 cursor-not-allowed' : ''
              }`}
            aria-busy={isRunning}
          >
            {isRunning ? (
              <div role="status" className="flex items-center">
                <div className="spinner w-5 h-5 border-2 mr-2 border-white border-l-transparent" aria-hidden="true"></div>
                <span>Running Audit...</span>
                <span className="sr-only">Please wait while the audit completes.</span>
              </div>
            ) : (
              <>
                <Play className="w-5 h-5 mr-2" aria-hidden="true" />
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
