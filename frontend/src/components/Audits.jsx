import React, { useState } from 'react';
import { Play, Server, User, Terminal, Lock, Key } from 'lucide-react';

const INITIAL_CONFIG = {
  server: '',
  user: '',
  port: '22',
  mode: 'text',
  passphrase: '',
  password: '',
  options: {
    fast: false,
    silent: false,
  },
};

const Audits = ({ onRunAudit, onClear, isRunning }) => {
  const [config, setConfig] = useState(INITIAL_CONFIG);
  const [resetKey, setResetKey] = useState(0);

  const [showPassphrase, setShowPassphrase] = useState(false);
  const [showPasswordAuth, setShowPasswordAuth] = useState(false);
  const [passphraseMessage, setPassphraseMessage] = useState('');

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

  const handleReset = () => {
    if (onClear) onClear();
    setConfig(INITIAL_CONFIG);
    setShowPassphrase(false);
    setShowPasswordAuth(false);
    setPassphraseMessage('');
    setResetKey(prev => prev + 1);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setPassphraseMessage('');

    try {
      await onRunAudit(config);
    } catch (error) {
      // Handle specific PassphraseRequired error
      if (error.code === "PASSPHRASE_REQUIRED") {
        setShowPassphrase(true);
        setPassphraseMessage("Key is encrypted. Please enter passphrase below.");
      }
    }
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

      <form key={resetKey} onSubmit={handleSubmit}>
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
                pattern="^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^localhost$"
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
            >
              <option value="text">Text Report</option>
              <option value="json">JSON Data</option>
              <option value="html">HTML Page</option>
              <option value="csv">CSV Export</option>
            </select>
          </div>
        </div>

        {/* Authentication Section */}
        <div className="bg-gray-50 p-4 rounded-md border border-gray-200 mb-6">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-sm font-medium text-gray-900 flex items-center">
              <Lock className="w-4 h-4 mr-2" /> Authentication
            </h3>
            <button
              type="button"
              onClick={() => setShowPasswordAuth(!showPasswordAuth)}
              className="text-xs text-brand-blue hover:underline"
            >
              {showPasswordAuth ? 'Hide Password Auth' : 'Use Password Auth'}
            </button>
          </div>

          {/* Inline Error Message for Passphrase */}
          {passphraseMessage && (
            <div className="mb-4 p-2 bg-red-50 border border-red-200 rounded text-sm text-red-600 flex items-center">
              <Key className="w-4 h-4 mr-2" />
              {passphraseMessage}
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Passphrase Input (Conditional) */}
            {showPassphrase && (
              <div className="col-span-2 animate-fade-in">
                <label className="block text-sm font-medium text-red-600 mb-1">
                  SSH Key Passphrase (Required)
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <Key className="h-5 w-5 text-red-400" aria-hidden="true" />
                  </div>
                  <input
                    type="password"
                    name="passphrase"
                    className="pl-10 w-full rounded-md border-red-300 focus:border-red-500 focus:ring-red-500 sm:text-sm py-2 border"
                    placeholder="Enter passphrase to unlock key..."
                    value={config.passphrase}
                    onChange={handleChange}
                    autoFocus
                  />
                </div>
              </div>
            )}

            {/* Password Input (Toggleable) */}
            {showPasswordAuth && (
              <div className="col-span-2 animate-fade-in">
                <label className="block text-sm font-medium text-gray-700 mb-1">SSH Password</label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <Lock className="h-5 w-5 text-gray-400" aria-hidden="true" />
                  </div>
                  <input
                    type="password"
                    name="password"
                    className="pl-10 w-full rounded-md border-gray-300 shadow-sm focus:border-brand-blue focus:ring-brand-blue sm:text-sm py-2 border"
                    placeholder="Enter password if not using keys..."
                    value={config.password}
                    onChange={handleChange}
                  />
                </div>
              </div>
            )}
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

          <div className="flex space-x-4">
            <button
              type="button"
              onClick={handleReset}
              className="px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-brand-blue"
            >
              Clear Form
            </button>
            <button
              type="submit"
              disabled={isRunning}
              className={`flex items-center justify-center px-6 py-2 border border-transparent text-base font-medium rounded-md text-white bg-brand-orange hover:bg-orange-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-brand-orange transition-all ${isRunning ? 'opacity-75 cursor-not-allowed' : ''
                }`}
            >
              {isRunning ? (
                <div role="status" className="flex items-center">
                  <div className="spinner w-5 h-5 border-2 mr-2 border-white border-l-transparent" aria-hidden="true"></div>
                  <span>Running Audit...</span>
                </div>
              ) : (
                <>
                  <Play className="w-5 h-5 mr-2" aria-hidden="true" />
                  Start Audit
                </>
              )}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
};

export default Audits;
