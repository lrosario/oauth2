import React, { useState, useEffect } from 'react';
import './App.css';
import { OAuthFlow, RequestLog, OAuthClient } from '../../shared/types';
import AuthorizationCodeFlow from './components/AuthorizationCodeFlow';
import PKCEFlow from './components/PKCEFlow';
import ClientCredentialsFlow from './components/ClientCredentialsFlow';
import RequestLogger from './components/RequestLogger';
import FlowSelector from './components/FlowSelector';
import { getApiUrl } from './utils/api';

const App: React.FC = () => {
  const [selectedFlow, setSelectedFlow] = useState<OAuthFlow>('authorization_code');
  const [requestLogs, setRequestLogs] = useState<RequestLog[]>([]);
  const [client, setClient] = useState<OAuthClient | null>(null);

  useEffect(() => {
    // Carregar informações do cliente demo
    fetch(getApiUrl('/oauth/clients/demo'))
      .then(response => response.json())
      .then(data => setClient(data))
      .catch(error => console.error('Error loading client info:', error));
  }, []);

  const addRequestLog = (log: RequestLog) => {
    setRequestLogs(prev => [log, ...prev]);
  };

  const clearLogs = () => {
    setRequestLogs([]);
  };

  if (!client) {
    return (
      <div className="app">
        <div className="loading">
          <h2>Loading OAuth Playground...</h2>
          <p>Make sure the OAuth server is running on port 3001</p>
        </div>
      </div>
    );
  }

  return (
    <div className="app">
      <header className="app-header">
        <h1>OAuth 2.0 Playground</h1>
        <p>Aprenda os fluxos OAuth 2.0 de forma interativa</p>
      </header>

      <div className="app-content">
        <div className="left-panel">
          <FlowSelector 
            selectedFlow={selectedFlow} 
            onFlowChange={setSelectedFlow}
          />
          
          <div className="client-info">
            <h3>Informações do Cliente</h3>
            <div className="info-grid">
              <div>
                <label>Client ID:</label>
                <code>{client.client_id}</code>
              </div>
              <div>
                <label>Client Secret:</label>
                <code>{client.client_secret}</code>
              </div>
              <div>
                <label>Redirect URI:</label>
                <code>{client.redirect_uris[0]}</code>
              </div>
              <div>
                <label>Grant Types:</label>
                <code>{client.grant_types.join(', ')}</code>
              </div>
            </div>
          </div>

          <div className="flow-container">
            {selectedFlow === 'authorization_code' && (
              <AuthorizationCodeFlow 
                client={client}
                onRequestLog={addRequestLog}
              />
            )}
            {selectedFlow === 'pkce' && (
              <PKCEFlow 
                client={client}
                onRequestLog={addRequestLog}
              />
            )}
            {selectedFlow === 'client_credentials' && (
              <ClientCredentialsFlow 
                client={client}
                onRequestLog={addRequestLog}
              />
            )}
          </div>
        </div>

        <div className="right-panel">
          <RequestLogger 
            logs={requestLogs}
            onClear={clearLogs}
          />
        </div>
      </div>
    </div>
  );
};

export default App;
