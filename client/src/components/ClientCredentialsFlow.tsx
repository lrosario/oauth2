import React, { useState } from 'react';
import { OAuthClient, RequestLog, TokenResponse, ApiResponse } from '../../../shared/types';
import { getApiUrl } from '../utils/api';

interface ClientCredentialsFlowProps {
  client: OAuthClient;
  onRequestLog: (log: RequestLog) => void;
}

const ClientCredentialsFlow: React.FC<ClientCredentialsFlowProps> = ({ client, onRequestLog }) => {
  const [step, setStep] = useState<number>(1);
  const [accessToken, setAccessToken] = useState<string>('');
  const [tokenResponse, setTokenResponse] = useState<TokenResponse | null>(null);
  const [profileData, setProfileData] = useState<ApiResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [selectedScope, setSelectedScope] = useState<string>('read');

  const logRequest = (method: 'GET' | 'POST', url: string, headers: Record<string, string>, body?: any, response?: any, status?: number) => {
    const log: RequestLog = {
      id: Date.now().toString(),
      timestamp: Date.now(),
      method,
      url,
      headers,
      body,
      response,
      status
    };
    onRequestLog(log);
  };

  const step1_GetToken = async () => {
    setLoading(true);
    try {
      const body = {
        grant_type: 'client_credentials',
        client_id: client.client_id,
        client_secret: client.client_secret,
        scope: selectedScope
      };

      const url = getApiUrl('/oauth/token');
      
      logRequest('POST', url, {
        'Content-Type': 'application/json'
      }, body);

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
      });

      const data: TokenResponse = await response.json();

      logRequest('POST', url, {
        'Content-Type': 'application/json'
      }, body, data, response.status);

      if (response.ok) {
        setAccessToken(data.access_token);
        setTokenResponse(data);
        setStep(2);
      } else {
        alert('Erro ao obter access token: ' + JSON.stringify(data));
      }
    } catch (error) {
      alert('Erro na requisição: ' + error);
    } finally {
      setLoading(false);
    }
  };

  const step2_UseToken = async () => {
    setLoading(true);
    try {
      const url = getApiUrl('/api/profile');
      const headers = {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json'
      };

      logRequest('GET', url, headers);

      const response = await fetch(url, { headers });
      const data: ApiResponse = await response.json();

      logRequest('GET', url, headers, undefined, data, response.status);

      if (response.ok) {
        setProfileData(data);
        setStep(3);
      } else {
        alert('Erro ao acessar recurso protegido: ' + JSON.stringify(data));
      }
    } catch (error) {
      alert('Erro na requisição: ' + error);
    } finally {
      setLoading(false);
    }
  };

  const reset = () => {
    setStep(1);
    setAccessToken('');
    setTokenResponse(null);
    setProfileData(null);
    setSelectedScope('read');
  };

  return (
    <div className="oauth-flow">
      <div className="flow-header">
        <h3>Client Credentials Flow</h3>
        <p>Fluxo para autenticação servidor-para-servidor sem envolvimento do usuário.</p>
      </div>

      <div className="flow-steps">
        <div className={`step ${step >= 1 ? 'active' : ''} ${step > 1 ? 'completed' : ''}`}>
          <div className="step-header">
            <span className="step-number">1</span>
            <h4>Obter Access Token Diretamente</h4>
          </div>
          <div className="step-content">
            <p>Cliente autentica diretamente com client_id e client_secret.</p>
            
            <div className="scope-selector">
              <label htmlFor="scope">Escolher Scope:</label>
              <select 
                id="scope"
                value={selectedScope} 
                onChange={(e) => setSelectedScope(e.target.value)}
                disabled={step > 1}
              >
                <option value="read">read</option>
                <option value="write">write</option>
                <option value="read write">read write</option>
              </select>
            </div>

            <button 
              onClick={step1_GetToken} 
              disabled={loading || step > 1}
              className="btn-primary"
            >
              {loading && step === 1 ? 'Obtendo Token...' : 'Obter Access Token'}
            </button>
            
            {tokenResponse && (
              <div className="result">
                <strong>Access Token obtido:</strong>
                <div className="token-info">
                  <p><strong>Token:</strong> <code>{accessToken.substring(0, 20)}...</code></p>
                  <p><strong>Type:</strong> {tokenResponse.token_type}</p>
                  <p><strong>Expires in:</strong> {tokenResponse.expires_in}s</p>
                  <p><strong>Scope:</strong> {tokenResponse.scope}</p>
                </div>
              </div>
            )}
          </div>
        </div>

        <div className={`step ${step >= 2 ? 'active' : ''} ${step > 2 ? 'completed' : ''}`}>
          <div className="step-header">
            <span className="step-number">2</span>
            <h4>Usar Token para Acessar Recurso</h4>
          </div>
          <div className="step-content">
            <p>Usar o access token para acessar recursos protegidos na API.</p>
            <button 
              onClick={step2_UseToken} 
              disabled={loading || step !== 2}
              className="btn-primary"
            >
              {loading && step === 2 ? 'Acessando...' : 'Acessar Perfil'}
            </button>
            {profileData && (
              <div className="result">
                <strong>Dados do perfil obtidos:</strong>
                <div className="profile-info">
                  <p><strong>User ID:</strong> {profileData.user_id}</p>
                  <p><strong>Nome:</strong> {profileData.name}</p>
                  <p><strong>Email:</strong> {profileData.email}</p>
                  <p><strong>Scope:</strong> {profileData.scope}</p>
                  <p><strong>Client ID:</strong> {profileData.client_id}</p>
                </div>
              </div>
            )}
          </div>
        </div>

        {step === 3 && (
          <div className="step active completed">
            <div className="step-header">
              <span className="step-number">✓</span>
              <h4>Fluxo Concluído!</h4>
            </div>
            <div className="step-content">
              <p>O fluxo Client Credentials foi executado com sucesso.</p>
              <button onClick={reset} className="btn-secondary">
                Executar Novamente
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="flow-explanation">
        <h4>Como funciona o Client Credentials Flow:</h4>
        <ol>
          <li><strong>Autenticação:</strong> Cliente envia client_id, client_secret e scope</li>
          <li><strong>Token:</strong> Servidor valida credenciais e retorna access token</li>
          <li><strong>Acesso:</strong> Cliente usa token para acessar recursos em nome próprio</li>
        </ol>
        
        <div className="use-cases">
          <h5>Casos de Uso Típicos:</h5>
          <ul>
            <li>APIs backend-to-backend</li>
            <li>Serviços automatizados (cron jobs, scripts)</li>
            <li>Microserviços comunicando entre si</li>
            <li>Aplicações daemon/background</li>
            <li>CLIs e ferramentas de linha de comando</li>
          </ul>
        </div>

        <div className="security-notes">
          <h5>Considerações de Segurança:</h5>
          <ul>
            <li>Não há usuário final envolvido no processo</li>
            <li>Cliente age em nome próprio, não de um usuário</li>
            <li>Client_secret deve ser mantido seguro</li>
            <li>Ideal para ambientes onde o secret pode ser protegido</li>
            <li>Tokens podem ter escopos limitados por segurança</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default ClientCredentialsFlow;
