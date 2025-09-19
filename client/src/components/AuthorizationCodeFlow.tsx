import React, { useState } from 'react';
import { OAuthClient, RequestLog, AuthorizationResponse, TokenResponse, ApiResponse } from '../../../shared/types';
import { getApiUrl } from '../utils/api';

interface AuthorizationCodeFlowProps {
  client: OAuthClient;
  onRequestLog: (log: RequestLog) => void;
}

const AuthorizationCodeFlow: React.FC<AuthorizationCodeFlowProps> = ({ client, onRequestLog }) => {
  const [step, setStep] = useState<number>(1);
  const [authCode, setAuthCode] = useState<string>('');
  const [accessToken, setAccessToken] = useState<string>('');
  const [tokenResponse, setTokenResponse] = useState<TokenResponse | null>(null);
  const [profileData, setProfileData] = useState<ApiResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

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

  const step1_GetAuthCode = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        client_id: client.client_id,
        redirect_uri: client.redirect_uris[0],
        response_type: 'code',
        scope: 'read',
        state: 'demo-state'
      });

      const url = `${getApiUrl('/oauth/authorize')}?${params}`;
      
      logRequest('GET', url, {
        'Accept': 'application/json'
      });

      const response = await fetch(url);
      const data: AuthorizationResponse = await response.json();

      logRequest('GET', url, {
        'Accept': 'application/json'
      }, undefined, data, response.status);

      if (response.ok) {
        setAuthCode(data.authorization_code);
        setStep(2);
      } else {
        alert('Erro ao obter código de autorização: ' + JSON.stringify(data));
      }
    } catch (error) {
      alert('Erro na requisição: ' + error);
    } finally {
      setLoading(false);
    }
  };

  const step2_ExchangeCodeForToken = async () => {
    setLoading(true);
    try {
      const body = {
        grant_type: 'authorization_code',
        client_id: client.client_id,
        client_secret: client.client_secret,
        code: authCode,
        redirect_uri: client.redirect_uris[0]
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
        setStep(3);
      } else {
        alert('Erro ao trocar código por token: ' + JSON.stringify(data));
      }
    } catch (error) {
      alert('Erro na requisição: ' + error);
    } finally {
      setLoading(false);
    }
  };

  const step3_UseToken = async () => {
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
        setStep(4);
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
    setAuthCode('');
    setAccessToken('');
    setTokenResponse(null);
    setProfileData(null);
  };

  return (
    <div className="oauth-flow">
      <div className="flow-header">
        <h3>Authorization Code Flow</h3>
        <p>Este é o fluxo OAuth mais comum para aplicações web com backend seguro.</p>
      </div>

      <div className="flow-steps">
        <div className={`step ${step >= 1 ? 'active' : ''} ${step > 1 ? 'completed' : ''}`}>
          <div className="step-header">
            <span className="step-number">1</span>
            <h4>Obter Código de Autorização</h4>
          </div>
          <div className="step-content">
            <p>O cliente redireciona o usuário para o servidor de autorização.</p>
            <button 
              onClick={step1_GetAuthCode} 
              disabled={loading || step > 1}
              className="btn-primary"
            >
              {loading && step === 1 ? 'Solicitando...' : 'Solicitar Autorização'}
            </button>
            {authCode && (
              <div className="result">
                <strong>Código de autorização obtido:</strong>
                <code>{authCode}</code>
              </div>
            )}
          </div>
        </div>

        <div className={`step ${step >= 2 ? 'active' : ''} ${step > 2 ? 'completed' : ''}`}>
          <div className="step-header">
            <span className="step-number">2</span>
            <h4>Trocar Código por Token</h4>
          </div>
          <div className="step-content">
            <p>O backend do cliente troca o código de autorização por um access token.</p>
            <button 
              onClick={step2_ExchangeCodeForToken} 
              disabled={loading || step !== 2}
              className="btn-primary"
            >
              {loading && step === 2 ? 'Trocando...' : 'Trocar por Token'}
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

        <div className={`step ${step >= 3 ? 'active' : ''} ${step > 3 ? 'completed' : ''}`}>
          <div className="step-header">
            <span className="step-number">3</span>
            <h4>Usar Token para Acessar Recurso</h4>
          </div>
          <div className="step-content">
            <p>Usar o access token para acessar recursos protegidos na API.</p>
            <button 
              onClick={step3_UseToken} 
              disabled={loading || step !== 3}
              className="btn-primary"
            >
              {loading && step === 3 ? 'Acessando...' : 'Acessar Perfil'}
            </button>
            {profileData && (
              <div className="result">
                <strong>Dados do perfil obtidos:</strong>
                <div className="profile-info">
                  <p><strong>User ID:</strong> {profileData.user_id}</p>
                  <p><strong>Nome:</strong> {profileData.name}</p>
                  <p><strong>Email:</strong> {profileData.email}</p>
                  <p><strong>Scope:</strong> {profileData.scope}</p>
                </div>
              </div>
            )}
          </div>
        </div>

        {step === 4 && (
          <div className="step active completed">
            <div className="step-header">
              <span className="step-number">✓</span>
              <h4>Fluxo Concluído!</h4>
            </div>
            <div className="step-content">
              <p>O fluxo Authorization Code foi executado com sucesso.</p>
              <button onClick={reset} className="btn-secondary">
                Executar Novamente
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="flow-explanation">
        <h4>Como funciona o Authorization Code Flow:</h4>
        <ol>
          <li><strong>Redirecionamento:</strong> Cliente redireciona usuário para servidor de autorização</li>
          <li><strong>Autorização:</strong> Usuário autoriza o acesso (simulado automaticamente)</li>
          <li><strong>Código:</strong> Servidor retorna código de autorização para o cliente</li>
          <li><strong>Token:</strong> Cliente troca código + client_secret por access token</li>
          <li><strong>Acesso:</strong> Cliente usa token para acessar recursos protegidos</li>
        </ol>
        <p><strong>Segurança:</strong> O client_secret nunca é exposto ao navegador, apenas no backend.</p>
      </div>
    </div>
  );
};

export default AuthorizationCodeFlow;
