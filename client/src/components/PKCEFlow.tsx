import React, { useState } from 'react';
import { OAuthClient, RequestLog, AuthorizationResponse, TokenResponse, ApiResponse } from '../../../shared/types';
import { getApiUrl } from '../utils/api';

interface PKCEFlowProps {
  client: OAuthClient;
  onRequestLog: (log: RequestLog) => void;
}

const PKCEFlow: React.FC<PKCEFlowProps> = ({ client, onRequestLog }) => {
  const [step, setStep] = useState<number>(1);
  const [codeVerifier, setCodeVerifier] = useState<string>('');
  const [codeChallenge, setCodeChallenge] = useState<string>('');
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

  // Gerar code_verifier e code_challenge
  const generatePKCECodes = () => {
    // Gerar code_verifier (43-128 caracteres)
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const verifier = btoa(String.fromCharCode.apply(null, Array.from(array)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
    
    // Gerar code_challenge (SHA256 hash do verifier)
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    
    crypto.subtle.digest('SHA-256', data).then(hash => {
      const challenge = btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(hash))))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
      
      setCodeVerifier(verifier);
      setCodeChallenge(challenge);
      setStep(2);
    });
  };

  const step2_GetAuthCode = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        client_id: client.client_id,
        redirect_uri: client.redirect_uris[0],
        response_type: 'code',
        scope: 'read',
        state: 'demo-state-pkce',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256'
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
        setStep(3);
      } else {
        alert('Erro ao obter código de autorização: ' + JSON.stringify(data));
      }
    } catch (error) {
      alert('Erro na requisição: ' + error);
    } finally {
      setLoading(false);
    }
  };

  const step3_ExchangeCodeForToken = async () => {
    setLoading(true);
    try {
      const body = {
        grant_type: 'authorization_code',
        client_id: client.client_id,
        code: authCode,
        redirect_uri: client.redirect_uris[0],
        code_verifier: codeVerifier
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
        setStep(4);
      } else {
        alert('Erro ao trocar código por token: ' + JSON.stringify(data));
      }
    } catch (error) {
      alert('Erro na requisição: ' + error);
    } finally {
      setLoading(false);
    }
  };

  const step4_UseToken = async () => {
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
        setStep(5);
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
    setCodeVerifier('');
    setCodeChallenge('');
    setAuthCode('');
    setAccessToken('');
    setTokenResponse(null);
    setProfileData(null);
  };

  return (
    <div className="oauth-flow">
      <div className="flow-header">
        <h3>PKCE (Proof Key for Code Exchange)</h3>
        <p>Versão segura do Authorization Code para SPAs e aplicações móveis.</p>
      </div>

      <div className="flow-steps">
        <div className={`step ${step >= 1 ? 'active' : ''} ${step > 1 ? 'completed' : ''}`}>
          <div className="step-header">
            <span className="step-number">1</span>
            <h4>Gerar PKCE Codes</h4>
          </div>
          <div className="step-content">
            <p>Gerar code_verifier aleatório e code_challenge (SHA256 hash).</p>
            <button 
              onClick={generatePKCECodes} 
              disabled={loading || step > 1}
              className="btn-primary"
            >
              Gerar Códigos PKCE
            </button>
            {codeVerifier && (
              <div className="result">
                <strong>PKCE Codes gerados:</strong>
                <div className="pkce-codes">
                  <p><strong>Code Verifier:</strong> <code>{codeVerifier.substring(0, 20)}...</code></p>
                  <p><strong>Code Challenge:</strong> <code>{codeChallenge.substring(0, 20)}...</code></p>
                  <p><strong>Method:</strong> S256</p>
                </div>
              </div>
            )}
          </div>
        </div>

        <div className={`step ${step >= 2 ? 'active' : ''} ${step > 2 ? 'completed' : ''}`}>
          <div className="step-header">
            <span className="step-number">2</span>
            <h4>Obter Código de Autorização</h4>
          </div>
          <div className="step-content">
            <p>Redirecionar usuário com code_challenge incluído na requisição.</p>
            <button 
              onClick={step2_GetAuthCode} 
              disabled={loading || step !== 2}
              className="btn-primary"
            >
              {loading && step === 2 ? 'Solicitando...' : 'Solicitar Autorização'}
            </button>
            {authCode && (
              <div className="result">
                <strong>Código de autorização obtido:</strong>
                <code>{authCode}</code>
              </div>
            )}
          </div>
        </div>

        <div className={`step ${step >= 3 ? 'active' : ''} ${step > 3 ? 'completed' : ''}`}>
          <div className="step-header">
            <span className="step-number">3</span>
            <h4>Trocar Código por Token</h4>
          </div>
          <div className="step-content">
            <p>Trocar código + code_verifier por access token (sem client_secret).</p>
            <button 
              onClick={step3_ExchangeCodeForToken} 
              disabled={loading || step !== 3}
              className="btn-primary"
            >
              {loading && step === 3 ? 'Trocando...' : 'Trocar por Token'}
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

        <div className={`step ${step >= 4 ? 'active' : ''} ${step > 4 ? 'completed' : ''}`}>
          <div className="step-header">
            <span className="step-number">4</span>
            <h4>Usar Token para Acessar Recurso</h4>
          </div>
          <div className="step-content">
            <p>Usar o access token para acessar recursos protegidos na API.</p>
            <button 
              onClick={step4_UseToken} 
              disabled={loading || step !== 4}
              className="btn-primary"
            >
              {loading && step === 4 ? 'Acessando...' : 'Acessar Perfil'}
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

        {step === 5 && (
          <div className="step active completed">
            <div className="step-header">
              <span className="step-number">✓</span>
              <h4>Fluxo Concluído!</h4>
            </div>
            <div className="step-content">
              <p>O fluxo PKCE foi executado com sucesso.</p>
              <button onClick={reset} className="btn-secondary">
                Executar Novamente
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="flow-explanation">
        <h4>Como funciona o PKCE:</h4>
        <ol>
          <li><strong>Code Verifier:</strong> Cliente gera string aleatória (43-128 caracteres)</li>
          <li><strong>Code Challenge:</strong> SHA256 hash do code_verifier</li>
          <li><strong>Autorização:</strong> Envia code_challenge na requisição de autorização</li>
          <li><strong>Token:</strong> Envia code_verifier (não client_secret) para trocar por token</li>
          <li><strong>Validação:</strong> Servidor verifica se SHA256(code_verifier) = code_challenge</li>
        </ol>
        <div className="security-benefits">
          <h5>Benefícios de Segurança:</h5>
          <ul>
            <li>Não requer client_secret (seguro para SPAs)</li>
            <li>Protege contra ataques de interceptação de código</li>
            <li>Code_verifier nunca é transmitido na URL</li>
            <li>Cada requisição usa códigos únicos</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default PKCEFlow;
