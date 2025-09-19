// Types compartilhados entre cliente e servidor

export interface OAuthClient {
  client_id: string;
  client_secret: string;
  redirect_uris: string[];
  grant_types: string[];
  scopes: string[];
}

export interface AuthorizationRequest {
  client_id: string;
  redirect_uri: string;
  response_type: 'code';
  scope?: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: 'S256' | 'plain';
}

export interface TokenRequest {
  grant_type: 'authorization_code' | 'client_credentials';
  client_id: string;
  client_secret?: string;
  code?: string;
  redirect_uri?: string;
  code_verifier?: string;
  scope?: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  token_type: 'Bearer';
  expires_in: number;
  scope: string;
}

export interface AuthorizationResponse {
  message: string;
  authorization_code: string;
  redirect_url: string;
  expires_in: number;
  flow_type: string;
}

export interface ApiResponse {
  user_id: string;
  name: string;
  email: string;
  scope: string;
  client_id: string;
}

export interface RequestLog {
  id: string;
  timestamp: number;
  method: 'GET' | 'POST';
  url: string;
  headers: Record<string, string>;
  body?: any;
  response?: any;
  status?: number;
}

export type OAuthFlow = 'authorization_code' | 'pkce' | 'client_credentials';
