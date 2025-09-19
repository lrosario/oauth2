export const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:3001';

export const getApiUrl = (endpoint: string) => {
  return `${API_BASE_URL}${endpoint}`;
};