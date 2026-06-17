import api from './api';
import { ApiResponse } from '@/types';

export interface ApiToken {
  id: number;
  name: string;
  prefix: string;
  lastUsedAt: string | null;
  createdAt: string;
}

export interface ApiTokenCreated extends ApiToken {
  token: string;
}

export async function getApiTokens(): Promise<ApiResponse<ApiToken[]>> {
  const res = await api.get('/api-tokens');
  return res as unknown as ApiResponse<ApiToken[]>;
}

export async function createApiToken(name: string): Promise<ApiResponse<ApiTokenCreated>> {
  const res = await api.post('/api-tokens', { name });
  return res as unknown as ApiResponse<ApiTokenCreated>;
}

export async function deleteApiToken(id: number): Promise<ApiResponse> {
  const res = await api.delete(`/api-tokens/${id}`);
  return res as unknown as ApiResponse;
}