import api from './api';
import { ApiResponse, Tunnel, TunnelCidrRoute, TunnelHostnameRoute } from '@/types';

export const getTunnels = async (
  credentialId: number,
  accountId?: string
): Promise<ApiResponse<{ accountId: string; tunnels: Tunnel[] }>> => {
  return api.get('/tunnels', { params: { credentialId, accountId } });
};

export const getTunnelAccounts = async (credentialId: number): Promise<ApiResponse<{ accounts: Array<{ id: string; name?: string }> }>> =>
  api.get('/tunnels/accounts', { params: { credentialId } });

export const getTunnelZones = async (credentialId: number, accountId?: string): Promise<ApiResponse<{ zones: Array<{ id: string; name: string }> }>> =>
  api.get('/tunnels/zones', { params: { credentialId, accountId } });

export const getTunnelConfig = async (
  tunnelId: string,
  credentialId: number,
  accountId?: string
): Promise<ApiResponse<{ config: any }>> => {
  return api.get(`/tunnels/${tunnelId}/config`, { params: { credentialId, accountId } });
};

export const createTunnel = async (
  name: string,
  credentialId: number,
  accountId?: string
): Promise<ApiResponse<{ tunnel: Tunnel }>> => {
  return api.post('/tunnels', { name }, { params: { credentialId, accountId } });
};

export const updateTunnelConfig = async (
  tunnelId: string,
  config: any,
  credentialId: number,
  accountId?: string
): Promise<ApiResponse<{ config: any }>> => {
  return api.put(`/tunnels/${tunnelId}/config`, { config }, { params: { credentialId, accountId } });
};

export const upsertTunnelPublicHostname = async (
  tunnelId: string,
  params: { hostname: string; service: string; path?: string; zoneId?: string },
  credentialId: number,
  accountId?: string
): Promise<ApiResponse<{ config: any; dns?: { action: 'created' | 'updated' | 'unchanged' } }>> => {
  return api.post(`/tunnels/${tunnelId}/public-hostnames`, params, { params: { credentialId, accountId } });
};

export const deleteTunnelPublicHostname = async (
  tunnelId: string,
  params: { hostname: string; path?: string; zoneId?: string; deleteDns?: boolean },
  credentialId: number,
  accountId?: string
): Promise<ApiResponse<{ config: any; dns?: { deleted?: boolean; reason?: string } }>> => {
  return api.delete(`/tunnels/${tunnelId}/public-hostnames`, { params: { credentialId, accountId }, data: params });
};

export const deleteTunnel = async (
  tunnelId: string,
  credentialId: number,
  options?: { cleanupDns?: boolean },
  accountId?: string
): Promise<ApiResponse<{ cleanup?: { matched: number; deleted: number; errors: Array<{ hostname: string; message: string }> } }>> => {
  return api.delete(`/tunnels/${tunnelId}`, {
    params: { credentialId, accountId, ...(options?.cleanupDns ? { cleanupDns: 1 } : {}) },
  });
};

export const getTunnelToken = async (
  tunnelId: string,
  credentialId: number,
  accountId?: string
): Promise<ApiResponse<{ token: string }>> => {
  return api.get(`/tunnels/${tunnelId}/token`, { params: { credentialId, accountId } });
};

export const getTunnelCidrRoutes = async (
  tunnelId: string,
  credentialId: number,
  accountId?: string
): Promise<ApiResponse<{ routes: TunnelCidrRoute[] }>> => {
  return api.get(`/tunnels/${tunnelId}/routes/cidr`, { params: { credentialId, accountId } });
};

export const createTunnelCidrRoute = async (
  tunnelId: string,
  params: { network: string; comment?: string; virtualNetworkId?: string },
  credentialId: number,
  accountId?: string
): Promise<ApiResponse<{ route: TunnelCidrRoute }>> => {
  return api.post(`/tunnels/${tunnelId}/routes/cidr`, params, { params: { credentialId, accountId } });
};

export const deleteTunnelCidrRoute = async (
  tunnelId: string,
  routeId: string,
  credentialId: number,
  accountId?: string
): Promise<ApiResponse<{ routeId: string }>> => {
  return api.delete(`/tunnels/${tunnelId}/routes/cidr/${routeId}`, { params: { credentialId, accountId } });
};

export const getTunnelHostnameRoutes = async (
  tunnelId: string,
  credentialId: number,
  accountId?: string
): Promise<ApiResponse<{ routes: TunnelHostnameRoute[] }>> => {
  return api.get(`/tunnels/${tunnelId}/routes/hostname`, { params: { credentialId, accountId } });
};

export const createTunnelHostnameRoute = async (
  tunnelId: string,
  params: { hostname: string; comment?: string },
  credentialId: number,
  accountId?: string
): Promise<ApiResponse<{ route: TunnelHostnameRoute }>> => {
  return api.post(`/tunnels/${tunnelId}/routes/hostname`, params, { params: { credentialId, accountId } });
};

export const deleteTunnelHostnameRoute = async (
  tunnelId: string,
  routeId: string,
  credentialId: number,
  accountId?: string
): Promise<ApiResponse<{ routeId: string }>> => {
  return api.delete(`/tunnels/${tunnelId}/routes/hostname/${routeId}`, { params: { credentialId, accountId } });
};
