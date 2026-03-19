import api from './api';
import type { ApiResponse } from '@/types';

export interface DomainAccelerationConfig {
  id: number;
  dnsCredentialId: number;
  zoneName: string;
  pluginProvider: string;
  pluginCredentialId: number;
  remoteSiteId: string;
  siteStatus: string;
  verifyStatus: string;
  verified: boolean;
  paused: boolean;
  accessType: string;
  area: string;
  planId?: string;
  verifyRecordName?: string;
  verifyRecordType?: string;
  verifyRecordValue?: string;
  lastError?: string;
  lastSyncedAt?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface EnableAccelerationPayload {
  zoneName: string;
  zoneId?: string;
  dnsCredentialId: number;
  pluginCredentialId: number;
  autoDnsRecord?: boolean;
}

export interface EnableAccelerationResult {
  config: DomainAccelerationConfig;
  dnsRecordsAdded?: Array<{ zoneName: string; type: string; name: string; value: string }>;
  dnsErrors?: Array<{ error: string; name?: string }>;
}

export async function listAccelerationConfigs(params?: {
  dnsCredentialId?: number;
  zoneName?: string;
  refresh?: boolean;
}): Promise<ApiResponse<{ items: DomainAccelerationConfig[] }>> {
  const response = await api.get('/accelerations/configs', { params });
  return response as unknown as ApiResponse<{ items: DomainAccelerationConfig[] }>;
}

export async function enableAcceleration(
  data: EnableAccelerationPayload,
): Promise<ApiResponse<EnableAccelerationResult>> {
  const response = await api.post('/accelerations/enable', data);
  return response as unknown as ApiResponse<EnableAccelerationResult>;
}

export async function verifyAcceleration(data: {
  zoneName: string;
  dnsCredentialId: number;
}): Promise<ApiResponse<{ config: DomainAccelerationConfig }>> {
  const response = await api.post('/accelerations/verify', data);
  return response as unknown as ApiResponse<{ config: DomainAccelerationConfig }>;
}

export async function syncAcceleration(data: {
  zoneName: string;
  dnsCredentialId: number;
}): Promise<ApiResponse<{ config: DomainAccelerationConfig }>> {
  const response = await api.post('/accelerations/sync', data);
  return response as unknown as ApiResponse<{ config: DomainAccelerationConfig }>;
}

export async function disableAcceleration(data: {
  zoneName: string;
  dnsCredentialId: number;
}): Promise<ApiResponse<{ deleted: boolean }>> {
  const response = await api.post('/accelerations/disable', data);
  return response as unknown as ApiResponse<{ deleted: boolean }>;
}
