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

export interface RemoteAccelerationSite {
  provider: string;
  remoteSiteId: string;
  zoneName: string;
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
}

export interface DiscoveredAccelerationSite {
  pluginCredentialId: number;
  pluginCredentialName: string;
  pluginProvider: string;
  site: RemoteAccelerationSite;
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
  dnsRecordsSkipped?: Array<{ zoneName: string; type: string; name: string; value: string }>;
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

export async function discoverAccelerationSites(params: {
  zoneName: string;
  pluginCredentialId?: number;
}): Promise<ApiResponse<{ items: DiscoveredAccelerationSite[] }>> {
  const response = await api.get('/accelerations/discover', { params });
  return response as unknown as ApiResponse<{ items: DiscoveredAccelerationSite[] }>;
}

export async function listRemoteAccelerationSites(params?: {
  zoneName?: string;
  pluginCredentialId?: number;
}): Promise<ApiResponse<{ items: DiscoveredAccelerationSite[] }>> {
  const response = await api.get('/accelerations/remote-sites', { params });
  return response as unknown as ApiResponse<{ items: DiscoveredAccelerationSite[] }>;
}

export async function importRemoteAcceleration(data: {
  zoneName: string;
  zoneId?: string;
  dnsCredentialId: number;
  pluginCredentialId: number;
  remoteSiteId?: string;
  autoDnsRecord?: boolean;
}): Promise<ApiResponse<EnableAccelerationResult>> {
  const response = await api.post('/accelerations/import-remote', data);
  return response as unknown as ApiResponse<EnableAccelerationResult>;
}

export async function setAccelerationSiteStatus(data: {
  zoneName: string;
  dnsCredentialId?: number;
  pluginCredentialId?: number;
  remoteSiteId?: string;
  enabled: boolean;
}): Promise<ApiResponse<{ config?: DomainAccelerationConfig; site?: RemoteAccelerationSite }>> {
  const response = await api.post('/accelerations/site-status', data);
  return response as unknown as ApiResponse<{ config?: DomainAccelerationConfig; site?: RemoteAccelerationSite }>;
}

export async function deleteRemoteAcceleration(data: {
  zoneName: string;
  dnsCredentialId?: number;
  pluginCredentialId?: number;
  remoteSiteId?: string;
  deleteLocalConfig?: boolean;
}): Promise<ApiResponse<{ deleted: boolean; localDeleted?: boolean }>> {
  const response = await api.post('/accelerations/delete-remote', data);
  return response as unknown as ApiResponse<{ deleted: boolean; localDeleted?: boolean }>;
}

export async function syncAllAccelerations(data?: {
  dnsCredentialId?: number;
  pluginCredentialId?: number;
}): Promise<ApiResponse<{ items: DomainAccelerationConfig[]; errors: Array<{ zoneName: string; dnsCredentialId: number; error: string }>; synced: number; failed: number }>> {
  const response = await api.post('/accelerations/sync-all', data || {});
  return response as unknown as ApiResponse<{ items: DomainAccelerationConfig[]; errors: Array<{ zoneName: string; dnsCredentialId: number; error: string }>; synced: number; failed: number }>;
}

export async function createAccelerationVerifyRecord(data: {
  zoneName: string;
  zoneId?: string;
  dnsCredentialId: number;
  pluginCredentialId?: number;
  remoteSiteId?: string;
  verifyAfter?: boolean;
}): Promise<ApiResponse<{ config?: DomainAccelerationConfig | null; site?: RemoteAccelerationSite | null; dnsRecordsAdded?: Array<{ zoneName: string; type: string; name: string; value: string }>; dnsRecordsSkipped?: Array<{ zoneName: string; type: string; name: string; value: string }>; dnsErrors?: Array<{ error: string; name?: string }> }>> {
  const response = await api.post('/accelerations/create-verify-record', data);
  return response as unknown as ApiResponse<{ config?: DomainAccelerationConfig | null; site?: RemoteAccelerationSite | null; dnsRecordsAdded?: Array<{ zoneName: string; type: string; name: string; value: string }>; dnsRecordsSkipped?: Array<{ zoneName: string; type: string; name: string; value: string }>; dnsErrors?: Array<{ error: string; name?: string }> }>;
}
