import api from './api';
import type { ApiResponse } from '@/types';

export interface DashboardSummaryData {
  syncSuccessRate24h: number;
  syncFailedCount24h: number;
  syncAvgDurationMs24h: number;
  riskyChangeCount24h: number;
  providerAvailability: Array<{
    provider: string;
    successRate: number;
    timeoutRate: number;
  }>;
  expiring7d: number;
  expiring30d: number;
  recordTypeDistribution: Record<string, number>;
  pendingAlertCount: number;
}

export interface SyncJob {
  id: string;
  status: 'pending' | 'running' | 'success' | 'failed';
  scope: 'all' | 'provider' | 'credential';
  provider?: string | null;
  credentialId?: number | null;
  durationMs?: number | null;
  error?: string | null;
  createdAt: string;
  updatedAt?: string;
}

export interface AlertRule {
  id: string;
  name: string;
  enabled: boolean;
  type: 'status_issue' | 'expiry_warning' | 'sync_failure';
  threshold?: number;
  channels: Array<'webhook' | 'email' | 'inapp'>;
  createdAt: string;
  updatedAt?: string;
}

export interface AlertEvent {
  id: string;
  level: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'acknowledged' | 'resolved';
  title: string;
  message?: string;
  domain?: string;
  createdAt: string;
}

export interface DashboardViewPreset {
  id: string;
  name: string;
  payload: Record<string, unknown>;
  createdAt: string;
}

export interface DomainTagEntry {
  domain: string;
  tags: string[];
}

export interface DomainAuditItem {
  id: string;
  action: string;
  resourceType: string;
  status: string;
  domain?: string;
  recordName?: string;
  operator?: string;
  timestamp: string;
}

export async function getDashboardSummary(params?: {
  provider?: string;
  credentialId?: number | 'all' | null;
}): Promise<ApiResponse<{ summary: DashboardSummaryData }>> {
  return api.get('/dashboard/summary', { params }) as Promise<ApiResponse<{ summary: DashboardSummaryData }>>;
}

export async function runDomainInspection(data?: {
  provider?: string;
  credentialId?: number | 'all' | null;
  domains?: string[];
}): Promise<ApiResponse<{ inspected: number; issues: number }>> {
  return api.post('/dashboard/inspect', data || {}) as Promise<ApiResponse<{ inspected: number; issues: number }>>;
}

export async function listSyncJobs(params?: {
  page?: number;
  limit?: number;
  status?: string;
}): Promise<ApiResponse<{ jobs: SyncJob[] }>> {
  return api.get('/dashboard/sync-jobs', { params }) as Promise<ApiResponse<{ jobs: SyncJob[] }>>;
}

export async function createSyncJob(data: {
  scope: 'all' | 'provider' | 'credential';
  provider?: string;
  credentialId?: number;
}): Promise<ApiResponse<{ job: SyncJob }>> {
  return api.post('/dashboard/sync-jobs', data) as Promise<ApiResponse<{ job: SyncJob }>>;
}

export async function retrySyncJob(id: string): Promise<ApiResponse<{ job: SyncJob }>> {
  return api.post(`/dashboard/sync-jobs/${encodeURIComponent(id)}/retry`, {}) as Promise<ApiResponse<{ job: SyncJob }>>;
}

export async function listAlertRules(): Promise<ApiResponse<{ rules: AlertRule[] }>> {
  return api.get('/dashboard/alert-rules') as Promise<ApiResponse<{ rules: AlertRule[] }>>;
}

export async function upsertAlertRule(data: Partial<AlertRule> & { name: string; type: AlertRule['type'] }): Promise<ApiResponse<{ rule: AlertRule }>> {
  return api.post('/dashboard/alert-rules', data) as Promise<ApiResponse<{ rule: AlertRule }>>;
}

export async function listAlertEvents(params?: {
  status?: 'open' | 'acknowledged' | 'resolved';
  limit?: number;
}): Promise<ApiResponse<{ events: AlertEvent[] }>> {
  return api.get('/dashboard/alert-events', { params }) as Promise<ApiResponse<{ events: AlertEvent[] }>>;
}

export async function acknowledgeAlertEvent(id: string): Promise<ApiResponse<{ ok: boolean }>> {
  return api.post(`/dashboard/alert-events/${encodeURIComponent(id)}/ack`, {}) as Promise<ApiResponse<{ ok: boolean }>>;
}

export async function listDashboardViews(): Promise<ApiResponse<{ views: DashboardViewPreset[] }>> {
  return api.get('/dashboard/views') as Promise<ApiResponse<{ views: DashboardViewPreset[] }>>;
}

export async function createDashboardView(data: {
  name: string;
  payload: Record<string, unknown>;
}): Promise<ApiResponse<{ view: DashboardViewPreset }>> {
  return api.post('/dashboard/views', data) as Promise<ApiResponse<{ view: DashboardViewPreset }>>;
}

export async function deleteDashboardView(id: string): Promise<ApiResponse<{ ok: boolean }>> {
  return api.delete(`/dashboard/views/${encodeURIComponent(id)}`) as Promise<ApiResponse<{ ok: boolean }>>;
}

export async function listDomainTags(params?: {
  domain?: string;
}): Promise<ApiResponse<{ items: DomainTagEntry[] }>> {
  return api.get('/dashboard/domain-tags', { params }) as Promise<ApiResponse<{ items: DomainTagEntry[] }>>;
}

export async function upsertDomainTags(data: {
  domain: string;
  tags: string[];
}): Promise<ApiResponse<{ item: DomainTagEntry }>> {
  return api.post('/dashboard/domain-tags', data) as Promise<ApiResponse<{ item: DomainTagEntry }>>;
}

export async function listDomainAudit(params?: {
  domain?: string;
  page?: number;
  limit?: number;
}): Promise<ApiResponse<{ items: DomainAuditItem[] }>> {
  return api.get('/dashboard/audit', { params }) as Promise<ApiResponse<{ items: DomainAuditItem[] }>>;
}
