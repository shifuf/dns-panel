import api from './api';
import type { ApiResponse } from '@/types';
import type { SslCertificate, SslCertificateDetail, ApplyCertificateParams, IssueAcmeParams, UploadCertificateParams } from '@/types/ssl';

interface PaginatedResponse<T> {
  success: boolean;
  message: string;
  data: T[];
  pagination: { total: number; page: number; limit: number; pages: number };
  errors?: Array<{ credentialId: number; name: string; error: string }>;
  statusSummary?: Record<string, number>;
  sourceSummary?: Record<string, number>;
  credentialSummary?: Array<{ credentialId: number; credentialName: string; source: string; count: number }>;
}

export interface SslCredential {
  id: number;
  name: string;
  provider: string;
  createdAt: string;
}

export async function getSslCredentials(): Promise<ApiResponse<SslCredential[]>> {
  const res = await api.get('/ssl/credentials');
  return res as unknown as ApiResponse<SslCredential[]>;
}

export interface SslAutoRenew {
  enabled: boolean;
  days: number;
  lastRunAt?: string;
  lastResult?: string;
}

export async function getSslAutoRenew(): Promise<ApiResponse<SslAutoRenew>> {
  const res = await api.get('/ssl/auto-renew');
  return res as unknown as ApiResponse<SslAutoRenew>;
}

export async function setSslAutoRenew(enabled: boolean, days?: number): Promise<ApiResponse<SslAutoRenew>> {
  const res = await api.post('/ssl/auto-renew', { enabled, days });
  return res as unknown as ApiResponse<SslAutoRenew>;
}

export async function createSslCredential(data: {
  name: string;
  secretId: string;
  secretKey: string;
}): Promise<ApiResponse<{ id: number }>> {
  const res = await api.post('/ssl/credentials', data);
  return res as unknown as ApiResponse<{ id: number }>;
}

export async function updateSslCredential(id: number, data: {
  name?: string;
  secretId?: string;
  secretKey?: string;
}): Promise<ApiResponse> {
  const res = await api.put(`/ssl/credentials/${id}`, data);
  return res as unknown as ApiResponse;
}

export async function deleteSslCredential(id: number): Promise<ApiResponse> {
  const res = await api.delete(`/ssl/credentials/${id}`);
  return res as unknown as ApiResponse;
}

export async function getSslCertificates(
  credentialId: number | 'all',
  params?: { page?: number; limit?: number; search?: string; filterCredentialId?: number; status?: string; source?: string },
): Promise<PaginatedResponse<SslCertificate>> {
  const query = new URLSearchParams({ credentialId: String(credentialId) });
  if (params?.page) query.set('page', String(params.page));
  if (params?.limit) query.set('limit', String(params.limit));
  if (params?.search) query.set('search', params.search);
  if (params?.filterCredentialId) query.set('filterCredentialId', String(params.filterCredentialId));
  if (params?.status) query.set('status', params.status);
  if (params?.source) query.set('source', params.source);
  const res = await api.get(`/ssl/certificates?${query.toString()}`);
  return res as unknown as PaginatedResponse<SslCertificate>;
}

export async function getSslCertificateDetail(
  credentialId: number,
  certId: string,
): Promise<ApiResponse<SslCertificateDetail>> {
  const res = await api.get(`/ssl/certificates/${encodeURIComponent(certId)}?credentialId=${credentialId}`);
  return res as unknown as ApiResponse<SslCertificateDetail>;
}

export async function applySslCertificate(
  params: ApplyCertificateParams,
): Promise<ApiResponse<{ CertificateId: string; dnsRecordsAdded?: any[]; dnsErrors?: any[] }>> {
  const res = await api.post('/ssl/certificates/apply', params);
  return res as unknown as ApiResponse<{ CertificateId: string; dnsRecordsAdded?: any[]; dnsErrors?: any[] }>;
}

export async function issueAcmeCertificate(
  params: IssueAcmeParams,
): Promise<ApiResponse<{ id: number; domain: string; status: string; provider: string }>> {
  const res = await api.post('/ssl/certificates/issue-acme', params);
  return res as unknown as ApiResponse<{ id: number; domain: string; status: string; provider: string }>;
}

export interface SslAcmeJob {
  id: number;
  certificateId: number;
  dnsCredentialId: number;
  domain: string;
  domains: string;
  operation: 'issue' | 'renew';
  status: 'queued' | 'running' | 'success' | 'failed' | 'cancelled';
  attempts: number;
  error?: string;
  createdAt: string;
  updatedAt: string;
  startedAt?: string;
  completedAt?: string;
}

export interface SslDeploymentEvent {
  id: number;
  provider: string;
  remoteCertId: string;
  credentialId?: number;
  domain: string;
  source: 'tencent' | 'letsencrypt';
  status: 'queued' | 'running' | 'success' | 'failed' | 'skipped';
  attempts: number;
  nextAttemptAt?: string;
  targetName?: string;
  fingerprint?: string;
  error?: string;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
  updatedAt: string;
}

export interface SslNotificationSettings {
  enabled: boolean;
  emailEnabled: boolean;
  emailTo: string;
  webhookEnabled: boolean;
  webhookUrl: string;
  wecomEnabled: boolean;
  wecomWebhookUrl: string;
  retentionDays: number;
}

export interface SslTaskLog {
  id: number;
  taskType: 'acme' | 'deployment' | 'renewal';
  taskId?: number;
  domain?: string;
  source?: string;
  status: string;
  attempt: number;
  targetName?: string;
  message?: string;
  createdAt: string;
}

export interface SslTaskStats {
  byStatus: Record<string, number>;
  bySource: Record<string, number>;
  failureReasons: Array<{ reason: string; count: number }>;
}

export async function getSslAcmeJobs(): Promise<ApiResponse<SslAcmeJob[]>> {
  const res = await api.get('/ssl/acme-jobs');
  return res as unknown as ApiResponse<SslAcmeJob[]>;
}

export async function retrySslAcmeJob(id: number): Promise<ApiResponse> {
  const res = await api.post(`/ssl/acme-jobs/${id}/retry`, {});
  return res as unknown as ApiResponse;
}

export async function cancelSslAcmeJob(id: number): Promise<ApiResponse> {
  const res = await api.post(`/ssl/acme-jobs/${id}/cancel`, {});
  return res as unknown as ApiResponse;
}

export async function getSslDeploymentEvents(params?: {
  status?: string; source?: string; domain?: string; page?: number; limit?: number;
}): Promise<ApiResponse<SslDeploymentEvent[]> & { pagination?: { total: number; page: number; limit: number; pages: number } }> {
  const res = await api.get('/ssl/deployment-events', { params });
  return res as unknown as ApiResponse<SslDeploymentEvent[]>;
}

export async function getSslNotificationSettings(): Promise<ApiResponse<SslNotificationSettings>> {
  const res = await api.get('/ssl/notification-settings');
  return res as unknown as ApiResponse<SslNotificationSettings>;
}

export async function saveSslNotificationSettings(settings: SslNotificationSettings): Promise<ApiResponse<SslNotificationSettings>> {
  const res = await api.post('/ssl/notification-settings', settings);
  return res as unknown as ApiResponse<SslNotificationSettings>;
}

export async function testSslNotification(): Promise<ApiResponse<{ deliveries: Array<{ channel: string; success: boolean; error?: string }> }>> {
  const res = await api.post('/ssl/notification-settings/test', {});
  return res as unknown as ApiResponse<{ deliveries: Array<{ channel: string; success: boolean; error?: string }> }>;
}

export async function getSslTaskLogs(params?: { page?: number; limit?: number }): Promise<ApiResponse<SslTaskLog[]>> {
  const res = await api.get('/ssl/task-logs', { params });
  return res as unknown as ApiResponse<SslTaskLog[]>;
}

export async function getSslTaskStats(): Promise<ApiResponse<SslTaskStats>> {
  const res = await api.get('/ssl/task-stats');
  return res as unknown as ApiResponse<SslTaskStats>;
}

export async function downloadSslTaskLogs(params?: { status?: string; source?: string; domain?: string }): Promise<void> {
  const res = await api.get('/ssl/task-logs/download', { params, responseType: 'blob' });
  const blob = new Blob([res as unknown as BlobPart], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'ssl-task-logs.csv';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

export async function retrySslDeploymentEvent(id: number): Promise<ApiResponse> {
  const res = await api.post(`/ssl/deployment-events/${id}/retry`, {});
  return res as unknown as ApiResponse;
}

export async function setCertificateAutoRenew(
  credentialId: number,
  certId: string,
  enabled: boolean,
): Promise<ApiResponse<{ enabled: boolean }>> {
  const res = await api.post(`/ssl/certificates/${encodeURIComponent(certId)}/auto-renew`, { credentialId, enabled });
  return res as unknown as ApiResponse<{ enabled: boolean }>;
}

export async function completeSslCertificate(
  credentialId: number,
  certId: string,
): Promise<ApiResponse> {
  const res = await api.post(`/ssl/certificates/${encodeURIComponent(certId)}/complete`, { credentialId });
  return res as unknown as ApiResponse;
}

export async function autoDnsSslCertificate(
  credentialId: number,
  certId: string,
): Promise<ApiResponse<{ dnsRecordsAdded: any[]; dnsErrors: any[]; completed: boolean }>> {
  const res = await api.post(`/ssl/certificates/${encodeURIComponent(certId)}/auto-dns`, { credentialId });
  return res as unknown as ApiResponse<{ dnsRecordsAdded: any[]; dnsErrors: any[]; completed: boolean }>;
}

export async function downloadSslCertificate(
  credentialId: number,
  certId: string,
): Promise<void> {
  const query = `credentialId=${credentialId}`;
  const res = await api.get(`/ssl/certificates/${encodeURIComponent(certId)}/download?${query}`, {
    responseType: 'blob',
  });
  const blob = new Blob([res as unknown as BlobPart], { type: 'application/zip' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${certId}.zip`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export async function uploadSslCertificate(
  params: UploadCertificateParams,
): Promise<ApiResponse<{ CertificateId: string }>> {
  const res = await api.post('/ssl/certificates/upload', params);
  return res as unknown as ApiResponse<{ CertificateId: string }>;
}

export async function deleteSslCertificate(
  credentialId: number,
  certId: string,
): Promise<ApiResponse> {
  const res = await api.delete(`/ssl/certificates/${encodeURIComponent(certId)}?credentialId=${credentialId}`);
  return res as unknown as ApiResponse;
}

export async function reconcileSslCertificates(
  credentialId?: number | 'all',
): Promise<ApiResponse<{ results: any[]; failed: number }>> {
  const res = await api.post('/ssl/certificates/reconcile', credentialId ? { credentialId } : {});
  return res as unknown as ApiResponse<{ results: any[]; failed: number }>;
}

export async function batchDeploySslCertificates(
  certIds: string[],
): Promise<ApiResponse<{ queued: any[]; skipped: any[]; errors: any[] }>> {
  const res = await api.post('/ssl/certificates/batch-deploy', { certIds });
  return res as unknown as ApiResponse<{ queued: any[]; skipped: any[]; errors: any[] }>;
}

export async function batchSetSslAutoRenew(
  certIds: string[],
  enabled: boolean,
): Promise<ApiResponse<{ updated: any[]; skipped: any[]; errors: any[] }>> {
  const res = await api.post('/ssl/certificates/batch-auto-renew', { certIds, enabled });
  return res as unknown as ApiResponse<{ updated: any[]; skipped: any[]; errors: any[] }>;
}

export async function checkSslExpiry(): Promise<ApiResponse<{ checked: number; notified: number; expired: number }>> {
  const res = await api.post('/ssl/certificates/check-expiry', {});
  return res as unknown as ApiResponse<{ checked: number; notified: number; expired: number }>;
}

export interface SslCaOption {
  value: string;
  label: string;
  requiresEab?: boolean;
}

export async function getSslAcmeCas(): Promise<ApiResponse<{ cas: SslCaOption[]; default: string }>> {
  const res = await api.get('/ssl/acme-cas');
  return res as unknown as ApiResponse<{ cas: SslCaOption[]; default: string }>;
}

export interface SiteDeploymentOverview {
  site: string;
  latestStatus: string;
  latestSource: string;
  latestDomain: string;
  latestError: string;
  latestFingerprint: string;
  latestAt: string;
  history: Array<{
    eventId: number;
    status: string;
    domain: string;
    source: string;
    attempts: number;
    error: string;
    at: string;
  }>;
}

export async function getSslDeploymentsBySite(): Promise<ApiResponse<SiteDeploymentOverview[]>> {
  const res = await api.get('/ssl/deployments/by-site');
  return res as unknown as ApiResponse<SiteDeploymentOverview[]>;
}

export async function getSslPluginVersion(): Promise<ApiResponse<{ expectedVersion: string; minVersion: string; releaseNotes?: string }>> {
  const res = await api.get('/ssl/plugin-version');
  return res as unknown as ApiResponse<{ expectedVersion: string; minVersion: string; releaseNotes?: string }>;
}

export interface SslCertificateView {
  certId: string;
  publicKey: string;
  meta: {
    notBefore?: string;
    notAfter?: string;
    san?: string[];
    issuer?: string;
    subjectCN?: string;
    serialNumber?: string;
    fingerprintSha256?: string;
    signatureAlgorithm?: string;
  };
}

export async function viewSslCertificate(
  credentialId: number,
  certId: string,
): Promise<ApiResponse<SslCertificateView>> {
  const res = await api.get(
    `/ssl/certificates/${encodeURIComponent(certId)}/view?credentialId=${credentialId}`,
  );
  return res as unknown as ApiResponse<SslCertificateView>;
}

export async function deploySslCertificate(
  certId: string,
): Promise<ApiResponse<{ id: number; status: string }>> {
  const res = await api.post('/ssl/certificates/deploy', { certId });
  return res as unknown as ApiResponse<{ id: number; status: string }>;
}

export interface CleanExpiredResult {
  cleaned: Array<{ domain: string; certId: string; status: string; dryRun?: boolean }>;
  kept: Array<{ domain: string; certId: string; status: string; reason: string }>;
  errors: Array<{ domain?: string; certId?: string; credential?: string; error: string }>;
  dryRun: boolean;
}

export async function cleanExpiredSslCertificates(params?: {
  staleDays?: number;
  domain?: string;
  dryRun?: boolean;
}): Promise<ApiResponse<CleanExpiredResult>> {
  const res = await api.post('/ssl/certificates/clean-expired', params || {});
  return res as unknown as ApiResponse<CleanExpiredResult>;
}

export async function syncSslCertificates(
  credentialId: number,
): Promise<ApiResponse<{ synced: number }>> {
  const res = await api.post('/ssl/certificates/sync', { credentialId });
  return res as unknown as ApiResponse<{ synced: number }>;
}

export interface RenewResult {
  renewed: Array<{ domain: string; credential: string; newCertId: string; dnsRecordAdded: boolean }>;
  failed: Array<{ domain: string; credential: string; error: string }>;
  skipped: Array<{ domain: string; credential: string; reason: string }>;
}

export async function renewExpiredCertificates(
  params?: { renewDays?: number; dnsCredentialId?: number },
): Promise<ApiResponse<RenewResult>> {
  const res = await api.post('/ssl/certificates/renew-expired', params || {});
  return res as unknown as ApiResponse<RenewResult>;
}

export async function cleanupDnsSslCertificate(
  credentialId: number,
  certId: string,
): Promise<ApiResponse<{ deleted: any[]; errors: any[] }>> {
  const res = await api.post(`/ssl/certificates/${encodeURIComponent(certId)}/cleanup-dns`, { credentialId });
  return res as unknown as ApiResponse<{ deleted: any[]; errors: any[] }>;
}
