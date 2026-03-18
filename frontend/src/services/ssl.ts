import api from './api';
import type { ApiResponse } from '@/types';
import type { SslCertificate, SslCertificateDetail, ApplyCertificateParams, UploadCertificateParams } from '@/types/ssl';

interface PaginatedResponse<T> {
  success: boolean;
  message: string;
  data: T[];
  pagination: { total: number; page: number; limit: number; pages: number };
  errors?: Array<{ credentialId: number; name: string; error: string }>;
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
  params?: { page?: number; limit?: number; search?: string; filterCredentialId?: number },
): Promise<PaginatedResponse<SslCertificate>> {
  const query = new URLSearchParams({ credentialId: String(credentialId) });
  if (params?.page) query.set('page', String(params.page));
  if (params?.limit) query.set('limit', String(params.limit));
  if (params?.search) query.set('search', params.search);
  if (params?.filterCredentialId) query.set('filterCredentialId', String(params.filterCredentialId));
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
