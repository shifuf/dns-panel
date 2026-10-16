import api from './api';
import type { ApiResponse } from '@/types';

export interface DnsRecordHistoryItem {
  id: number;
  credentialId?: number | null;
  zoneId?: string | null;
  zoneName?: string | null;
  recordId?: string | null;
  recordName?: string | null;
  recordType?: string | null;
  action: string;
  oldValue?: string | null;
  newValue?: string | null;
  createdAt: string;
}

export interface DnsRecordTemplate {
  id: number;
  name: string;
  description?: string | null;
  records: Array<Record<string, unknown>>;
  createdAt: string;
  updatedAt?: string;
}

export interface DnsSearchHit {
  credentialId: number;
  credentialName?: string;
  provider?: string;
  zoneId: string;
  zoneName: string;
  recordId: string;
  recordName: string;
  recordType: string;
  value: string;
}

export interface DnsPropagateResult {
  name: string;
  type: string;
  expected?: string | null;
  answers: Array<{ resolver: string; values: string[]; error?: string }>;
  consistent: boolean;
}

export async function listDnsRecordHistory(params?: {
  zoneId?: string;
  recordId?: string;
  page?: number;
  limit?: number;
}): Promise<ApiResponse<{ items: DnsRecordHistoryItem[]; total: number }>> {
  return api.get('/dns-records/history', { params }) as Promise<ApiResponse<{ items: DnsRecordHistoryItem[]; total: number }>>;
}

export async function rollbackDnsRecord(
  historyId: number,
  options?: { credentialId?: number | null }
): Promise<ApiResponse<{ record?: unknown }>> {
  const params =
    options?.credentialId != null && Number(options.credentialId) > 0
      ? { credentialId: Number(options.credentialId) }
      : undefined;
  return api.post(`/dns-records/history/${historyId}/rollback`, {}, { params }) as Promise<
    ApiResponse<{ record?: unknown }>
  >;
}

export async function listDnsTemplates(): Promise<ApiResponse<{ templates: DnsRecordTemplate[] }>> {
  return api.get('/dns-records/templates') as Promise<ApiResponse<{ templates: DnsRecordTemplate[] }>>;
}

export async function createDnsTemplate(data: {
  name: string;
  description?: string;
  records: Array<Record<string, unknown>>;
}): Promise<ApiResponse<{ template: DnsRecordTemplate }>> {
  return api.post('/dns-records/templates', data) as Promise<ApiResponse<{ template: DnsRecordTemplate }>>;
}

export async function deleteDnsTemplate(id: number): Promise<ApiResponse> {
  return api.delete(`/dns-records/templates/${id}`) as Promise<ApiResponse>;
}

export async function applyDnsTemplate(data: {
  templateId: number;
  zoneId: string;
  credentialId?: number;
}): Promise<ApiResponse<{ created: number; failed: number; results: Array<Record<string, unknown>> }>> {
  return api.post('/dns-records/templates/apply', data) as Promise<
    ApiResponse<{ created: number; failed: number; results: Array<Record<string, unknown>> }>
  >;
}

export async function exportDnsRecords(params: {
  zoneId: string;
  credentialId?: number;
  format?: 'json' | 'csv' | 'bind';
}): Promise<ApiResponse<{ content: string; filename: string; format: string }>> {
  return api.get(`/dns-records/zones/${encodeURIComponent(params.zoneId)}/export`, {
    params: { credentialId: params.credentialId, format: params.format || 'json' },
  }) as Promise<ApiResponse<{ content: string; filename: string; format: string }>>;
}

export async function importDnsRecords(data: {
  zoneId: string;
  credentialId?: number;
  format?: 'json' | 'csv' | 'bind';
  content: string;
  dryRun?: boolean;
}): Promise<ApiResponse<{ created: number; skipped: number; failed: number; results: Array<Record<string, unknown>> }>> {
  return api.post(`/dns-records/zones/${encodeURIComponent(data.zoneId)}/import`, {
    format: data.format || 'json',
    content: data.content,
    dryRun: Boolean(data.dryRun),
    credentialId: data.credentialId,
  }) as Promise<ApiResponse<{ created: number; skipped: number; failed: number; results: Array<Record<string, unknown>> }>>;
}

export async function searchDnsRecords(params: {
  q: string;
  limit?: number;
}): Promise<ApiResponse<{ hits: DnsSearchHit[] }>> {
  return api.get('/dns-records/search', { params }) as Promise<ApiResponse<{ hits: DnsSearchHit[] }>>;
}

export async function checkDnsPropagation(data: {
  name: string;
  type?: string;
  expected?: string;
}): Promise<ApiResponse<DnsPropagateResult>> {
  return api.post('/dns-records/propagate-check', data) as Promise<ApiResponse<DnsPropagateResult>>;
}

export async function detectDnsConflicts(params: {
  zoneId: string;
  credentialId?: number;
}): Promise<ApiResponse<{ conflicts: Array<{ name: string; types: string[]; message: string }> }>> {
  return api.get(`/dns-records/zones/${encodeURIComponent(params.zoneId)}/conflicts`, {
    params: { credentialId: params.credentialId },
  }) as Promise<ApiResponse<{ conflicts: Array<{ name: string; types: string[]; message: string }> }>>;
}
