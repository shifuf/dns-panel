import api from './api';
import { ApiResponse, DNSRecord } from '@/types';
import { DnsLine } from '@/types/dns';

export interface RecordsResponseCapabilities {
  supportsWeight?: boolean;
  supportsLine?: boolean;
  supportsStatus?: boolean;
  supportsRemark?: boolean;
}

export interface DNSRecordsResponseData {
  records: DNSRecord[];
  total: number;
  page: number;
  pageSize: number;
  capabilities?: RecordsResponseCapabilities;
}

const mapDNSRecord = (r: any): DNSRecord => ({
  id: r.id,
  type: r.type,
  zoneName: r.zoneName,
  name: r.name,
  content: r.value,
  ttl: r.ttl,
  proxied: !!r.proxied,
  priority: r.priority,
  weight: r.weight,
  line: r.line,
  lineName: r.lineName,
  remark: r.remark,
  updatedAt: r.updatedAt,
  enabled:
    typeof r.enabled === 'boolean'
      ? r.enabled
      : r.status === '1'
        ? true
        : r.status === '0'
          ? false
          : undefined,
  acceleration: r.acceleration || null,
});

/**
 * 获取 DNS 记录列表
 */
export const getDNSRecords = async (
  zoneId: string,
  options: {
    page?: number;
    pageSize?: number;
    credentialId?: number;
  } = {}
): Promise<ApiResponse<DNSRecordsResponseData>> => {
  const page = Math.max(1, Number(options.page || 1));
  const pageSize = Math.max(1, Number(options.pageSize || 20));
  const params: Record<string, number> = {
    page,
    pageSize,
  };
  if (options.credentialId !== undefined) {
    params.credentialId = options.credentialId;
  }

  const response = await api.get(`/dns-records/zones/${zoneId}/records`, { params });
  const payload = (response as any)?.data || {};
  const rawRecords = Array.isArray(payload.records) ? payload.records : [];

  return {
    ...(response as any),
    data: {
      ...payload,
      records: rawRecords.map((r: any) => mapDNSRecord(r)),
      total: Number(payload.total || 0),
      page: Number(payload.page || page),
      pageSize: Number(payload.pageSize || pageSize),
      capabilities: payload.capabilities,
    },
  } as ApiResponse<DNSRecordsResponseData>;
};

/**
 * 获取解析线路列表
 */
export const getDNSLines = async (
  zoneId: string,
  credentialId?: number
): Promise<ApiResponse<{ lines: DnsLine[] }>> => {
  const params = credentialId !== undefined ? { credentialId } : {};
  const response = await api.get(`/dns-records/zones/${zoneId}/lines`, { params });
  return response as unknown as ApiResponse<{ lines: DnsLine[] }>;
};

export const getDNSMinTTL = async (
  zoneId: string,
  credentialId?: number
): Promise<ApiResponse<{ minTTL: number }>> => {
  const params = credentialId !== undefined ? { credentialId } : {};
  const response = await api.get(`/dns-records/zones/${zoneId}/min-ttl`, { params });
  return response as unknown as ApiResponse<{ minTTL: number }>;
};

/**
 * 创建 DNS 记录
 */
export const createDNSRecord = async (
  zoneId: string,
  params: {
    type: string;
    name: string;
    content: string;
    ttl?: number;
    proxied?: boolean;
    priority?: number;
    weight?: number;
    line?: string;
    remark?: string;
  },
  credentialId?: number
): Promise<ApiResponse<{ record: DNSRecord }>> => {
  const queryParams = credentialId !== undefined ? { credentialId } : {};

  const response = await api.post(
    `/dns-records/zones/${zoneId}/records`,
    {
      name: params.name,
      type: params.type,
      value: params.content,
      ttl: params.ttl,
      proxied: params.proxied,
      priority: params.priority,
      weight: params.weight,
      line: params.line,
      remark: params.remark,
    },
    { params: queryParams }
  );

  const r = (response as any)?.data?.record;
  const record: DNSRecord | null = r ? mapDNSRecord(r) : null;

  return {
    ...(response as any),
    data: {
      ...(response as any)?.data,
      record,
    },
  } as ApiResponse<{ record: DNSRecord }>;
};

/**
 * 更新 DNS 记录
 */
export const updateDNSRecord = async (
  zoneId: string,
  recordId: string,
  params: {
    type?: string;
    name?: string;
    content?: string;
    ttl?: number;
    proxied?: boolean;
    priority?: number;
    weight?: number;
    line?: string;
    remark?: string;
  },
  credentialId?: number
): Promise<ApiResponse<{ record: DNSRecord }>> => {
  const queryParams = credentialId !== undefined ? { credentialId } : {};

  const response = await api.put(
    `/dns-records/zones/${zoneId}/records/${recordId}`,
    {
      name: params.name,
      type: params.type,
      value: params.content,
      ttl: params.ttl,
      proxied: params.proxied,
      priority: params.priority,
      weight: params.weight,
      line: params.line,
      remark: params.remark,
    },
    { params: queryParams }
  );

  const r = (response as any)?.data?.record;
  const record: DNSRecord | null = r ? mapDNSRecord(r) : null;

  return {
    ...(response as any),
    data: {
      ...(response as any)?.data,
      record,
    },
  } as ApiResponse<{ record: DNSRecord }>;
};

/**
 * 设置 DNS 记录状态
 */
export const setDNSRecordStatus = async (
  zoneId: string,
  recordId: string,
  enabled: boolean,
  credentialId?: number
): Promise<ApiResponse<{ record: DNSRecord | null }>> => {
  const params = credentialId !== undefined ? { credentialId } : {};
  const response = await api.put(`/dns-records/zones/${zoneId}/records/${recordId}/status`, { enabled }, { params });
  const r = (response as any)?.data?.record;
  return {
    ...(response as any),
    data: {
      ...(response as any)?.data,
      record: r ? mapDNSRecord(r) : null,
    },
  } as ApiResponse<{ record: DNSRecord | null }>;
};

export interface AccelerationRestoreRecord {
  type: string;
  value: string;
  ttl?: number;
  line?: string;
  priority?: number;
  weight?: number;
  remark?: string;
  proxied?: boolean;
}

export const setDNSRecordAcceleration = async (
  zoneId: string,
  recordId: string,
  enabled: boolean,
  credentialId?: number,
  options?: { restoreRecord?: AccelerationRestoreRecord; accelerationCredentialId?: number }
): Promise<ApiResponse<{ record: DNSRecord | null; acceleration?: DNSRecord['acceleration']; applied?: boolean; restored?: boolean; needsRestoreInput?: boolean; currentRecord?: DNSRecord | null; suggestedType?: string }>> => {
  const params = credentialId !== undefined ? { credentialId } : {};
  const payload: Record<string, any> = { enabled };
  if (options?.restoreRecord) payload.restoreRecord = options.restoreRecord;
  if (options?.accelerationCredentialId !== undefined) payload.accelerationCredentialId = options.accelerationCredentialId;
  const response = await api.put(`/dns-records/zones/${zoneId}/records/${recordId}/acceleration`, payload, { params });
  const data = (response as any)?.data || {};
  const r = data.record;
  return {
    ...(response as any),
    data: {
      ...data,
      record: r ? mapDNSRecord(r) : null,
      acceleration: r?.acceleration || data.acceleration || null,
      currentRecord: data.currentRecord ? mapDNSRecord(data.currentRecord) : null,
    },
  } as ApiResponse<{ record: DNSRecord | null; acceleration?: DNSRecord['acceleration']; applied?: boolean; restored?: boolean; needsRestoreInput?: boolean; currentRecord?: DNSRecord | null; suggestedType?: string }>;
};

/**
 * 刷新 DNS 记录缓存（清除服务端缓存）
 */
export const refreshDNSRecords = async (
  zoneId: string,
  credentialId?: number
): Promise<ApiResponse> => {
  const params: any = {};
  if (credentialId !== undefined) params.credentialId = credentialId;
  const response = await api.post('/dns-records/refresh', { zoneId }, { params });
  return response as unknown as ApiResponse;
};

/**
 * 删除 DNS 记录
 */
export const deleteDNSRecord = async (
  zoneId: string,
  recordId: string,
  credentialId?: number
): Promise<ApiResponse> => {
  const params = credentialId !== undefined ? { credentialId } : {};
  return api.delete(`/dns-records/zones/${zoneId}/records/${recordId}`, { params });
};

/**
 * 批量删除 DNS 记录
 */
export const batchDeleteDNSRecords = async (
  zoneId: string,
  recordIds: string[],
  credentialId?: number
): Promise<ApiResponse<{ successCount: number; failedCount: number; results: Array<{ recordId: string; success: boolean; error?: string }> }>> => {
  const params = credentialId !== undefined ? { credentialId } : {};
  const response = await api.post(`/dns-records/zones/${zoneId}/records/batch-delete`, { recordIds }, { params });
  return response as unknown as ApiResponse<{ successCount: number; failedCount: number; results: Array<{ recordId: string; success: boolean; error?: string }> }>;
};

/**
 * 批量设置 DNS 记录状态
 */
export const batchSetDNSRecordStatus = async (
  zoneId: string,
  recordIds: string[],
  enabled: boolean,
  credentialId?: number
): Promise<ApiResponse<{ successCount: number; failedCount: number; enabled: boolean; results: Array<{ recordId: string; success: boolean; enabled: boolean; error?: string }> }>> => {
  const params = credentialId !== undefined ? { credentialId } : {};
  const response = await api.put(`/dns-records/zones/${zoneId}/records/batch-status`, { recordIds, enabled }, { params });
  return response as unknown as ApiResponse<{ successCount: number; failedCount: number; enabled: boolean; results: Array<{ recordId: string; success: boolean; enabled: boolean; error?: string }> }>;
};
