import api from './api';
import { ApiResponse, Domain } from '@/types';

function toCredentialParam(credentialId?: number | 'all' | null): number | undefined {
  if (typeof credentialId !== 'number') return undefined;
  if (!Number.isFinite(credentialId)) return undefined;
  return credentialId;
}

/**
 * 获取所有域名列表
 * @param credentialId 可选，指定凭证ID；'all' 由调用方在前端聚合处理
 */
export const getDomains = async (credentialId?: number | 'all' | null): Promise<ApiResponse<{ domains: Domain[] }>> => {
  const params: any = {};
  const credentialParam = toCredentialParam(credentialId);
  if (credentialParam !== undefined) {
    params.credentialId = credentialParam;
  }

  const pageSize = 100;
  const zones: any[] = [];
  let firstResponse: any | undefined;
  const seen = new Set<string>();
  let complete = false;
  let total: number | null = null;

  const fetchPage = (page: number) =>
    api.get('/dns-records/zones', {
      params: {
        ...params,
        page,
        pageSize,
      },
    });

  // Follow the provider's total even when it returns fewer rows than requested.
  // Without a total, only an empty page proves that the listing is complete.
  for (let page = 1; page <= 200; page += 1) {
    const response: any = await fetchPage(page);
    firstResponse ??= response;
    const batch = response?.data?.zones;
    if (response?.success === false || !Array.isArray(batch)) {
      throw new Error(response?.message || '域名列表响应格式错误');
    }
    const rawTotal = response.data.total;
    if (rawTotal != null && Number.isFinite(Number(rawTotal)) && Number(rawTotal) > 0) {
      total = Number(rawTotal);
    }
    const previousCount = zones.length;
    for (const zone of batch) {
      const key = String(zone.id ?? zone.name);
      if (seen.has(key)) continue;
      seen.add(key);
      zones.push(zone);
    }
    if ((total !== null && zones.length >= total) || (batch.length === 0 && total === null)) {
      complete = true;
      break;
    }
    if (zones.length === previousCount) {
      throw new Error(`域名列表不完整（已加载 ${zones.length}${total === null ? '' : ` / ${total}`}），请刷新重试`);
    }
  }
  if (!complete) throw new Error('域名列表不完整，已达到分页上限，请缩小账户范围后重试');

  const credId = toCredentialParam(credentialId);
  const domains: Domain[] = zones.map((z: any) => ({
    id: z.id,
    name: z.name,
    status: z.status,
    recordCount: z.recordCount,
    updatedAt: z.updatedAt,
    credentialId: credId,
  }));

  return {
    ...(firstResponse as any),
    data: {
      ...(firstResponse as any)?.data,
      domains,
    },
  } as ApiResponse<{ domains: Domain[] }>;
};

/**
 * 获取域名详情
 */
export const getDomainById = async (zoneId: string, credentialId?: number): Promise<ApiResponse<{ domain: any }>> => {
  const params: any = {};
  if (typeof credentialId === 'number' && Number.isFinite(credentialId)) {
    params.credentialId = credentialId;
  }

  const response = await api.get(`/dns-records/zones/${zoneId}`, { params });
  const zone = (response as any)?.data?.zone;
  const domain = zone
    ? {
        id: zone.id,
        name: zone.name,
        status: zone.status,
        recordCount: zone.recordCount,
        updatedAt: zone.updatedAt,
      }
    : null;

  return {
    ...(response as any),
    data: {
      ...(response as any)?.data,
      domain,
    },
  } as ApiResponse<{ domain: any }>;
};

/**
 * 刷新域名缓存
 */
export const refreshDomains = async (credentialId?: number | 'all' | null): Promise<ApiResponse> => {
  const params: any = {};
  const credentialParam = toCredentialParam(credentialId);
  if (credentialParam !== undefined) {
    params.credentialId = credentialParam;
  }
  const response = await api.post('/dns-records/refresh', {}, { params });
  return response as unknown as ApiResponse;
};

export interface AddZoneResult {
  domain: string;
  success: boolean;
  existed?: boolean;
  zone?: { id: string; name: string; status: string };
  nameServers?: string[];
  error?: string;
  details?: any;
}

/**
 * 批量添加域名（创建 Zone）
 */
export const addZones = async (
  credentialId: number,
  domains: string[]
): Promise<ApiResponse<{ results: AddZoneResult[] }>> => {
  const response = await api.post('/dns-records/zones', { domains }, { params: { credentialId } });
  return response as unknown as ApiResponse<{ results: AddZoneResult[] }>;
};

/**
 * 删除域名（删除 Zone）
 */
export const deleteZone = async (credentialId: number, zoneId: string): Promise<ApiResponse<{ deleted: boolean }>> => {
  const response = await api.delete(`/dns-records/zones/${zoneId}`, { params: { credentialId } });
  return response as unknown as ApiResponse<{ deleted: boolean }>;
};
