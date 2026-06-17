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

  const fetchPage = (page: number) =>
    api.get('/dns-records/zones', {
      params: {
        ...params,
        page,
        pageSize,
      },
    });

  // Fetch the first page to learn the total count.
  const first = await fetchPage(1);
  firstResponse = first;
  const firstBatch = (first as any)?.data?.zones || [];
  const total = Number((first as any)?.data?.total ?? 0);
  zones.push(...firstBatch);

  if (firstBatch.length === pageSize && total > zones.length) {
    // Total known: fan out the remaining pages in parallel instead of
    // walking them one-by-one (each cold page is a live upstream round-trip).
    const lastPage = Math.min(200, Math.ceil(total / pageSize));
    const rest = await Promise.all(
      Array.from({ length: lastPage - 1 }, (_, i) => fetchPage(i + 2)),
    );
    for (const response of rest) {
      zones.push(...((response as any)?.data?.zones || []));
    }
  } else if (firstBatch.length === pageSize && total === 0) {
    // Provider didn't report a total — fall back to sequential walking.
    let page = 2;
    while (page <= 200) {
      const response = await fetchPage(page);
      const batch = (response as any)?.data?.zones || [];
      zones.push(...batch);
      if (batch.length < pageSize) break;
      page += 1;
    }
  }

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
