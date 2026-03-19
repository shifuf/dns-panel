import type { ProviderType } from '@/types/dns';

const PROVIDER_ALIAS_MAP: Record<string, ProviderType> = {
  dnspod_token: 'dnspod',
  tencent: 'dnspod',
  tencentcloud: 'dnspod',
  tencent_cloud: 'dnspod',
  qcloud: 'dnspod',
};

export function normalizeProviderType(provider: string | ProviderType): ProviderType {
  const raw = String(provider || '').trim().toLowerCase();
  return (PROVIDER_ALIAS_MAP[raw] || raw) as ProviderType;
}

const PROVIDER_DISPLAY_NAME_MAP: Record<ProviderType, string> = {
  cloudflare: 'Cloudflare',
  aliyun: '阿里云',
  dnspod: '腾讯云',
  dnspod_token: '腾讯云',
  huawei: '华为云',
  baidu: '百度云',
  west: '西部数码',
  huoshan: '火山引擎',
  jdcloud: '京东云',
  dnsla: 'DNSLA',
  namesilo: 'NameSilo',
  powerdns: 'PowerDNS',
  spaceship: 'Spaceship',
  tencent_ssl: '腾讯云 SSL',
  tencent_edgeone: '腾讯云 EdgeOne',
};

export function getProviderDisplayName(provider: ProviderType | string | null | undefined): string {
  if (!provider) return '';
  const normalized = normalizeProviderType(provider);
  return PROVIDER_DISPLAY_NAME_MAP[normalized] || normalized;
}
