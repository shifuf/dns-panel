import api from './api';
import type { ApiResponse } from '@/types';

export interface AccelerationSite {
  siteId: string;
  zoneId?: string;
  zoneName?: string;
  siteName?: string;
  status?: string;
  verifyStatus?: string;
  verified?: boolean;
  paused?: boolean;
  type?: string;
  area?: string;
  planId?: string;
  createdAt?: string;
  updatedAt?: string;
  raw?: Record<string, unknown>;
}

export interface AccelerationVerificationInfo {
  recordType?: string;
  recordName?: string;
  recordValue?: string;
  verificationCode?: string;
  raw?: Record<string, unknown> | Record<string, unknown>[];
}

export interface AccelerationDnsRecord {
  id?: string;
  credentialId?: number | null;
  credentialName?: string;
  provider?: string;
  zone?: string;
  zoneId?: string;
  type?: string;
  name?: string;
  value?: string;
  ttl?: number | string;
  status?: string;
  proxied?: boolean | null;
  existing?: boolean;
}

export interface AccelerationDnsConflict {
  id?: string;
  type?: string;
  name?: string;
  value?: string;
  ttl?: number | string;
  status?: string;
  proxied?: boolean | null;
  reason?: string;
}

export interface AccelerationPublicResolution {
  checked?: boolean;
  resolver?: string;
  answers?: string[];
  currentValue?: string;
  isResolved?: boolean;
  status?: number | string;
  error?: string | null;
}

export interface AccelerationDnsCheck {
  expectedValue?: string;
  zoneMatched?: boolean;
  configured?: boolean;
  currentValue?: string;
  provider?: string | null;
  credentialId?: number | null;
  credentialName?: string;
  zone?: string;
  zoneId?: string;
  records?: AccelerationDnsRecord[];
  conflicts?: AccelerationDnsConflict[];
  errors?: Array<{ key?: string; error: string }>;
  publicResolution?: AccelerationPublicResolution;
}

export interface AccelerationDomain {
  domainName: string;
  domainStatus?: string;
  uiState?: 'active' | 'deploying' | 'cname_pending' | 'paused' | 'error' | string;
  siteId?: string;
  identificationStatus?: string;
  verified?: boolean;
  paused?: boolean;
  cnameTarget?: string;
  cnameStatus?: string;
  originType?: string;
  originValue?: string;
  backupOriginValue?: string;
  hostHeader?: string;
  originProtocol?: string;
  httpOriginPort?: number;
  httpsOriginPort?: number;
  ipv6Status?: string;
  verifyRecordName?: string;
  verifyRecordType?: string;
  verifyRecordValue?: string;
  verificationCode?: string;
  certificateMode?: string;
  certificateId?: string;
  certificateIds?: string[];
  certificateStatus?: string;
  certificateIssuer?: string;
  certificateEffectiveTime?: string;
  certificateExpireTime?: string;
  certificateSignAlgo?: string;
  certificateBound?: boolean;
  createdAt?: string;
  updatedAt?: string;
  raw?: Record<string, unknown>;
}

export interface AccelerationCertificate {
  hosts?: string[];
  host?: string;
  certificateId?: string;
  certId?: string;
  certType?: string;
  status?: string;
  issuer?: string | null;
  subject?: string | null;
  signAlgo?: string | null;
  expireTime?: string;
  effectiveTime?: string;
  requestId?: string;
  raw?: Record<string, unknown>;
}

export async function listAccelerationSites(params: {
  credentialId: number;
  provider?: string;
  keyword?: string;
}): Promise<ApiResponse<{ sites: AccelerationSite[]; total: number }>> {
  const response = await api.get('/accelerations/sites', { params });
  return response as unknown as ApiResponse<{ sites: AccelerationSite[]; total: number }>;
}

export async function createAccelerationSite(data: {
  credentialId: number;
  provider?: string;
  zoneName: string;
  area?: string;
  type?: string;
  planId?: string;
}): Promise<ApiResponse<{ site: AccelerationSite }>> {
  const response = await api.post('/accelerations/sites', data);
  return response as unknown as ApiResponse<{ site: AccelerationSite }>;
}

export async function identifyAccelerationSite(data: {
  credentialId: number;
  provider?: string;
  zoneName: string;
}): Promise<ApiResponse<{ zoneName: string; zone?: AccelerationSite | null; verification: AccelerationVerificationInfo }>> {
  const response = await api.post('/accelerations/sites/identify', data);
  return response as unknown as ApiResponse<{ zoneName: string; zone?: AccelerationSite | null; verification: AccelerationVerificationInfo }>;
}

export async function verifyAccelerationSite(data: {
  credentialId: number;
  provider?: string;
  zoneName: string;
  siteId?: string;
  verificationCode?: string;
}): Promise<ApiResponse<{ zoneName: string; site?: AccelerationSite | null; status?: string; passed?: boolean }>> {
  const response = await api.post('/accelerations/sites/verify', data);
  return response as unknown as ApiResponse<{ zoneName: string; site?: AccelerationSite | null; status?: string; passed?: boolean }>;
}

export async function updateAccelerationSiteStatus(data: {
  credentialId: number;
  provider?: string;
  siteId: string;
  zoneName?: string;
  enabled: boolean;
}): Promise<ApiResponse<{ siteId: string; enabled: boolean }>> {
  const response = await api.post(`/accelerations/sites/${encodeURIComponent(data.siteId)}/status`, data);
  return response as unknown as ApiResponse<{ siteId: string; enabled: boolean }>;
}

export async function deleteAccelerationSite(params: {
  credentialId: number;
  provider?: string;
  siteId: string;
  zoneName?: string;
}): Promise<ApiResponse<{ siteId: string; requestId?: string }>> {
  const response = await api.delete(`/accelerations/sites/${encodeURIComponent(params.siteId)}`, { params });
  return response as unknown as ApiResponse<{ siteId: string; requestId?: string }>;
}

export async function listAccelerationDomains(params: {
  credentialId: number;
  provider?: string;
  siteId: string;
  domainName?: string;
  keyword?: string;
}): Promise<ApiResponse<{ domains: AccelerationDomain[]; total: number; siteId: string }>> {
  const response = await api.get('/accelerations/domains', { params });
  return response as unknown as ApiResponse<{ domains: AccelerationDomain[]; total: number; siteId: string }>;
}

export async function createAccelerationDomain(data: {
  credentialId: number;
  provider?: string;
  siteId: string;
  domainName: string;
  originType?: string;
  originValue: string;
  backupOriginValue?: string;
  hostHeader?: string;
  originProtocol?: string;
  httpOriginPort?: number;
  httpsOriginPort?: number;
  ipv6Status?: string;
  upsert?: boolean;
}): Promise<ApiResponse<{ domain: AccelerationDomain }>> {
  const response = await api.post('/accelerations/domains', data);
  return response as unknown as ApiResponse<{ domain: AccelerationDomain }>;
}

export async function updateAccelerationDomain(domainName: string, data: {
  credentialId: number;
  provider?: string;
  siteId: string;
  originType?: string;
  originValue: string;
  backupOriginValue?: string;
  hostHeader?: string;
  originProtocol?: string;
  httpOriginPort?: number;
  httpsOriginPort?: number;
  ipv6Status?: string;
}): Promise<ApiResponse<{ domain: AccelerationDomain }>> {
  const response = await api.put(`/accelerations/domains/${encodeURIComponent(domainName)}`, data);
  return response as unknown as ApiResponse<{ domain: AccelerationDomain }>;
}

export async function finalizeAccelerationDomain(domainName: string, data: {
  credentialId: number;
  provider?: string;
  siteId: string;
  originType?: string;
  originValue: string;
  backupOriginValue?: string;
  hostHeader?: string;
  originProtocol?: string;
  httpOriginPort?: number;
  httpsOriginPort?: number;
  ipv6Status?: string;
  dnsCredentialId?: number;
  autoMatchDns?: boolean;
  ttl?: number;
}): Promise<ApiResponse<{
  domain: AccelerationDomain;
  dnsRecordsAdded?: AccelerationDnsRecord[];
  dnsErrors?: Array<{ key?: string; error: string }>;
  dnsConflicts?: AccelerationDnsConflict[];
  dnsCheck?: AccelerationDnsCheck;
  publicResolution?: AccelerationPublicResolution;
}>> {
  const response = await api.post(`/accelerations/domains/${encodeURIComponent(domainName)}/finalize`, data);
  return response as unknown as ApiResponse<{
    domain: AccelerationDomain;
    dnsRecordsAdded?: AccelerationDnsRecord[];
    dnsErrors?: Array<{ key?: string; error: string }>;
    dnsConflicts?: AccelerationDnsConflict[];
    dnsCheck?: AccelerationDnsCheck;
    publicResolution?: AccelerationPublicResolution;
  }>;
}

export async function updateAccelerationDomainStatus(domainName: string, data: {
  credentialId: number;
  provider?: string;
  siteId: string;
  enabled: boolean;
}): Promise<ApiResponse<{ zoneId: string; domainNames: string[]; enabled: boolean }>> {
  const response = await api.post(`/accelerations/domains/${encodeURIComponent(domainName)}/status`, data);
  return response as unknown as ApiResponse<{ zoneId: string; domainNames: string[]; enabled: boolean }>;
}

export async function deleteAccelerationDomain(params: {
  credentialId: number;
  provider?: string;
  siteId: string;
  domainName: string;
}): Promise<ApiResponse<{ zoneId: string; domainNames: string[]; requestId?: string }>> {
  const response = await api.delete(`/accelerations/domains/${encodeURIComponent(params.domainName)}`, { params });
  return response as unknown as ApiResponse<{ zoneId: string; domainNames: string[]; requestId?: string }>;
}

export async function getAccelerationDomainStatus(data: {
  credentialId: number;
  provider?: string;
  siteId: string;
  domainName: string;
  dnsCredentialId?: number;
  autoMatchDns?: boolean;
}): Promise<ApiResponse<{ zoneId: string; domainName: string; status: string; message?: string; dnsCheck?: AccelerationDnsCheck; domain?: AccelerationDomain }>> {
  const response = await api.post('/accelerations/domains/status', data);
  return response as unknown as ApiResponse<{ zoneId: string; domainName: string; status: string; message?: string; dnsCheck?: AccelerationDnsCheck; domain?: AccelerationDomain }>;
}

export async function autoVerifyAccelerationSiteDns(data: {
  credentialId: number;
  provider?: string;
  zoneName: string;
  siteId?: string;
  dnsCredentialId?: number;
  autoMatchDns?: boolean;
  autoVerify?: boolean;
  ttl?: number;
}): Promise<ApiResponse<{
  zoneName: string;
  siteId?: string;
  verification?: AccelerationVerificationInfo;
  dnsRecordsAdded?: AccelerationDnsRecord[];
  dnsRecordsSkipped?: AccelerationDnsRecord[];
  dnsErrors?: Array<{ key?: string; error: string }>;
  verifySubmitted?: boolean;
  verifyError?: string;
  verifyResult?: { status?: string; passed?: boolean };
}>> {
  const response = await api.post('/accelerations/sites/auto-verify-dns', data);
  return response as unknown as ApiResponse<{
    zoneName: string;
    siteId?: string;
    verification?: AccelerationVerificationInfo;
    dnsRecordsAdded?: AccelerationDnsRecord[];
    dnsRecordsSkipped?: AccelerationDnsRecord[];
    dnsErrors?: Array<{ key?: string; error: string }>;
    verifySubmitted?: boolean;
    verifyError?: string;
    verifyResult?: { status?: string; passed?: boolean };
  }>;
}

export async function autoConfigureAccelerationCname(data: {
  credentialId: number;
  provider?: string;
  siteId: string;
  domainName: string;
  dnsCredentialId?: number;
  autoMatchDns?: boolean;
  ttl?: number;
}): Promise<ApiResponse<{
  domain: AccelerationDomain;
  dnsRecordsAdded?: AccelerationDnsRecord[];
  dnsErrors?: Array<{ key?: string; error: string }>;
  dnsConflicts?: AccelerationDnsConflict[];
  dnsCheck?: AccelerationDnsCheck;
  publicResolution?: AccelerationPublicResolution;
}>> {
  const response = await api.post('/accelerations/domains/auto-cname', data);
  return response as unknown as ApiResponse<{
    domain: AccelerationDomain;
    dnsRecordsAdded?: AccelerationDnsRecord[];
    dnsErrors?: Array<{ key?: string; error: string }>;
    dnsConflicts?: AccelerationDnsConflict[];
    dnsCheck?: AccelerationDnsCheck;
    publicResolution?: AccelerationPublicResolution;
  }>;
}

export async function createAccelerationCertificate(data: {
  credentialId: number;
  provider?: string;
  siteId: string;
  domainName: string;
  alternativeNames?: string[];
}): Promise<ApiResponse<{
  zoneId: string;
  domainName: string;
  certificateId?: string;
  status?: string;
  requestId?: string;
}>> {
  const response = await api.post('/accelerations/certificates/create', data);
  return response as unknown as ApiResponse<{
    zoneId: string;
    domainName: string;
    certificateId?: string;
    status?: string;
    requestId?: string;
  }>;
}

export async function bindAccelerationCertificate(data: {
  credentialId: number;
  provider?: string;
  siteId: string;
  hosts: string[];
  certType: string;
  certId?: string;
  certInfo?: {
    CertContent?: string;
    PrivateKey?: string;
    CertId?: string;
  };
}): Promise<ApiResponse<{ zoneId: string; hosts: string[]; certId?: string; certificates?: AccelerationCertificate[]; items?: AccelerationCertificate[]; requestId?: string }>> {
  const response = await api.post('/accelerations/certificates/bind', data);
  return response as unknown as ApiResponse<{ zoneId: string; hosts: string[]; certId?: string; certificates?: AccelerationCertificate[]; items?: AccelerationCertificate[]; requestId?: string }>;
}

export async function listAccelerationCertificates(params: {
  credentialId: number;
  provider?: string;
  siteId: string;
  hosts?: string[];
}): Promise<ApiResponse<{ zoneId: string; certificates: AccelerationCertificate[]; items?: AccelerationCertificate[]; requestId?: string }>> {
  const response = await api.get('/accelerations/certificates', { params });
  return response as unknown as ApiResponse<{ zoneId: string; certificates: AccelerationCertificate[]; items?: AccelerationCertificate[]; requestId?: string }>;
}
