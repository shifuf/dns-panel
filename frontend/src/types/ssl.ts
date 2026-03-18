export type SslCertificateStatus =
  | 'applying'
  | 'validating'
  | 'issued'
  | 'expired'
  | 'failed'
  | 'cancelled'
  | 'revoked'
  | 'upload';

export interface SslCertificate {
  id?: number;
  remoteCertId: string;
  credentialId?: number;
  credentialName?: string;
  provider?: string;
  domain: string;
  san?: string | string[];
  certType: string;
  productName?: string;
  status: SslCertificateStatus;
  statusMsg?: string;
  issuer?: string;
  notBefore?: string;
  notAfter?: string;
  isUploaded?: boolean;
  remoteCreatedAt?: string;
  syncedAt?: string;
}

export interface SslCertificateDetail extends SslCertificate {
  dvAuths?: Array<{
    domain: string;
    key: string;
    value: string;
    type: string;
  }>;
  dvAuthDetail?: {
    domain: string;
    key: string;
    value: string;
    type: string;
    path: string;
    subDomain: string;
  };
  deployedResources?: any[];
}

export interface ApplyCertificateParams {
  credentialId: number;
  domain: string;
  dvAuthMethod?: 'DNS_AUTO' | 'DNS' | 'FILE';
  dnsCredentialId?: number;
  autoDnsRecord?: boolean;
  autoMatchDns?: boolean;
  oldCertificateId?: string;
}

export interface UploadCertificateParams {
  credentialId: number;
  publicKey: string;
  privateKey: string;
  alias?: string;
}
