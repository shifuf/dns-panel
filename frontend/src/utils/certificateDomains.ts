export function certificateNames(cert?: { domain?: string; san?: string | string[] }): string[] {
  if (!cert) return [];
  let san: unknown = cert.san || [];
  if (typeof san === 'string') {
    const rawSan = san;
    try { san = JSON.parse(rawSan); } catch { san = rawSan.split(/[,，\s]+/); }
  }
  const values = [cert.domain, ...(Array.isArray(san) ? san : [])];
  return [...new Set(values.filter((v): v is string => typeof v === 'string' && !!v.trim())
    .map(v => v.trim().toLowerCase().replace(/\.$/, '')))];
}

export function certificateCoversDomain(domain: string, names: string[]): boolean {
  const host = domain.trim().toLowerCase().replace(/\.$/, '');
  return names.some(name => {
    if (name === host) return true;
    if (!name.startsWith('*.') || host.startsWith('*.')) return false;
    const suffix = name.slice(1);
    if (!host.endsWith(suffix)) return false;
    const label = host.slice(0, -suffix.length);
    return !!label && !label.includes('.');
  });
}

export function deploymentDomains(input: string, names: string[], provider?: string): string[] {
  const domains = [...new Set(input.split(/[,，\s]+/).map(v => v.trim().toLowerCase().replace(/\.$/, '')).filter(Boolean))];
  if (!domains.length) throw new Error('请填写平台已接入的 CDN 域名');
  for (const domain of domains) {
    const coverageDomain = provider === 'qiniu' && domain.startsWith('.') ? '*' + domain : domain;
    const hostname = coverageDomain.startsWith('*.') ? coverageDomain.slice(2) : coverageDomain;
    const labels = hostname.split('.');
    if (domain.length > 253 || labels.length < 2 || labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
      throw new Error(`域名格式无效：${domain}，请只填写域名，不要包含协议、端口或路径`);
    }
    if (!certificateCoversDomain(coverageDomain, names)) {
      throw new Error(`证书不覆盖 ${domain}；泛域名证书只覆盖一层子域名`);
    }
  }
  return domains;
}
