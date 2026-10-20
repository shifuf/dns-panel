"""腾讯云平台证书部署：上传走 SSL 服务，绑定 CDN 域名走
SSL 服务的 DeployCertificateInstance（一键部署到 CDN/CLB 等云资源）。

说明：CDN 独立服务（cdn.tencentcloudapi.com）的域名查询接口对部分账号
返回 InvalidAction，因此域名绑定统一改用 SSL 服务的一键部署接口，
其 ResourceSet 支持 ResourceType="cdn" + 域名。
"""
from __future__ import annotations

from typing import Any, Dict

from modules.tencent_ssl_api import TencentSslApi, TencentSslApiError


class TencentPlatformApi(TencentSslApi):
    """复用腾讯云 SSL 凭证（SecretId/SecretKey）完成平台部署动作。"""

    def test_connection(self) -> int:
        """list 一张证书证明 SecretId/SecretKey 有效，返回证书总数。"""
        resp = self.list_certificates(offset=0, limit=1) or {}
        total = int(resp.get("totalCount") or resp.get("TotalCount") or len(resp.get("certificates") or []))
        return total

    def upload_cert(self, name: str, ca_pem: str, private_pem: str) -> str:
        result = self.upload_certificate(ca_pem, private_pem, alias=name)
        cert_id = str(result.get("CertificateId") or "").strip()
        if not cert_id:
            raise TencentSslApiError("腾讯云上传证书未返回证书 ID", 502)
        return cert_id

    def get_binding_status(self, domain: str) -> Dict[str, Any]:
        """查询 CDN 域名当前 HTTPS 配置（DescribeDomainConfigHttps，实时状态）。

        CDN 独立服务接口对部分账号可能报 InvalidAction，此时返回
        {bound: None} 表示"无法实时检查，以上次上传记录为准"。
        """
        domain = str(domain or "").strip().strip(".")
        if not domain:
            raise TencentSslApiError("缺少域名", 400)
        try:
            conf = self._tc3_request("DescribeDomainConfigHttps", {"Domain": domain}) or {}
        except TencentSslApiError as exc:
            if "InvalidAction" in str(exc) or "InvalidParameter" in str(exc):
                return {"bound": None, "error": str(exc)[:200]}
            raise
        https = conf.get("HttpsInfo") or conf.get("Https") or {}
        cert_id = str(https.get("CertId") or "").strip()
        return {
            "bound": bool(cert_id),
            "certificateId": cert_id,
            "https": str(https.get("Switch") or "").lower() == "on",
            "forceHttps": str(https.get("ForceHttps") or "").lower() == "on",
            "raw": conf,
        }

    def bind_cdn_domain(self, domain: str, cert_id: str) -> Dict[str, Any]:
        """DeployCertificateInstance：把证书一键部署到 CDN 域名。"""
        domain = str(domain or "").strip().strip(".")
        cert_id = str(cert_id or "").strip()
        if not domain or not cert_id:
            raise TencentSslApiError("绑定证书需要域名与证书 ID", 400)
        return self._tc3_request("DeployCertificateInstance", {
            "CertificateId": cert_id,
            "ResourceSet": [
                {"ResourceType": "cdn", "ResourceResourceId": domain},
            ],
            "Status": 1,
        }) or {}
