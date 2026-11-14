"""Tunnel regressions exercise the real API adapter and HTTP route orchestration."""
from __future__ import annotations

import io
import json
import sys
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app
from modules.cloudflare_api import CloudflareApi, CloudflareApiError


class TunnelTests(unittest.TestCase):
    def setUp(self):
        self.api = CloudflareApi("test-token")
        self.calls = []
        self.config = {"ingress": [
            {"hostname": "app.example.com", "path": "/api", "service": "http://localhost:80", "originRequest": {"noTLSVerify": True}},
            {"hostname": "app.example.com", "path": "/web", "service": "http://localhost:80"},
            {"service": "http_status:404"}], "originRequest": {"connectTimeout": 30}}
        self.records = [{"id": "dns", "name": "app.example.com", "type": "CNAME", "content": "tid.cfargotunnel.com", "proxied": True}]
        self.tunnel_deleted = False
        self.patcher = patch("modules.cloudflare_api.urllib.request.urlopen", side_effect=self.transport)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def transport(self, req, timeout=60):
        url = urllib.parse.urlsplit(req.full_url)
        path = url.path.removeprefix("/client/v4")
        query = urllib.parse.parse_qs(url.query)
        body = json.loads(req.data) if req.data else None
        self.calls.append((req.method, path, query, body))
        result, info = self.respond(req.method, path, query, body)
        if isinstance(result, list) and info == {}:
            info = {"total_count": len(result), "total_pages": 1}
        return io.BytesIO(json.dumps({"success": True, "result": result, "result_info": info}).encode())

    def respond(self, method, path, query, body):
        if path == "/accounts":
            return [{"id": "aid", "name": "Account"}], {}
        if path == "/zones":
            return [{"id": "zid", "name": "example.com", "account": {"id": "aid", "name": "Account"}}], {}
        if path == "/zones/zid":
            return {"id": "zid", "name": "example.com", "account": {"id": "aid"}}, {}
        if path == "/accounts/aid/cfd_tunnel" and method == "POST":
            return {"id": "tid", "name": body["name"], "remote_config": body.get("config_src") == "cloudflare"}, {}
        if path == "/accounts/aid/cfd_tunnel/tid":
            if method == "DELETE":
                self.tunnel_deleted = True
            return {"id": "tid", "remote_config": True}, {}
        if path.endswith("/configurations"):
            if method == "PUT":
                self.config = body["config"]
            return {"config": self.config}, {}
        if path == "/zones/zid/dns_records":
            return self.records, {"total_count": len(self.records)}
        if path == "/zones/zid/dns_records/dns" and method == "DELETE":
            self.records = []
            return {"id": "dns"}, {}
        if path == "/zones/zid/dns_records/dns" and method == "PUT":
            self.records = [{"id": "dns", **body}]
            return self.records[0], {}
        raise AssertionError(f"Unexpected HTTP request: {method} {path}")

    def route(self, method, suffix, body=None, query=None):
        handler = app.H.__new__(app.H)
        handler.command = method
        handler._auth = lambda: {"id": 1}
        handler._cf_context = lambda *a, **kw: {"cf": self.api, "accountId": "aid", "credential": {"accountId": "aid"}}
        handler._ok = lambda data, message="", code=200: setattr(handler, "result", (code, data))
        handler._err = lambda message, code=400: setattr(handler, "result", (code, {"message": message}))
        handler._tunnels_routes("/api/tunnels" + suffix, {"credentialId": ["1"], **(query or {})}, json.dumps(body or {}).encode())
        return handler.result

    def test_tunnel_listing_reads_all_pages_and_excludes_deleted(self):
        def pages(method, path, query, body):
            page = int(query.get("page", ["1"])[0])
            self.assertEqual(query.get("is_deleted"), ["false"])
            return ([{"id": "first"}, {"id": "old", "deleted_at": "2026-01-01"}] if page == 1 else [{"id": "last"}]), {"total_pages": 2}
        self.respond = pages
        self.assertEqual([t["id"] for t in self.api.list_tunnels("aid", page_size=2)], ["first", "last"])

    def test_creation_uses_remote_configuration(self):
        self.assertTrue(self.api.create_tunnel("aid", "new")["remote_config"])

    def test_account_discovery_falls_back_to_zone_accounts_on_forbidden(self):
        # The network layer must raise HTTPError so the real adapter retains status.
        import urllib.error
        error = urllib.error.HTTPError("https://api.cloudflare.com", 403, "forbidden", {}, io.BytesIO(b'{"errors":[{"message":"forbidden"}]}'))
        self.addCleanup(error.close)
        def forbidden(req, timeout=60):
            if urllib.parse.urlsplit(req.full_url).path.endswith("/accounts"):
                raise error
            return self.transport(req, timeout)
        with patch("modules.cloudflare_api.urllib.request.urlopen", side_effect=forbidden):
            self.assertEqual(self.api.get_default_account_id(), "aid")

    def test_upsert_refuses_to_replace_unrelated_cname(self):
        self.records[0]["content"] = "unrelated.example.net"
        with self.assertRaises(CloudflareApiError):
            self.api.upsert_tunnel_cname_record("zid", "app.example.com", "tid")
        self.assertEqual(self.records[0]["content"], "unrelated.example.net")

    def test_public_route_infers_zone_and_preserves_extra_configuration(self):
        status, data = self.route("POST", "/tid/public-hostnames", {"hostname": "APP.example.com", "path": "/api", "service": "http://localhost:8080"})
        self.assertEqual(status, 200, data)
        self.assertEqual(self.config["ingress"][0]["originRequest"], {"noTLSVerify": True})
        self.assertEqual(self.config["ingress"][0]["service"], "http://localhost:8080")
        self.assertEqual(self.config["originRequest"], {"connectTimeout": 30})
        self.assertEqual(self.config["ingress"][-1], {"service": "http_status:404"})

    def test_deleting_one_path_preserves_dns_used_by_another_path(self):
        status, data = self.route("DELETE", "/tid/public-hostnames", {"hostname": "app.example.com", "path": "/api", "zoneId": "zid", "deleteDns": True})
        self.assertEqual(status, 200, data)
        self.assertEqual(len(self.records), 1)
        self.assertEqual([r.get("path") for r in self.config["ingress"]], ["/web", None])

    def test_tunnel_delete_really_cleans_matching_dns(self):
        status, data = self.route("DELETE", "/tid", query={"cleanupDns": ["1"]})
        self.assertEqual(status, 200, data)
        self.assertTrue(self.tunnel_deleted)
        self.assertEqual(self.records, [])
        self.assertEqual(data["cleanup"]["deleted"], 1)

    def test_invalid_service_is_rejected_before_config_mutation(self):
        status, data = self.route("POST", "/tid/public-hostnames", {"hostname": "app.example.com", "zoneId": "zid", "service": "localhost:80"})
        self.assertEqual(status, 400, data)
        self.assertFalse(any(c[0] == "PUT" for c in self.calls))

    def test_dns_conflict_rolls_back_config_without_changing_record(self):
        original = json.loads(json.dumps(self.config))
        self.records[0]["content"] = "elsewhere.example.net"
        status, data = self.route("POST", "/tid/public-hostnames", {"hostname": "app.example.com", "path": "/api", "zoneId": "zid", "service": "http://localhost:9090"})
        self.assertEqual(status, 400, data)
        self.assertEqual(self.config, original)
        self.assertEqual(self.records[0]["content"], "elsewhere.example.net")

    def test_local_tunnel_cannot_mutate_remote_config(self):
        original = self.respond
        def respond(method, path, query, body):
            if method == "GET" and path == "/accounts/aid/cfd_tunnel/tid":
                return {"id": "tid", "remote_config": False}, {}
            return original(method, path, query, body)
        self.respond = respond
        status, data = self.route("POST", "/tid/public-hostnames", {"hostname": "app.example.com", "service": "http://localhost:80"})
        self.assertEqual(status, 400, data)
        self.assertFalse(any(c[0] in ("PUT", "POST", "DELETE") for c in self.calls))

    def test_dns_inventory_failure_keeps_tunnel_intact(self):
        original = self.respond
        def respond(method, path, query, body):
            if path == "/zones":
                raise OSError("zone access unavailable")
            return original(method, path, query, body)
        self.respond = respond
        status, _ = self.route("DELETE", "/tid", query={"cleanupDns": ["1"]})
        self.assertGreaterEqual(status, 400)
        self.assertFalse(self.tunnel_deleted)
        self.assertEqual(len(self.records), 1)

    def test_dns_cleanup_failure_is_reported_after_successful_tunnel_delete(self):
        original = self.respond
        def respond(method, path, query, body):
            if method == "DELETE" and path == "/zones/zid/dns_records/dns":
                raise OSError("DNS deletion denied")
            return original(method, path, query, body)
        self.respond = respond
        status, data = self.route("DELETE", "/tid", query={"cleanupDns": ["1"]})
        self.assertEqual(status, 200, data)
        self.assertTrue(self.tunnel_deleted)
        self.assertEqual(data["cleanup"]["deleted"], 0)
        self.assertEqual(data["cleanup"]["errors"][0]["hostname"], "app.example.com")

    def test_tunnel_delete_failure_keeps_dns_intact(self):
        original = self.respond
        def respond(method, path, query, body):
            if method == "DELETE" and path == "/accounts/aid/cfd_tunnel/tid":
                raise OSError("tunnel has active connections")
            return original(method, path, query, body)
        self.respond = respond
        status, _ = self.route("DELETE", "/tid", query={"cleanupDns": ["1"]})
        self.assertGreaterEqual(status, 400)
        self.assertEqual(len(self.records), 1)

    def test_private_routes_include_later_pages_and_only_requested_tunnel(self):
        def respond(method, path, query, body):
            if int(query["page"][0]) == 1:
                return [{"id": "r1", "tunnel_id": "tid"}, {"id": "foreign", "tunnel_id": "other"}], {"total_pages": 2}
            return [{"id": "r2", "tunnel_id": "tid"}, {"id": "deleted", "tunnel_id": "tid", "deleted_at": "2026-01-01"}], {"total_pages": 2}
        self.respond = respond
        self.assertEqual([r["id"] for r in self.api.list_cidr_routes("aid", "tid", page_size=2)], ["r1", "r2"])
        self.assertEqual([r["id"] for r in self.api.list_hostname_routes("aid", "tid", page_size=2)], ["r1", "r2"])

    def test_empty_remote_config_can_receive_first_public_route(self):
        self.config = {}
        status, data = self.route("POST", "/tid/public-hostnames", {"hostname": "app.example.com", "service": "http://localhost:80"})
        self.assertEqual(status, 200, data)
        self.assertEqual(self.config["ingress"], [{"hostname": "app.example.com", "service": "http://localhost:80"}, {"service": "http_status:404"}])

    def test_invalid_cidr_is_rejected_before_cloudflare_create(self):
        status, data = self.route("POST", "/tid/routes/cidr", {"network": "10.0.0.1/8"})
        self.assertEqual(status, 400, data)
        self.assertFalse(any(c[0] == "POST" for c in self.calls))

    def test_pagination_uses_actual_batch_size_when_cloudflare_caps_page_size(self):
        self.respond = lambda method, path, query, body: (([{"id": "first"}] if query["page"] == ["1"] else [{"id": "last"}]), {"total_count": 2})
        self.assertEqual([t["id"] for t in self.api.list_tunnels("aid", page_size=100)], ["first", "last"])

    def test_pagination_rejects_incomplete_result_instead_of_presenting_it_as_complete(self):
        self.respond = lambda method, path, query, body: (([{"id": "first"}] if query["page"] == ["1"] else []), {"total_count": 3})
        with self.assertRaises(CloudflareApiError):
            self.api.list_tunnels("aid")

    def test_new_tunnel_response_does_not_request_or_return_installation_secret(self):
        status, data = self.route("POST", "/", {"name": "new"})
        self.assertEqual(status, 201, data)
        self.assertNotIn("tunnel_secret", self.calls[0][3])
        self.assertNotIn("token", data)

    def test_installation_token_response_prevents_browser_caching(self):
        original = self.respond
        def respond(method, path, query, body):
            return ("test-install-token", {}) if path.endswith("/token") else original(method, path, query, body)
        self.respond = respond
        handler = app.H.__new__(app.H)
        handler.command = "GET"
        handler._auth = lambda: {"id": 1}
        handler._cf_context = lambda *a, **kw: {"cf": self.api, "accountId": "aid"}
        headers = {}
        handler.send_response = lambda code: None
        handler._cors = lambda: None
        handler.send_header = lambda key, value: headers.update({key: value})
        handler.end_headers = lambda: None
        handler.wfile = io.BytesIO()
        handler._tunnels_routes("/api/tunnels/tid/token", {"credentialId": ["1"]}, b"{}")
        self.assertIn("no-store", headers.get("Cache-Control", ""))
        self.assertEqual(json.loads(handler.wfile.getvalue())["data"]["token"], "test-install-token")

    def test_malformed_installation_token_is_an_error_not_a_shell_command(self):
        self.respond = lambda *args: ({"unexpected": "value"}, {})
        with self.assertRaises(CloudflareApiError):
            self.api.get_tunnel_token("aid", "tid")


if __name__ == "__main__":
    unittest.main()
