import os
import sys
import importlib.util
import types
import unittest

PLUGIN_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", "baota-ssl-plugin")
PLUGIN_FILE = os.path.join(PLUGIN_DIR, "dnspanel_ssl_main.py")


def _load_plugin():
    saved_chdir = os.chdir
    os.chdir = lambda *a, **k: None
    try:
        fake = types.ModuleType("public")
        fake.ReadFile = lambda path: None
        fake.WriteLog = lambda *a, **k: None
        fake.M = lambda *a, **k: None
        fake.GetWebServer = lambda: "nginx"
        fake.ReturnMsg = lambda status, msg: {"status": bool(status), "msg": str(msg)}
        sys.modules["public"] = fake
        spec = importlib.util.spec_from_file_location("dnspanel_ssl_regression", PLUGIN_FILE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        os.chdir = saved_chdir


class CertificateSummaryShapeTests(unittest.TestCase):
    """A certificate summary must be a dict: a stray trailing comma
    once made it a tuple, and the caller then failed with
    "'tuple' object does not support item assignment"."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_plugin()

    def test_summary_from_pem_returns_dict(self):
        mod = self.mod
        original_run = mod._run_checked
        original_names = mod._cert_names_from_pem
        original_write = mod._atomic_write
        original_remove = mod.os.remove
        mod._run_checked = lambda cmd: (True, "notAfter=Dec 31 23:59:59 2999 GMT" + chr(10) + "SHA256 Fingerprint=AA:BB:CC")
        mod._cert_names_from_pem = lambda text: ["files.shifuf.com"]
        mod._atomic_write = lambda path, content, mode=0o600: None
        mod.os.remove = lambda path: None
        try:
            summary = mod._cert_summary_from_pem("-----BEGIN CERTIFICATE-----")
        finally:
            mod._run_checked = original_run
            mod._cert_names_from_pem = original_names
            mod._atomic_write = original_write
            mod.os.remove = original_remove
        self.assertIsInstance(summary, dict)
        self.assertEqual(summary["names"], ["files.shifuf.com"])

    def test_summary_from_file_can_add_path(self):
        mod = self.mod
        original_exists = mod.os.path.exists
        original_size = mod.os.path.getsize
        original_summary = mod._cert_summary_from_pem
        original_read = mod.public.ReadFile
        mod.os.path.exists = lambda path: True
        mod.os.path.getsize = lambda path: 128
        mod._cert_summary_from_pem = lambda text: {"names": ["files.shifuf.com"], "expiry": None, "fingerprint": "aa"}
        mod.public.ReadFile = lambda path: "-----BEGIN CERTIFICATE-----"
        try:
            summary = mod._cert_summary_from_file("/tmp/example.pem")
        finally:
            mod.os.path.exists = original_exists
            mod.os.path.getsize = original_size
            mod._cert_summary_from_pem = original_summary
            mod.public.ReadFile = original_read
        self.assertIsInstance(summary, dict)
        self.assertEqual(summary["path"], "/tmp/example.pem")


class DeployedCertificateDetectionTests(unittest.TestCase):
    """A site that already serves a certificate covering the panel
    certificate's names must be reported as deployed, even when its copy is
    older; expiry alone must not turn it into "not deployed"."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_plugin()

    def test_site_covering_panel_names_is_deployed(self):
        mod = self.mod
        original_exists = mod.os.path.exists
        original_size = mod.os.path.getsize
        mod.os.path.exists = lambda path: True
        mod.os.path.getsize = lambda path: 128
        try:
            summary = mod._installed_cert_summary("files.shifuf.com")
        finally:
            mod.os.path.exists = original_exists
            mod.os.path.getsize = original_size
        self.assertEqual(mod._names_coverage_score(["*.shifuf.com"], ["*.shifuf.com"]), 1)
        self.assertTrue(mod._is_supersede(["*.shifuf.com"], ["*.shifuf.com"]))
        self.assertFalse(mod._is_supersede(["*.shifuf.com"], ["files.shifuf.com"]))




class RealSiteNameTests(unittest.TestCase):
    """BaoTa's vhost directory also holds internal worker configs whose
    file names are not domains; they must never be reported as sites."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_plugin()

    def test_non_domain_worker_names_are_filtered(self):
        mod = self.mod
        for name in ("0.fastcgi_cache", "0.site_total_log_format", "0.websocket", "waf2monitor_data", "0.default", "ssl.files.shifuf.com"):
            self.assertFalse(mod._is_real_site_name(name), name)

    def test_real_domains_are_kept(self):
        mod = self.mod
        for name in ("dns.shifuf.com", "ai.shifuf.com", "cpa.shifuf.com", "account.shifuf.com"):
            self.assertTrue(mod._is_real_site_name(name), name)


class DeployedSourceLabelTests(unittest.TestCase):
    """The UI must say whether the certificate a site serves came from
    Tencent Cloud or Let's Encrypt, and must not guess when it cannot tell."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_plugin()

    def test_known_sources_are_named(self):
        mod = self.mod
        self.assertEqual(mod._deployed_source_label({"sources": ["tencent"]}), "腾讯云")
        self.assertEqual(mod._deployed_source_label({"sources": ["letsencrypt"]}), "Let's Encrypt")

    def test_unknown_source_is_not_guessed(self):
        mod = self.mod
        self.assertEqual(mod._deployed_source_label({}), "手工部署")


class SiteHostCoverageTests(unittest.TestCase):
    """Deployment is decided against the site's own hosts, so a site
    serving its own exact-domain certificate is deployed even when the panel
    offers a wildcard for the same parent domain."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_plugin()

    def test_exact_domain_cert_covers_its_own_site(self):
        mod = self.mod
        self.assertEqual(mod._names_coverage_score(["dns.shifuf.com"], ["dns.shifuf.com"]), 1)

    def test_wildcard_cert_also_covers_its_own_site(self):
        mod = self.mod
        self.assertEqual(mod._names_coverage_score(["*.shifuf.com"], ["dns.shifuf.com"]), 1)



class NoOpensslCertificateReadingTests(unittest.TestCase):
    """BaoTa's panel Python has a minimal PATH and frequently no openssl
    binary. Reading certificates must not depend on it: when it did, every
    certificate came back unreadable and every site was reported undeployed."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_plugin()

    def _real_pem(self):
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "data", "wildcard-le.pem")
        with open(path, "rb") as handle:
            return handle.read().decode("ascii")

    def test_names_read_without_openssl(self):
        mod = self.mod
        original = mod._find_executable
        mod._find_executable = lambda candidates: None
        try:
            names = mod._cert_names_from_pem(self._real_pem())
        finally:
            mod._find_executable = original
        self.assertIn("*.shifuf.com", names)
        self.assertIn("shifuf.com", names)

    def test_summary_read_without_openssl(self):
        mod = self.mod
        original = mod._run_checked
        mod._run_checked = lambda command: (False, "openssl: not found")
        try:
            summary = mod._cert_summary_from_pem(self._real_pem())
        finally:
            mod._run_checked = original
        self.assertIsInstance(summary, dict)
        self.assertEqual(summary["names"], ["*.shifuf.com", "shifuf.com"])
        self.assertIsNotNone(summary["expiry"])
        self.assertEqual(summary["issuerOrg"], "Let's Encrypt")

    def test_issuer_identified_without_openssl(self):
        mod = self.mod
        original = mod._run_checked
        mod._run_checked = lambda command: (False, "openssl: not found")
        try:
            label = mod._issuer_source_label(self._real_pem())
        finally:
            mod._run_checked = original
        self.assertEqual(label, "letsencrypt")



class CertificateChainTests(unittest.TestCase):
    """A leaf-only certificate makes https report 不安全: the browser cannot
    build a path to a trusted root. The plugin must detect that and repair it
    without the user editing files by hand."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_plugin()

    def _fixture(self, name):
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "data", name)
        with open(path, "r") as handle:
            return handle.read()

    def test_leaf_only_chain_is_incomplete(self):
        mod = self.mod
        leaf = self._fixture("chain-leaf.pem")
        self.assertEqual(mod._pem_certificate_count(leaf), 1)
        self.assertFalse(mod._pem_chain_complete(leaf))

    def test_leaf_plus_intermediate_is_complete(self):
        mod = self.mod
        chain = self._fixture("chain-leaf-inter.pem")
        self.assertEqual(mod._pem_certificate_count(chain), 2)
        self.assertTrue(mod._pem_chain_complete(chain))

    def test_leaf_intermediate_root_is_complete(self):
        mod = self.mod
        chain = self._fixture("chain-full.pem")
        self.assertEqual(mod._pem_certificate_count(chain), 3)
        self.assertTrue(mod._pem_chain_complete(chain))

    def test_repair_adds_the_missing_intermediate(self):
        mod = self.mod
        here = os.path.dirname(os.path.abspath(__file__))
        work = os.path.join(here, "data")
        leaf = self._fixture("chain-leaf.pem")
        repaired, added, note = mod._complete_certificate_chain(leaf, "files.shifuf.com", work)
        self.assertEqual(added, 1, note)
        self.assertTrue(mod._pem_chain_complete(repaired))
        self.assertEqual(mod._pem_certificate_count(repaired), 2)

    def test_repair_is_idempotent(self):
        mod = self.mod
        here = os.path.dirname(os.path.abspath(__file__))
        work = os.path.join(here, "data")
        full = self._fixture("chain-full.pem")
        repaired, added, note = mod._complete_certificate_chain(full, "files.shifuf.com", work)
        self.assertEqual(added, 0, note)
        self.assertEqual(mod._pem_certificate_count(repaired), 3)

    def test_intermediate_issuer_names_are_recognised(self):
        mod = self.mod
        self.assertEqual(mod._issuer_label_from_text("YR2"), "letsencrypt")
        self.assertEqual(mod._issuer_label_from_text("ISRG Root X1"), "letsencrypt")
        self.assertEqual(mod._issuer_label_from_text("R10"), "letsencrypt")

if __name__ == "__main__":
    unittest.main()
