"""
Tests para compute_stats() — agregación de estadísticas globales.

Cobertura:
- Totales correctos con un solo reporte
- Totales correctos con múltiples reportes
- Tracking de IPs (sources, pass/fail por IP)
- Timeline por fecha
- Disposiciones agregadas
- IPs ignoradas se registran correctamente
- Reporte vacío (sin records)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dmarc_visualizer import parse_dmarc_xml, compute_stats

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load_fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


def _parse(name):
    return parse_dmarc_xml(_load_fixture(name), filename=name)


# ─────────────────────────────────────────────────────────────────
#  Stats con un solo reporte
# ─────────────────────────────────────────────────────────────────

class TestComputeStatsSingleReport:

    def setup_method(self):
        report = _parse("google_report.xml")
        self.stats = compute_stats([report])

    def test_total_reports(self):
        assert self.stats["total_reports"] == 1

    def test_total_messages(self):
        assert self.stats["total_messages"] == 4

    def test_pass_fail(self):
        assert self.stats["dmarc_pass"] == 4
        assert self.stats["dmarc_fail"] == 0

    def test_pass_rate(self):
        assert self.stats["dmarc_pass_rate"] == 100.0

    def test_alignment(self):
        assert self.stats["alignment_breakdown"]["spf_only"] == 4

    def test_sources(self):
        """Dos IPs: 194.104.111.120 (3 msgs) y 194.104.109.120 (1 msg)."""
        sources = self.stats["sources"]
        assert sources["194.104.111.120"] == 3
        assert sources["194.104.109.120"] == 1

    def test_ip_pass_tracking(self):
        assert self.stats["ip_pass"]["194.104.111.120"] == 3
        assert self.stats["ip_fail"]["194.104.111.120"] == 0

    def test_domains(self):
        assert "example.es" in self.stats["domains"]
        assert self.stats["domains"]["example.es"]["msgs"] == 4

    def test_orgs(self):
        assert self.stats["orgs"]["google.com"] == 1


# ─────────────────────────────────────────────────────────────────
#  Stats con múltiples reportes
# ─────────────────────────────────────────────────────────────────

class TestComputeStatsMultipleReports:

    def setup_method(self):
        r1 = _parse("google_report.xml")
        r2 = _parse("microsoft_report.xml")
        self.stats = compute_stats([r1, r2])

    def test_total_reports(self):
        assert self.stats["total_reports"] == 2

    def test_total_messages(self):
        """Google: 4 msgs + Microsoft: 11 msgs = 15."""
        assert self.stats["total_messages"] == 15

    def test_aggregated_pass_fail(self):
        """Google: 4 pass, 0 fail + Microsoft: 5 pass, 6 fail."""
        assert self.stats["dmarc_pass"] == 9
        assert self.stats["dmarc_fail"] == 6

    def test_pass_rate(self):
        """9/15 = 60.0%."""
        assert self.stats["dmarc_pass_rate"] == 60.0

    def test_dispositions(self):
        d = self.stats["dispositions"]
        assert d.get("quarantine", 0) == 3
        assert d.get("reject", 0) == 2

    def test_quarantine_records_tracked(self):
        assert len(self.stats["quarantine_records"]) == 1
        assert self.stats["quarantine_records"][0]["ip"] == "52.212.19.177"

    def test_reject_records_tracked(self):
        assert len(self.stats["reject_records"]) == 1
        assert self.stats["reject_records"][0]["ip"] == "203.0.113.50"

    def test_fail_records_tracked(self):
        """3 records fail en Microsoft: quarantine, reject, forwarded."""
        fail_ips = [r["ip"] for r in self.stats["fail_records"]]
        assert "52.212.19.177" in fail_ips
        assert "203.0.113.50" in fail_ips
        assert "82.223.190.18" in fail_ips

    def test_multiple_orgs(self):
        assert "google.com" in self.stats["orgs"]
        assert "microsoft.com" in self.stats["orgs"]

    def test_alignment_breakdown_mixed(self):
        ab = self.stats["alignment_breakdown"]
        assert ab.get("spf_only", 0) == 4      # Google: 4
        assert ab.get("full_pass", 0) == 5      # Microsoft: 5
        assert ab.get("fail", 0) == 6           # Microsoft: 3+2+1


# ─────────────────────────────────────────────────────────────────
#  IPs ignoradas
# ─────────────────────────────────────────────────────────────────

class TestComputeStatsIgnoredIPs:

    def test_ignored_ips_in_output(self):
        report = _parse("google_report.xml")
        ignored = {"194.104.111.120"}
        stats = compute_stats([report], ignored_ips=ignored)
        assert "194.104.111.120" in stats["ignored_ips"]

    def test_ip_labels(self):
        report = _parse("google_report.xml")
        labels = {"194.104.111.120": "Mimecast Gateway"}
        stats = compute_stats([report], ip_labels=labels)
        assert stats["ip_labels"]["194.104.111.120"] == "Mimecast Gateway"


# ─────────────────────────────────────────────────────────────────
#  Timeline
# ─────────────────────────────────────────────────────────────────

class TestComputeStatsTimeline:

    def test_timeline_has_entries(self):
        report = _parse("google_report.xml")
        stats = compute_stats([report])
        assert len(stats["timeline"]) > 0

    def test_timeline_values(self):
        report = _parse("google_report.xml")
        stats = compute_stats([report])
        # Todos los records comparten la misma date_label
        for date, data in stats["timeline"].items():
            assert "pass" in data
            assert "fail" in data
            assert "total" in data
            assert data["total"] == data["pass"] + data["fail"]


# ─────────────────────────────────────────────────────────────────
#  Edge cases
# ─────────────────────────────────────────────────────────────────

class TestComputeStatsEdgeCases:

    def test_empty_reports_list(self):
        stats = compute_stats([])
        assert stats["total_reports"] == 0
        assert stats["total_messages"] == 0
        assert stats["dmarc_pass_rate"] == 0

    def test_malformed_report(self):
        """Reporte con datos raros no debe romper compute_stats.

        NOTA: count no numérico (ej: 'abc') causa crash en parse_dmarc_xml
        por int() sin try/except. Bug pendiente de arreglar.
        """
        report = _parse("malformed_report.xml")
        stats = compute_stats([report])
        assert stats["total_reports"] == 1
        assert stats["total_messages"] == 0