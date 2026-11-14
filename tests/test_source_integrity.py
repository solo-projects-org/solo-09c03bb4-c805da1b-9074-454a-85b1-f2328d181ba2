"""Source-authentication tests: separator-collision fix.

Covers the vulnerability where the legacy sd1 source digest joins fields
with ``\x1f``; a sample/account id containing that control character can be
re-split across columns in SQLite without changing the digest, so a
regenerated report would silently attribute transactions to another
account.
"""

import csv
import io
import json
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from app import features
from app.config import Settings
from app.service import AppService, ConflictError

UTC = timezone.utc
DAY = 86400
US = "\x1f"  # the sd1 field separator, embedded in data


def ts(text: str) -> int:
    return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp())


AUDIT = ts("2025-01-10T12:00:00Z")


def txn_csv(rows: list[tuple]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["event_id", "account_id", "occurred_at", "ingested_at",
                "amount", "action"])
    for r in rows:
        w.writerow(r)
    return buf.getvalue().encode()


def sample_csv(rows: list[tuple]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["sample_id", "account_id", "audit_at", "label"])
    for r in rows:
        w.writerow(r)
    return buf.getvalue().encode()


class SourceIntegrityTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.svc = AppService(Settings(data_dir=self.dir, worker_poll_seconds=0.05))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #
    def upload_collision_sources(self):
        """Samples/txns where one account id carries the sd1 separator."""
        self.svc.upload_transactions("txn.csv", txn_csv([
            ("E91", f"A{US}B", AUDIT - 2 * DAY, AUDIT - 3 * DAY, "100.00", "revise"),
            ("E92", "B", AUDIT - 2 * DAY, AUDIT - 3 * DAY, "40.00", "revise"),
        ]))
        self.svc.upload_samples("samples.csv", sample_csv([
            ("S901", f"A{US}B", AUDIT, 1),
            ("S902", "B", AUDIT, 0),
        ]))

    def build(self) -> str:
        report = self.svc.create_report()
        pid = report["report_id"]
        self.svc.claim_next_report()
        self.svc.run_report(pid)
        return pid

    def output_rows(self, pid: str) -> list[dict]:
        found = self.svc.report_file(pid)
        self.assertIsNotNone(found, "report should be downloadable")
        return list(csv.DictReader(
            io.StringIO(found[0].read_text(encoding="utf-8"))))

    def downgrade_to_legacy(self, pid: str) -> None:
        """Rewrite the manifest exactly as the pre-fix version would have."""
        with self.svc.db.write_transaction() as conn:
            row = conn.execute(
                "SELECT txn_batch_hi, sample_batch_hi, manifest_json "
                "FROM reports WHERE public_id=?", (pid,)).fetchone()
            digest, _, _ = features.source_digest(
                conn, row["txn_batch_hi"], row["sample_batch_hi"])
            manifest = json.loads(row["manifest_json"])
            manifest.pop("digest_format", None)
            manifest["source_digest"] = digest
            conn.execute(
                "UPDATE reports SET manifest_json=? WHERE public_id=?",
                (json.dumps(manifest, ensure_ascii=False, sort_keys=True), pid))

    def redelimit_sample(self) -> None:
        """Re-split ('S901', 'A\\x1fB') into ('S901\\x1fA', 'B').

        The sd1 digest byte stream is identical, but the sample now joins
        account ``B`` instead of ``A\\x1fB``.
        """
        with self.svc.db.write_transaction() as conn:
            conn.execute(
                "UPDATE samples SET sample_id=?, account_id=? WHERE sample_id=?",
                (f"S901{US}A", "B", "S901"))

    def stored_upload(self, kind: str) -> Path:
        with self.svc.db.read() as conn:
            row = conn.execute(
                "SELECT stored_path FROM batches WHERE kind=? ORDER BY id LIMIT 1",
                (kind,)).fetchone()
        return Path(row["stored_path"])

    # ------------------------------------------------------------------ #
    # digest properties
    # ------------------------------------------------------------------ #
    def test_sd1_collides_but_sd2_distinguishes_boundaries(self):
        self.upload_collision_sources()
        with self.svc.db.read() as conn:
            d1_before, _, _ = features.source_digest(conn, 1, 2)
            d2_before, _, _ = features.source_digest_v2(conn, 1, 2)
        self.redelimit_sample()
        with self.svc.db.read() as conn:
            d1_after, _, _ = features.source_digest(conn, 1, 2)
            d2_after, _, _ = features.source_digest_v2(conn, 1, 2)
        # The vulnerability: re-delimiting is invisible to sd1 …
        self.assertEqual(d1_before, d1_after)
        # … and the fix: sd2 separates the two layouts.
        self.assertNotEqual(d2_before, d2_after)
        self.assertTrue(d2_before.startswith("sd2:"))

    def test_new_reports_use_sd2_format(self):
        self.upload_collision_sources()
        info = self.svc.create_report()
        manifest = info["manifest"]
        self.assertEqual(manifest["digest_format"], "sd2")
        self.assertTrue(manifest["source_digest"].startswith("sd2:"))
        report = self.svc.get_report(info["report_id"])
        self.assertEqual(report["digest_format"], "sd2")

    # ------------------------------------------------------------------ #
    # legacy (sd1) reports
    # ------------------------------------------------------------------ #
    def test_legacy_regenerate_ok_when_untampered_and_identical(self):
        self.upload_collision_sources()
        pid = self.build()
        self.downgrade_to_legacy(pid)
        before = self.output_rows(pid)

        new = self.svc.regenerate_report(pid)
        self.svc.claim_next_report()
        self.svc.run_report(new["report_id"])
        self.assertEqual(self.svc.get_report(new["report_id"])["status"], "ready")
        # 核实通过的旧报告按原冻结批次生成相同特征
        self.assertEqual(self.output_rows(new["report_id"]), before)
        # 特征归属正确账户：S901 看 A<US>B 的 100.00，S902 看 B 的 40.00
        rows = {r["sample_id"]: r for r in before}
        self.assertEqual(rows["S901"]["txn_amount_7d"], "100.00")
        self.assertEqual(rows["S902"]["txn_amount_7d"], "40.00")

    def test_legacy_regenerate_refused_after_redelimiting(self):
        self.upload_collision_sources()
        pid = self.build()
        self.downgrade_to_legacy(pid)
        self.redelimit_sample()
        # sd1 摘要不变，但登记指纹 + 原档比对必须识破
        with self.svc.db.read() as conn:
            manifest = self.svc.get_report(pid)["manifest"]
            digest_now, _, _ = features.source_digest(
                conn, manifest["txn_batch_hi"], manifest["sample_batch_hi"])
        self.assertEqual(digest_now, manifest["source_digest"])
        with self.assertRaises(ConflictError):
            self.svc.regenerate_report(pid)

    def test_legacy_background_build_refused_after_redelimiting(self):
        self.upload_collision_sources()
        pid = self.svc.create_report()["report_id"]
        self.downgrade_to_legacy(pid)
        self.redelimit_sample()
        self.svc.claim_next_report()
        self.svc.run_report(pid)
        report = self.svc.get_report(pid)
        self.assertEqual(report["status"], "failed")
        self.assertIn("核验", report["error"])

    def test_legacy_regenerate_refused_when_file_tampered(self):
        self.upload_collision_sources()
        pid = self.build()
        self.downgrade_to_legacy(pid)
        path = self.stored_upload("samples")
        path.write_bytes(path.read_bytes() + b"\n# tampered\n")
        with self.assertRaises(ConflictError):
            self.svc.regenerate_report(pid)

    def test_legacy_regenerate_refused_when_file_missing(self):
        self.upload_collision_sources()
        pid = self.build()
        self.downgrade_to_legacy(pid)
        self.stored_upload("samples").unlink()
        with self.assertRaises(ConflictError):
            self.svc.regenerate_report(pid)

    def test_legacy_ready_report_still_downloadable(self):
        """已发布且文件校验通过的旧报告仍可下载。"""
        self.upload_collision_sources()
        pid = self.build()
        self.downgrade_to_legacy(pid)
        found = self.svc.report_file(pid)
        self.assertIsNotNone(found)
        self.assertEqual(self.svc.get_report(pid)["status"], "ready")
        # 即使之后库内行被重新分界，已发布文件仍按自身校验提供下载
        self.redelimit_sample()
        found = self.svc.report_file(pid)
        self.assertIsNotNone(found)
        rows = {r["sample_id"]: r for r in csv.DictReader(
            io.StringIO(found[0].read_text(encoding="utf-8")))}
        self.assertEqual(rows["S901"]["txn_amount_7d"], "100.00")

    # ------------------------------------------------------------------ #
    # sd2 reports
    # ------------------------------------------------------------------ #
    def test_sd2_regenerate_refused_after_redelimiting(self):
        self.upload_collision_sources()
        pid = self.build()  # sd2 manifest
        self.redelimit_sample()
        with self.assertRaises(ConflictError):
            self.svc.regenerate_report(pid)

    def test_sd2_regenerate_ok_when_untampered(self):
        self.upload_collision_sources()
        pid = self.build()
        new = self.svc.regenerate_report(pid)
        self.svc.claim_next_report()
        self.svc.run_report(new["report_id"])
        self.assertEqual(self.svc.get_report(new["report_id"])["status"], "ready")
        self.assertEqual(self.output_rows(new["report_id"]), self.output_rows(pid))

    def test_sd2_regenerate_survives_missing_upload_file(self):
        """sd2 摘要本身无歧义，库内行即事实；原档缺失不妨碍重取。"""
        self.upload_collision_sources()
        pid = self.build()
        self.stored_upload("samples").unlink()
        new = self.svc.regenerate_report(pid)
        self.svc.claim_next_report()
        self.svc.run_report(new["report_id"])
        self.assertEqual(self.svc.get_report(new["report_id"])["status"], "ready")


if __name__ == "__main__":
    unittest.main()
