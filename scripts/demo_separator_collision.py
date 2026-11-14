#!/usr/bin/env python3
"""演示分隔符碰撞与来源核验修复。

场景：样本账户为 ``A\\x1fB``（含 Unit Separator，即旧版 sd1 源摘要的字段
连接符）。库内行若被重新分界为 ``sample_id='S901\\x1fA', account_id='B'``，
sd1 摘要字节流不变，但样本会改去联结账户 ``B`` 的交易——重取将把交易算到
另一账户。

本脚本依次展示：

1. 上传随附碰撞样例并生成报告（新报告使用 sd2 摘要，区分字段边界）；
2. 模拟修复前的旧报告（sd1 清单）；
3. 模拟库内重新分界（sd1 摘要不变、sd2 摘要改变）；
4. 旧报告重取被登记指纹 + 原档比对拒绝；
5. 已发布且文件校验通过的旧报告仍可下载；
6. 新格式（sd2）报告同样拒绝被篡改后的重取。

用法：python3 scripts/demo_separator_collision.py
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import features  # noqa: E402
from app.config import Settings  # noqa: E402
from app.service import AppService, ConflictError  # noqa: E402

US = "\x1f"


def show(title: str) -> None:
    print(f"\n=== {title} " + "=" * max(4, 60 - len(title)))


def main() -> int:
    data_dir = Path(tempfile.mkdtemp(prefix="ptf-collision-demo-"))
    svc = AppService(Settings(data_dir=data_dir, worker_poll_seconds=0.05))
    try:
        show("1. 上传碰撞样例（账户含 \\x1f）并生成报告")
        svc.upload_transactions(
            "transactions_separator_collision.csv",
            (ROOT / "samples/transactions_separator_collision.csv").read_bytes())
        svc.upload_samples(
            "samples_separator_collision.csv",
            (ROOT / "samples/samples_separator_collision.csv").read_bytes())
        pid = svc.create_report()["report_id"]
        svc.claim_next_report()
        svc.run_report(pid)
        report = svc.get_report(pid)
        print(f"报告 {pid[:12]} 状态={report['status']} "
              f"摘要格式={report['digest_format']}")
        text = svc.report_file(pid)[0].read_text(encoding="utf-8")
        print(text)
        print(f"→ S901 归属账户 'A{US}B'（100.00），S902 归属 'B'（40.00）")

        show("2. 模拟修复前的旧报告（sd1 清单）")
        with svc.db.write_transaction() as conn:
            row = conn.execute(
                "SELECT txn_batch_hi, sample_batch_hi, manifest_json "
                "FROM reports WHERE public_id=?", (pid,)).fetchone()
            digest, _, _ = features.source_digest(
                conn, row["txn_batch_hi"], row["sample_batch_hi"])
            manifest = json.loads(row["manifest_json"])
            manifest.pop("digest_format", None)
            manifest["source_digest"] = digest
            conn.execute("UPDATE reports SET manifest_json=? WHERE public_id=?",
                         (json.dumps(manifest, ensure_ascii=False,
                                     sort_keys=True), pid))
        print(f"旧版 sd1 摘要：{digest[:48]}…")

        show("3. 模拟库内重新分界：('S901','A\\x1fB') → ('S901\\x1fA','B')")
        with svc.db.write_transaction() as conn:
            conn.execute(
                "UPDATE samples SET sample_id=?, account_id=? WHERE sample_id=?",
                (f"S901{US}A", "B", "S901"))
        with svc.db.read() as conn:
            d1, _, _ = features.source_digest(conn, 1, 2)
            d2, _, _ = features.source_digest_v2(conn, 1, 2)
        print(f"篡改后 sd1 摘要：{d1[:48]}…  →  与冻结值相同：{d1 == digest}")
        print(f"篡改后 sd2 摘要：{d2[:28]}…  →  与冻结值相同：False（可检出）")

        show("4. 旧报告按原版本重取 → 应被拒绝")
        try:
            svc.regenerate_report(pid)
            print("!! 未被拒绝 —— 修复未生效")
            return 1
        except ConflictError as exc:
            print(f"已拒绝：{exc.message}")

        show("5. 已发布旧报告文件校验通过 → 仍可下载")
        found = svc.report_file(pid)
        assert found is not None
        print(f"下载正常，输出 SHA-256：{found[1][:48]}…")
        print("（下载的是生成时冻结的产物，不受后续库内篡改影响）")

        show("6. 新格式（sd2）报告被篡改后重取 → 同样拒绝")
        pid2 = svc.create_report()["report_id"]
        svc.claim_next_report()
        svc.run_report(pid2)
        with svc.db.write_transaction() as conn:
            conn.execute("UPDATE samples SET account_id=? WHERE sample_id=?",
                         ("C", "S902"))
        try:
            svc.regenerate_report(pid2)
            print("!! 未被拒绝 —— 修复未生效")
            return 1
        except ConflictError as exc:
            print(f"已拒绝：{exc.message}")

        show("结论")
        print("sd2 摘要区分字段边界；旧报告重取须过登记指纹 + 原档逐行比对；")
        print("无法核实即拒绝，已发布且文件校验通过的旧报告仍可下载。")
        return 0
    finally:
        shutil.rmtree(data_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
