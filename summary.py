#!/usr/bin/env python3
# Copyright 2026 Yusuke Hirose
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""スキャン結果を GitHub Actions のサマリー用 Markdown として出力する。

前回の結果（prev_assets.csv / prev_risks.csv）があれば差分を算出し、
新規に現れたものを先頭に出す。

  使い方: summary.py <スナップショットのディレクトリ>
"""
import csv
import io
import sys
from pathlib import Path

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEV_LABEL = {"critical": "致命的", "high": "高", "medium": "中", "low": "低"}
MAX_ROWS = 30


def read_rows(path):
    try:
        text = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return []
    if not text.strip():
        return []
    return list(csv.DictReader(io.StringIO(text)))


def key_of(row, kind):
    if kind == "assets":
        return (row.get("host", ""), str(row.get("port", "")))
    return (row.get("host", ""), row.get("risk_id", ""), row.get("detail", ""))


def esc(text):
    """表のセルを壊さないようにする。"""
    if text is None:
        text = ""
    return str(text).replace("|", "\\|").replace("\n", " ")


def table(headers, rows):
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join(["---"] * len(headers)) + "|"]
    for r in rows:
        out.append("| " + " | ".join(esc(c) for c in r) + " |")
    return out


def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "snapshots")
    assets = read_rows(out / "assets.csv")
    risks = read_rows(out / "risks.csv")
    prev_a = read_rows(out / "prev_assets.csv")
    prev_r = read_rows(out / "prev_risks.csv")
    has_prev = bool(prev_a or prev_r)

    prev_a_keys = {key_of(r, "assets") for r in prev_a}
    prev_r_keys = {key_of(r, "risks") for r in prev_r}
    cur_a_keys = {key_of(r, "assets") for r in assets}
    cur_r_keys = {key_of(r, "risks") for r in risks}

    new_assets = [r for r in assets if key_of(r, "assets") not in prev_a_keys] if has_prev else []
    gone_assets = [r for r in prev_a if key_of(r, "assets") not in cur_a_keys] if has_prev else []
    new_risks = [r for r in risks if key_of(r, "risks") not in prev_r_keys] if has_prev else []
    gone_risks = [r for r in prev_r if key_of(r, "risks") not in cur_r_keys] if has_prev else []

    shadow = [r for r in assets if r.get("state") == "shadow"]
    confirmed = [r for r in risks if r.get("confidence") == "confirmed"]
    single = [r for r in risks if r.get("confidence") == "single"]

    L = []
    L.append("## スキャン結果")
    L.append("")

    # ---- 概況 ----
    L += table(
        ["項目", "件数", "前回比"],
        [
            ["資産", len(assets),
             f"+{len(new_assets)} / -{len(gone_assets)}" if has_prev else "初回"],
            ["持ち主不明", len(shadow), ""],
            ["指摘（確認済み）", len(confirmed),
             f"+{len(new_risks)} / -{len(gone_risks)}" if has_prev else "初回"],
            ["指摘（要確認）", len(single), ""],
        ])
    L.append("")

    # ---- 新規の指摘 ----
    if new_risks:
        L.append(f"### 新規の指摘 {len(new_risks)} 件")
        L.append("")
        rows = sorted(new_risks,
                      key=lambda r: (SEV_ORDER.get(r.get("severity"), 9),
                                     r.get("host", "")))[:MAX_ROWS]
        L += table(["深刻度", "確度", "対象", "内容", "検出元"],
                   [[SEV_LABEL.get(r.get("severity"), r.get("severity", "")),
                     "確認済み" if r.get("confidence") == "confirmed" else "要確認",
                     r.get("host", ""), r.get("detail", ""), r.get("source", "")]
                    for r in rows])
        if len(new_risks) > MAX_ROWS:
            L.append("")
            L.append(f"他 {len(new_risks) - MAX_ROWS} 件。詳細は report.html を参照してください。")
        L.append("")
    elif has_prev:
        L.append("### 新規の指摘はありません")
        L.append("")

    # ---- 解消した指摘 ----
    if gone_risks:
        L.append(f"### 解消した指摘 {len(gone_risks)} 件")
        L.append("")
        L += table(["対象", "内容"],
                   [[r.get("host", ""), r.get("detail", "")]
                    for r in gone_risks[:MAX_ROWS]])
        L.append("")

    # ---- 新規の資産 ----
    if new_assets:
        L.append(f"### 新しく見つかった資産 {len(new_assets)} 件")
        L.append("")
        L += table(["ホスト", "持ち主", "ポート", "技術"],
                   [[r.get("host", ""), r.get("owner") or "**不明**",
                     r.get("port", ""), (r.get("tech") or "").replace(";", ", ")]
                    for r in new_assets[:MAX_ROWS]])
        if len(new_assets) > MAX_ROWS:
            L.append("")
            L.append(f"他 {len(new_assets) - MAX_ROWS} 件。")
        L.append("")

    if gone_assets:
        L.append(f"### 消滅した資産 {len(gone_assets)} 件")
        L.append("")
        L += table(["ホスト", "持ち主"],
                   [[r.get("host", ""), r.get("owner") or "不明"]
                    for r in gone_assets[:MAX_ROWS]])
        L.append("")

    # ---- 初回は全件の要約を出す ----
    if not has_prev and risks:
        L.append(f"### 検出された指摘 {len(risks)} 件")
        L.append("")
        rows = sorted(risks, key=lambda r: (SEV_ORDER.get(r.get("severity"), 9),
                                            r.get("host", "")))[:MAX_ROWS]
        L += table(["深刻度", "確度", "対象", "内容", "検出元"],
                   [[SEV_LABEL.get(r.get("severity"), r.get("severity", "")),
                     "確認済み" if r.get("confidence") == "confirmed" else "要確認",
                     r.get("host", ""), r.get("detail", ""), r.get("source", "")]
                    for r in rows])
        if len(risks) > MAX_ROWS:
            L.append("")
            L.append(f"他 {len(risks) - MAX_ROWS} 件。")
        L.append("")

    # ---- 持ち主不明 ----
    if shadow:
        L.append("<details>")
        L.append(f"<summary>持ち主不明の資産 {len(shadow)} 件</summary>")
        L.append("")
        L += table(["ホスト", "推定クラウド", "技術"],
                   [[r.get("host", ""), r.get("cloud_provider") or "-",
                     (r.get("tech") or "").replace(";", ", ")]
                    for r in shadow[:MAX_ROWS]])
        if len(shadow) > MAX_ROWS:
            L.append("")
            L.append(f"他 {len(shadow) - MAX_ROWS} 件。")
        L.append("")
        L.append("持ち主が判明したら `owners.yaml` に追記してください。")
        L.append("</details>")
        L.append("")

    L.append("---")
    L.append("")
    L.append("詳細は Artifacts の `easm-result` をダウンロードし、"
             "`snapshots/report.html` をブラウザで開いてください。")

    try:
        print("\n".join(L))
    except BrokenPipeError:
        pass


if __name__ == "__main__":
    main()
