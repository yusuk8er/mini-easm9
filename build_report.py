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

"""スキャン結果と前回からの差分を埋め込んだ単一HTMLを生成する。

index.html は同じ場所にある CSV を fetch して表示するが、
file:// で開いた場合はブラウザの制限により fetch が失敗する。
配布や手元での閲覧を想定し、データを埋め込んだ自己完結のHTMLを作る。

前回の結果（prev_assets.csv / prev_risks.csv）があれば差分を算出し、
各行に delta 列を付ける。

  new     : 今回はじめて現れた
  removed : 前回はあったが今回は無い
  same    : 変化なし
  base    : 前回の結果が無いため判定できない（初回実行）

  使い方: build_report.py <出力ディレクトリ>
  出力:   <出力ディレクトリ>/report.html
"""
import csv
import datetime
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def read_rows(path):
    """CSVを読み、ヘッダーと行のリストを返す。"""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return [], []
    if not text.strip():
        return [], []
    reader = csv.DictReader(io.StringIO(text))
    return list(reader.fieldnames or []), list(reader)


def key_of(row, kind):
    """行を一意に識別するキー。"""
    if kind == "assets":
        return (row.get("host", ""), str(row.get("port", "")))
    return (row.get("host", ""), row.get("risk_id", ""), row.get("detail", ""))


def diff_rows(cur, prev, kind, has_prev):
    """delta 列を付けた行のリストを返す。消滅した行も末尾に加える。"""
    prev_keys = {key_of(r, kind) for r in prev}
    cur_keys = {key_of(r, kind) for r in cur}

    out = []
    for r in cur:
        r = dict(r)
        if not has_prev:
            r["delta"] = "base"
        else:
            r["delta"] = "same" if key_of(r, kind) in prev_keys else "new"
        out.append(r)

    if has_prev:
        for r in prev:
            if key_of(r, kind) not in cur_keys:
                r = dict(r)
                r["delta"] = "removed"
                out.append(r)
    return out


def to_csv(fields, rows):
    if not fields:
        return ""
    fields = list(fields)
    if "delta" not in fields:
        fields.append("delta")
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue()


def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "snapshots")
    template = ROOT / "index.html"
    if not template.exists():
        print("    index.html が見つかりません", file=sys.stderr)
        return 1

    a_fields, a_cur = read_rows(out / "assets.csv")
    r_fields, r_cur = read_rows(out / "risks.csv")
    _, a_prev = read_rows(out / "prev_assets.csv")
    _, r_prev = read_rows(out / "prev_risks.csv")

    if not a_cur and not r_cur:
        print("    CSVが無いため report.html は生成しません")
        return 0

    has_prev = bool(a_prev or r_prev)
    a_rows = diff_rows(a_cur, a_prev, "assets", has_prev)
    r_rows = diff_rows(r_cur, r_prev, "risks", has_prev)

    def count(rows, d):
        return sum(1 for x in rows if x.get("delta") == d)

    summary = {
        "assets_new": count(a_rows, "new"),
        "assets_removed": count(a_rows, "removed"),
        "risks_new": count(r_rows, "new"),
        "risks_resolved": count(r_rows, "removed"),
        "has_prev": has_prev,
    }

    payload = {
        "assets": to_csv(a_fields, a_rows),
        "risks": to_csv(r_fields, r_rows),
        "summary": summary,
        "generated": datetime.datetime.now(
            datetime.timezone(datetime.timedelta(hours=9))
        ).strftime("%Y-%m-%d %H:%M JST"),
    }
    block = ("<script>window.__EMBEDDED__ = "
             + json.dumps(payload, ensure_ascii=False)
             + ";</script>\n")

    html = template.read_text(encoding="utf-8")
    idx = html.index("<script>")
    html = html[:idx] + block + html[idx:]

    dest = out / "report.html"
    dest.write_text(html, encoding="utf-8")

    size = dest.stat().st_size / 1024
    if has_prev:
        print(f"    report.html を生成 "
              f"(資産 {len(a_cur)} / 指摘 {len(r_cur)} / {size:.0f}KB)")
        print(f"    差分: 資産 +{summary['assets_new']} -{summary['assets_removed']} / "
              f"指摘 +{summary['risks_new']} -{summary['risks_resolved']}")
    else:
        print(f"    report.html を生成 "
              f"(資産 {len(a_cur)} / 指摘 {len(r_cur)} / {size:.0f}KB / 初回のため差分なし)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
