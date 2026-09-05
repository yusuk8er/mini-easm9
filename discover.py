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

"""証明書透明性ログから、まだ把握していないドメインを見つける。

2つの手がかりを使う。

  1. SANピボット
     既知ドメインの証明書に、別ドメインが同居していることがある。
     1枚の証明書で複数ブランドをまとめて運用している場合に有効。

  2. 組織名での横断検索
     証明書の Subject Organization (O=) で検索し、
     同じ組織名義で発行された証明書のドメインを集める。

**発見したドメインは自動でスキャン対象になりません。**
candidates.csv に列挙するだけで、seeds.txt への追加は人が判断する。
証明書の組織名は他社と重複することがあり、SANに取引先の
ドメインが含まれることもあるため、無条件の拡大は危険。

  使い方:
      python3 discover.py                    # seeds.txt と org-names.txt を読む
      python3 discover.py example.co.jp      # 対象を直接指定
"""
import csv
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
UA = "Yusuk8er-easm/1.0 (asset discovery; contact: security team)"
TIMEOUT = 60
RETRY = 3
SLEEP = 2.0   # crt.sh に負荷をかけないための待ち時間

# 「登録可能ドメイン」を切り出すための多段サフィックス。
# 完全な Public Suffix List ではないが、日本の実務で必要な範囲は網羅する。
MULTI_SUFFIX = {
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ed.jp", "gr.jp", "lg.jp",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.kr", "or.kr", "com.cn",
    "com.au", "net.au", "org.au", "com.br", "co.nz", "com.tw", "com.hk",
    "com.sg", "co.th", "co.in", "com.mx", "co.za",
}


def registrable(host):
    """ホスト名から登録可能ドメインを取り出す。"""
    h = (host or "").strip().lower().rstrip(".").lstrip("*.")
    if not h or "." not in h:
        return ""
    parts = h.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def fetch_json(url):
    for attempt in range(RETRY):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                body = r.read().decode("utf-8", errors="replace")
            if not body.strip():
                return []
            return json.loads(body)
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
            if attempt == RETRY - 1:
                print(f"      取得に失敗: {e}", file=sys.stderr)
                return []
            time.sleep(SLEEP * (attempt + 1))
    return []


def names_from_records(records):
    """crt.sh のレスポンスからホスト名を取り出す。"""
    out = set()
    for rec in records:
        for field in ("name_value", "common_name"):
            val = rec.get(field) or ""
            for line in str(val).split("\n"):
                line = line.strip().lower().rstrip(".")
                if line and re.fullmatch(r"[a-z0-9.*_-]+\.[a-z]{2,}", line):
                    out.add(line.lstrip("*."))
    return out


def san_pivot(domain):
    """既知ドメインの証明書に同居している別ドメインを探す。"""
    url = "https://crt.sh/?q=" + urllib.parse.quote("%." + domain) + "&output=json"
    records = fetch_json(url)
    found = {}
    for rec in records:
        hosts = names_from_records([rec])
        regs = {registrable(h) for h in hosts}
        regs.discard("")
        # 1枚の証明書に複数の登録ドメインが載っている場合のみ意味がある
        if len(regs) > 1 and domain in regs:
            for r in regs - {domain}:
                found.setdefault(r, set()).add(
                    (rec.get("issuer_name") or "")[:40] or "cert")
    return found, len(records)


def org_search(org):
    """証明書の組織名で横断検索する。"""
    url = "https://crt.sh/?O=" + urllib.parse.quote(org) + "&output=json"
    records = fetch_json(url)
    found = {}
    for h in names_from_records(records):
        r = registrable(h)
        if r:
            found.setdefault(r, set()).add(org)
    return found, len(records)


def load_lines(path):
    if not path.exists():
        return []
    return [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.strip().startswith("#")]


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if args:
        seeds = [registrable(a) for a in args]
        orgs = []
    else:
        seeds = sorted({registrable(d) for d in load_lines(ROOT / "seeds.txt")} - {""})
        orgs = load_lines(ROOT / "org-names.txt")

    if not seeds and not orgs:
        print("seeds.txt にドメインを、org-names.txt に組織名を記載してください",
              file=sys.stderr)
        sys.exit(1)

    known = set(seeds)
    known |= {registrable(h) for h in load_lines(ROOT / "hosts.txt")}
    known.discard("")

    candidates = {}   # domain -> {"sources": set, "evidence": set}

    def add(domain, source, evidence):
        if not domain or domain in known:
            return
        c = candidates.setdefault(domain, {"sources": set(), "evidence": set()})
        c["sources"].add(source)
        c["evidence"].update(evidence)

    print("=" * 60)
    print(" 関連ドメインの探索")
    print("=" * 60)

    if seeds:
        print(f"\n[1] 証明書のSANから探索 ({len(seeds)} ドメイン)")
        for d in seeds:
            print(f"    {d} ... ", end="", flush=True)
            found, n = san_pivot(d)
            for dom, ev in found.items():
                add(dom, "san-pivot", ev)
            print(f"証明書 {n} 件 / 新規 {len(found)} 件")
            time.sleep(SLEEP)

    if orgs:
        print(f"\n[2] 証明書の組織名から探索 ({len(orgs)} 件)")
        for o in orgs:
            print(f"    {o} ... ", end="", flush=True)
            found, n = org_search(o)
            for dom, ev in found.items():
                add(dom, "org-search", ev)
            print(f"証明書 {n} 件 / 新規 {len(found)} 件")
            time.sleep(SLEEP)

    out = ROOT / "candidates.csv"
    rows = []
    for dom in sorted(candidates):
        c = candidates[dom]
        rows.append({
            "domain": dom,
            "source": ";".join(sorted(c["sources"])),
            "evidence": ";".join(sorted(c["evidence"]))[:200],
            "decision": "",
        })
    with out.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=["domain", "source", "evidence", "decision"])
        w.writeheader()
        w.writerows(rows)

    print("\n" + "=" * 60)
    print(f" 候補 {len(rows)} 件 -> {out.name}")
    print("=" * 60)
    if rows:
        print("\n自社のドメインかどうかを1件ずつ確認してください。")
        print("自社のものと判断できたものだけを seeds.txt に追記します。\n")
        for r in rows[:30]:
            print(f"    {r['domain']:38} [{r['source']}]")
        if len(rows) > 30:
            print(f"    ... 他 {len(rows) - 30} 件")
        print("\n!! 確認せずに seeds.txt へ追加しないでください。")
        print("!! 他社のドメインをスキャンすると法的な問題になります。")
    else:
        print("\n新しい候補は見つかりませんでした。")


if __name__ == "__main__":
    main()
