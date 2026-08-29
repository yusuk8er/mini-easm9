#!/usr/bin/env python3
"""独自コードの各ファイル先頭にライセンスヘッダーを挿入する。

すでにヘッダーがあるファイルは触らない。何度実行しても安全。

使い方:
    python3 add-license-header.py            # 挿入する
    python3 add-license-header.py --check    # 挿入せず、不足しているファイルを表示
"""
import re
import sys
from pathlib import Path

HOLDER = "Yusuke Hirose"
YEAR = "2026"
SPDX = "Apache-2.0"

NOTICE = [
    f"Copyright {YEAR} {HOLDER}",
    "",
    f"SPDX-License-Identifier: {SPDX}",
    "",
    'Licensed under the Apache License, Version 2.0 (the "License");',
    "you may not use this file except in compliance with the License.",
    "You may obtain a copy of the License at",
    "",
    "    http://www.apache.org/licenses/LICENSE-2.0",
    "",
    "Unless required by applicable law or agreed to in writing, software",
    'distributed under the License is distributed on an "AS IS" BASIS,',
    "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.",
    "See the License for the specific language governing permissions and",
    "limitations under the License.",
]

# 拡張子ごとのコメント記法
STYLES = {
    ".py": ("#", None),
    ".sh": ("#", None),
    ".yaml": ("#", None),
    ".yml": ("#", None),
    ".sql": ("--", None),
    ".html": (None, ("<!--", "-->")),
}

# 対象外（OSS由来・生成物・ドキュメント）
SKIP_NAMES = {"WORKFLOW-scan.yml.txt", "LICENSE", "NOTICE"}
SKIP_DIRS = {".git", "snapshots", "node_modules"}


def build_header(style):
    line_prefix, block = style
    if block:
        start, end = block
        body = "\n".join("  " + n if n else "" for n in NOTICE)
        return f"{start}\n{body}\n{end}\n"
    return "\n".join(f"{line_prefix} {n}".rstrip() for n in NOTICE) + "\n"


def has_header(text):
    head = text[:1500]
    return "SPDX-License-Identifier" in head or "Apache License" in head


def insert(path, style):
    text = path.read_text(encoding="utf-8")
    if has_header(text):
        return False

    header = build_header(style)
    lines = text.split("\n")
    at = 0

    # shebang と エンコーディング宣言、<!DOCTYPE> の後ろに入れる
    if lines and lines[0].startswith("#!"):
        at = 1
        if len(lines) > 1 and re.match(r"^#.*coding[:=]", lines[1]):
            at = 2
    elif lines and lines[0].lstrip().lower().startswith("<!doctype"):
        at = 1

    new = "\n".join(lines[:at]) + ("\n" if at else "") + header
    if at == 0 or lines[at:at + 1] != [""]:
        new += "\n"
    new += "\n".join(lines[at:])
    path.write_text(new, encoding="utf-8")
    return True


def main():
    check = "--check" in sys.argv
    root = Path(__file__).resolve().parent
    missing, done = [], []

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name in SKIP_NAMES or path.name == Path(__file__).name:
            continue
        style = STYLES.get(path.suffix)
        if not style:
            continue
        rel = path.relative_to(root)
        if has_header(path.read_text(encoding="utf-8")):
            continue
        if check:
            missing.append(str(rel))
        elif insert(path, style):
            done.append(str(rel))

    if check:
        if missing:
            print(f"ライセンスヘッダーがないファイル: {len(missing)} 件")
            for m in missing:
                print(f"  {m}")
            sys.exit(1)
        print("すべてのファイルにライセンスヘッダーがあります")
    else:
        if done:
            print(f"ヘッダーを挿入しました: {len(done)} 件")
            for d in done:
                print(f"  {d}")
        else:
            print("挿入対象はありませんでした（すべて付与済み）")


if __name__ == "__main__":
    main()
