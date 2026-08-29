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

"""nmap の XML 出力を services.jsonl に変換する。

nmap -sV はバナーを読んでサービスとバージョンを判定するため、
結果は観測事実として扱える（confirmed）。

使い方: nmap2jsonl.py <nmap.xml> <出力.jsonl>
"""
import json
import sys
from xml.etree import ElementTree


def main():
    src, dst = sys.argv[1], sys.argv[2]
    rows = []
    try:
        tree = ElementTree.parse(src)
    except (FileNotFoundError, ElementTree.ParseError):
        open(dst, "w").close()
        print("    サービス識別 0 件 (nmap の出力が読めません)")
        return

    for host in tree.getroot().findall("host"):
        # ホスト名を優先し、無ければ IP
        names = [h.get("name") for h in host.findall("hostnames/hostname")
                 if h.get("name")]
        addr_el = host.find("address[@addrtype='ipv4']")
        ip = addr_el.get("addr") if addr_el is not None else ""
        name = names[0] if names else ip

        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            if svc is None:
                continue
            product = (svc.get("product") or "").strip()
            version = (svc.get("version") or "").strip()
            rows.append({
                "host": name,
                "ip": ip,
                "port": int(port.get("portid")),
                "service": (svc.get("name") or "").lower(),
                "product": product,
                "version": (product + " " + version).strip(),
                "extrainfo": (svc.get("extrainfo") or "").strip(),
            })

    with open(dst, "w") as f:
        for r in sorted(rows, key=lambda x: (x["host"], x["port"])):
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"    サービス識別 {len(rows)} 件")


if __name__ == "__main__":
    main()
