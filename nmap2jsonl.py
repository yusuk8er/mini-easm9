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
import re
import sys
from xml.etree import ElementTree


# 弱いとみなす暗号スイート・プロトコルの判定材料
WEAK_CIPHER_HINTS = (
    ("_RC4_", "RC4", "high"),
    ("_DES_", "DES", "high"),
    ("_3DES_", "3DES", "medium"),
    ("_NULL_", "NULL暗号", "critical"),
    ("_EXPORT", "EXPORT暗号", "critical"),
    ("_anon_", "匿名鍵交換", "critical"),
    ("_MD5", "MD5", "medium"),
)
OLD_TLS = {"SSLv2": "critical", "SSLv3": "high", "TLSv1.0": "medium", "TLSv1.1": "medium"}


def script_text(elem):
    """<script> 要素の出力テキストを取り出す。"""
    return (elem.get("output") or "")


def parse_nse(host, port_id, scripts):
    """NSE の出力から設定上の不備を取り出す。

    いずれも応答をそのまま読んでいるだけなので、誤検知は発生しない。
    """
    out = []
    for sc in scripts:
        sid = sc.get("id") or ""
        text = script_text(sc)

        if sid == "ssl-enum-ciphers":
            # 古いプロトコルの有効化
            for proto, sev in OLD_TLS.items():
                if proto + ":" in text:
                    out.append({
                        "risk_id": "tls-old-protocol", "severity": sev,
                        "detail": f"{proto} が有効 ({port_id}/tcp)",
                    })
            # 弱い暗号スイート
            found = []
            for needle, label, sev in WEAK_CIPHER_HINTS:
                if needle in text:
                    found.append((label, sev))
            if found:
                worst = min(found, key=lambda x: ["critical", "high", "medium"].index(x[1]))
                out.append({
                    "risk_id": "tls-weak-cipher", "severity": worst[1],
                    "detail": "弱い暗号スイートが有効 ("
                              + ", ".join(sorted({f[0] for f in found}))
                              + f") ({port_id}/tcp)",
                })
            # nmap 自身の総合評価が F の場合
            if "least strength: F" in text:
                out.append({
                    "risk_id": "tls-weak-config", "severity": "high",
                    "detail": f"TLS設定の総合評価が最低水準 ({port_id}/tcp)",
                })

        elif sid == "smb2-security-mode":
            low = text.lower()
            if "not required" in low or "signing enabled but not required" in low:
                out.append({
                    "risk_id": "smb-signing-not-required", "severity": "medium",
                    "detail": f"SMB署名が必須になっていない ({port_id}/tcp)",
                })

        elif sid == "ftp-anon":
            if "Anonymous FTP login allowed" in text:
                out.append({
                    "risk_id": "ftp-anonymous-login", "severity": "high",
                    "detail": f"匿名FTPログインが可能 ({port_id}/tcp)",
                })

        elif sid == "ssh2-enum-algos":
            low = text.lower()
            weak = []
            for needle, label in (("diffie-hellman-group1-sha1", "DH group1"),
                                  ("ssh-rsa", "ssh-rsa(SHA-1)"),
                                  ("hmac-md5", "HMAC-MD5"),
                                  ("arcfour", "Arcfour"),
                                  ("3des-cbc", "3DES-CBC")):
                if needle in low:
                    weak.append(label)
            if weak:
                out.append({
                    "risk_id": "ssh-weak-algorithm", "severity": "medium",
                    "detail": "SSHで弱いアルゴリズムが有効 ("
                              + ", ".join(weak) + f") ({port_id}/tcp)",
                })

        elif sid == "rdp-ntlm-info":
            # 構成情報の露出。ドメイン名やホスト名が外部から取得できる状態
            if "DNS_Domain_Name" in text or "NetBIOS_Domain_Name" in text:
                out.append({
                    "risk_id": "rdp-info-disclosure", "severity": "medium",
                    "detail": f"RDPがドメイン名・ホスト名を外部に開示 ({port_id}/tcp)",
                })
    return out


def main():
    src, dst = sys.argv[1], sys.argv[2]
    rows = []
    nse_rows = []
    hosts = []
    try:
        raw = open(src, encoding="utf-8", errors="replace").read()
    except FileNotFoundError:
        open(dst, "w").close()
        open(str(dst).replace("services.jsonl", "nse_findings.jsonl"), "w").close()
        print("    サービス識別 0 件 (nmap の出力がありません)")
        return

    # 分割実行した複数のXMLを連結したファイルにも対応する。
    # 途中で打ち切られた断片は読み飛ばし、読めた分だけを採用する
    chunks = re.split(r"(?=<\?xml )", raw)
    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            hosts.extend(ElementTree.fromstring(chunk).findall("host"))
        except ElementTree.ParseError:
            # 末尾が切れている場合、最後の </host> までを拾い直す
            end = chunk.rfind("</host>")
            if end == -1:
                continue
            patched = chunk[:end + 7] + "</nmaprun>"
            start = patched.find("<nmaprun")
            if start == -1:
                continue
            try:
                hosts.extend(ElementTree.fromstring(patched[start:]).findall("host"))
            except ElementTree.ParseError:
                continue

    for host in hosts:
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
            port_id = int(port.get("portid"))
            rows.append({
                "host": name,
                "ip": ip,
                "port": port_id,
                "service": (svc.get("name") or "").lower(),
                "product": product,
                "version": (product + " " + version).strip(),
                "extrainfo": (svc.get("extrainfo") or "").strip(),
            })
            for f in parse_nse(name, port_id, port.findall("script")):
                f.update({"host": name, "ip": ip, "port": port_id})
                nse_rows.append(f)

    with open(dst, "w") as f:
        for r in sorted(rows, key=lambda x: (x["host"], x["port"])):
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # 設定上の不備は別ファイルに出す
    nse_dst = str(dst).replace("services.jsonl", "nse_findings.jsonl")
    seen = set()
    with open(nse_dst, "w") as f:
        for r in sorted(nse_rows, key=lambda x: (x["host"], x["port"], x["risk_id"])):
            k = (r["host"], r["port"], r["risk_id"], r["detail"])
            if k in seen:
                continue
            seen.add(k)
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"    サービス識別 {len(rows)} 件 / 設定の不備 {len(seen)} 件")


if __name__ == "__main__":
    main()
