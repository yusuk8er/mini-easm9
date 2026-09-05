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

"""外部偵察の結果とクラウド資産を突合して assets.csv を作る。

設計方針:
  - 依存は標準ライブラリのみ。DBを持たない。
  - 出力は必ずソート済み。差分は git diff に任せる。
  - 突合は「IP完全一致」と「CNAMEの部分一致」だけ。
    IPレンジ判定やARN逆引きのような凝った処理はやらない。
"""
import csv
import json
import sys
from pathlib import Path

FIELDS = [
    "host", "owner", "state", "ip", "cname", "cloud_provider",
    "port", "status", "title", "tech", "cpe", "findings",
]

CLOUD_HINTS = (
    ("amazonaws.com", "aws"), ("cloudfront.net", "aws"), ("awsglobalaccelerator.com", "aws"),
    ("azurewebsites.net", "azure"), ("blob.core.windows.net", "azure"),
    ("cloudapp.azure.com", "azure"), ("azurefd.net", "azure"), ("trafficmanager.net", "azure"),
    ("googleusercontent.com", "gcp"), ("run.app", "gcp"), ("appspot.com", "gcp"),
    ("storage.googleapis.com", "gcp"),
    ("herokuapp.com", "saas"), ("netlify.app", "saas"), ("vercel.app", "saas"),
    ("github.io", "saas"), ("firebaseapp.com", "saas"), ("pages.dev", "saas"),
    ("squarespace.com", "saas"), ("wixsite.com", "saas"), ("shopify.com", "saas"),
    ("hubspot.net", "saas"), ("sendgrid.net", "saas"), ("zendesk.com", "saas"),
)


def as_text(value):
    """外部ツールの出力は型が揺れることがあるため、安全に文字列へ寄せる。"""
    return value if isinstance(value, str) else ""


def as_list(value):
    """文字列のリストとして扱えるものだけを取り出す。"""
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [x for x in value if isinstance(x, str)]
    return []


def load_owners(path):
    """owners.yaml を読む。PyYAML なしで済むよう単純なコロン区切りで扱う。"""
    owners = []
    if not path.exists():
        return owners
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip().lower().rstrip("."), val.strip()
        if key and val:
            owners.append((key, val))
    # 長いキー（より具体的な指定）を優先する
    owners.sort(key=lambda kv: -len(kv[0]))
    return owners


def find_owner(host, owners):
    h = (host or "").lower().rstrip(".")
    for key, val in owners:
        if h == key or h.endswith("." + key):
            return val
    return ""


def classify(row, owner):
    """2分類。

    shadow : 持ち主台帳に載っていない。調べるべき対象
    known  : 持ち主が判明している

    クラウド連携を行わない構成のため、「自社アカウントに存在するか」による
    クラウドの認証情報を扱わないため、「自社アカウントに存在するか」による
    判定は行わない。CNAME から推定した事業者は cloud_provider 列に
    参考情報として残す。
    """
    return "known" if owner else "shadow"


# 主要な製品名 -> CPE のベンダー/製品 部分
TECH_TO_CPE = {
    "nginx": ("nginx", "nginx"),
    "apache http server": ("apache", "http_server"),
    "apache": ("apache", "http_server"),
    "apache tomcat": ("apache", "tomcat"),
    "iis": ("microsoft", "internet_information_services"),
    "microsoft-iis": ("microsoft", "internet_information_services"),
    "php": ("php", "php"),
    "openssl": ("openssl", "openssl"),
    "openssh": ("openbsd", "openssh"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "jira": ("atlassian", "jira"),
    "confluence": ("atlassian", "confluence"),
    "jenkins": ("jenkins", "jenkins"),
    "gitlab": ("gitlab", "gitlab"),
    "grafana": ("grafana", "grafana"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "kibana": ("elastic", "kibana"),
    "tomcat": ("apache", "tomcat"),
    "node.js": ("nodejs", "node.js"),
    "express": ("openjsf", "express"),
    "microsoft asp.net": ("microsoft", "asp.net"),
    "asp.net": ("microsoft", "asp.net"),
    "fortios": ("fortinet", "fortios"),
    "pulse secure": ("pulsesecure", "pulse_connect_secure"),
    "citrix": ("citrix", "netscaler_application_delivery_controller"),
    "exchange": ("microsoft", "exchange_server"),
    "postfix": ("postfix", "postfix"),
    "mysql": ("oracle", "mysql"),
    "postgresql": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
}


def cpe_from_tech(tech_list):
    """httpx の tech 表記から CPE 2.3 文字列を組み立てる。

    httpx の -cpe は対応製品が限られており空になることが多い。
    tech には 'Nginx:1.10.3' のように製品名とバージョンが出るので、
    そこから CPE を組み立てて補う。
    バージョンが取れないときは '*' のままにする。
    """
    out = []
    for t in tech_list or []:
        if not isinstance(t, str):
            continue
        name, _, ver = t.partition(":")
        key = name.strip().lower()
        vendor_product = TECH_TO_CPE.get(key)
        if not vendor_product:
            # 'Apache HTTP Server' のような表記ゆれを部分一致で拾う
            for k, v in TECH_TO_CPE.items():
                if k in key or key in k:
                    vendor_product = v
                    break
        if not vendor_product:
            continue
        vendor, product = vendor_product
        version = ver.strip() or "*"
        out.append(f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*")
    return out


def extract_cpe(rec):
    """httpx の cpe 出力を集める。

    httpx が返す CPE はバージョンが '*' のまま（既知の制約）。
    tech フィールドに 'Apache HTTP Server:2.4.7' 形式でバージョンが出ることが
    あるので、製品名が一致したら CPE の version 部分に流し込む。
    あくまで参考値であり、これで CVE を確定してはいけない。
    """
    raw = rec.get("cpe") or rec.get("cpes") or []
    if isinstance(raw, str):
        raw = [raw]
    elif isinstance(raw, dict):
        # httpx のバージョンによっては {"cpe": [...]} のような辞書で返る
        raw = raw.get("cpe") or raw.get("cpes") or list(raw.values())

    # 要素が文字列でないものは取り除く（辞書やnullが混ざることがある）
    flat = []
    for item in raw if isinstance(raw, (list, tuple)) else []:
        if isinstance(item, str):
            flat.append(item)
        elif isinstance(item, (list, tuple)):
            flat.extend(x for x in item if isinstance(x, str))
        elif isinstance(item, dict):
            flat.extend(str(v) for v in item.values() if isinstance(v, str))
    raw = [c for c in flat if c.startswith("cpe:")]

    if not raw:
        # httpx が CPE を返さない場合は tech から組み立てる
        return sorted(set(cpe_from_tech(rec.get("tech", []))))

    # tech から 製品名 -> バージョン の対応を作る
    versions = {}
    for t in rec.get("tech", []) or []:
        if isinstance(t, str) and ":" in t:
            name, _, ver = t.partition(":")
            versions[name.lower().replace(" ", "_")] = ver.strip()

    out = []
    for cpe in raw:
        parts = cpe.split(":")
        if len(parts) >= 6 and parts[5] == "*":
            product = parts[4].lower()
            for name, ver in versions.items():
                if product in name or name in product:
                    parts[5] = ver
                    cpe = ":".join(parts)
                    break
        out.append(cpe)
    return out


def read_jsonl(path):
    if not path.exists():
        return
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if line:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def guess_cloud(cnames):
    """CNAME の文字列からクラウド事業者を推定する。

    クラウドの認証情報は使用せず、DNSの応答だけで判定する。
    自社アカウントに存在するかまでは分からないため、あくまで参考情報。
    """
    for c in as_list(cnames):
        cl = c.lower()
        for needle, prov in CLOUD_HINTS:
            if needle in cl:
                return prov
    return ""


RISK_FIELDS = [
    "host", "owner", "severity", "confidence", "risk_id", "detail", "source",
]

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# 到達性リスク: 外部に出ているべきでないポート
DANGEROUS_PORTS = {
    22: ("ssh-exposed", "high", "SSH exposed to internet"),
    23: ("telnet-exposed", "critical", "Telnet exposed to internet"),
    445: ("smb-exposed", "critical", "SMB exposed to internet"),
    1433: ("mssql-exposed", "critical", "SQL Server exposed to internet"),
    3306: ("mysql-exposed", "critical", "MySQL exposed to internet"),
    3389: ("rdp-exposed", "critical", "RDP exposed to internet"),
    5432: ("postgres-exposed", "critical", "PostgreSQL exposed to internet"),
    5900: ("vnc-exposed", "critical", "VNC exposed to internet"),
    6379: ("redis-exposed", "critical", "Redis exposed to internet"),
    9200: ("elastic-exposed", "critical", "Elasticsearch exposed to internet"),
    11211: ("memcached-exposed", "critical", "Memcached exposed to internet"),
    27017: ("mongodb-exposed", "critical", "MongoDB exposed to internet"),
    21: ("ftp-exposed", "medium", "FTP exposed to internet"),
}


PRIVATE_PREFIXES = ("127.", "10.", "192.168.", "169.254.", "0.", "::1", "fe80:", "fc", "fd")


def is_private(ip):
    ip = as_text(ip).strip()
    if not ip:
        return False
    if ip.startswith(PRIVATE_PREFIXES):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (IndexError, ValueError):
            return False
    return False


def build_risks(out, owners, waf_hosts):
    """確度の高い順にリスクを組み立てる。

    confirmed : 観測できた事実（ポート開放、証明書の内容、クラウド設定）
                または nuclei が2回とも検出したもの
    single    : nuclei が1回だけ検出したもの。人による確認が必要
    """
    risks = []

    def add(host, sev, conf, rid, detail, source):
        risks.append({
            "host": host, "owner": find_owner(host, owners),
            "severity": sev, "confidence": conf,
            "risk_id": rid, "detail": detail, "source": source,
        })

    # 0. サービス識別の結果を先に読み込む。
    #    ポート由来の指摘に「実際に何が動いているか」を添えるために使う
    svc_map = {}
    for r in read_jsonl(out / "services.jsonl"):
        host = (as_text(r.get("host")) or as_text(r.get("ip"))).lower()
        port = r.get("port")
        if not host or port is None:
            continue
        # extrainfo は "Ubuntu Linux; protocol 2.0" のように冗長なことが多いため、
        # 一覧の可読性を優先して version / product だけを使う
        label = (as_text(r.get("version")) or as_text(r.get("product"))).strip()
        if label:
            svc_map[(host, port)] = label
            # IP でも引けるようにしておく
            ip = as_text(r.get("ip")).strip()
            if ip:
                svc_map[(ip, port)] = label

    def with_version(host, port, detail):
        """検出内容にサービスのバージョンを付け足す"""
        label = svc_map.get((host, port))
        return f"{detail} - {label}" if label else detail

    # 1. 開放ポート（TCP接続が成立した事実）
    for r in read_jsonl(out / "ports.jsonl"):
        port = r.get("port")
        host = (as_text(r.get("host")) or as_text(r.get("ip"))).lower()
        # スキャン元マシン自身や社内NWを誤って報告しない
        if is_private(r.get("ip")) or is_private(host):
            continue
        if port in DANGEROUS_PORTS and host:
            rid, sev, label = DANGEROUS_PORTS[port]
            add(host, sev, "confirmed", rid,
                with_version(host, port, f"{label} ({port}/tcp)"), "naabu")

    # 2. 証明書（中身を読んだ結果）
    for r in read_jsonl(out / "tls.jsonl"):
        host = as_text(r.get("host")).lower()
        if not host:
            continue
        if r.get("expired"):
            add(host, "high", "confirmed", "tls-expired",
                f"TLS certificate expired (not_after: {r.get('not_after', 'unknown')})", "tlsx")
        if r.get("self_signed"):
            add(host, "medium", "confirmed", "tls-self-signed",
                "Self-signed TLS certificate", "tlsx")
        if r.get("mismatched"):
            add(host, "medium", "confirmed", "tls-mismatch",
                "TLS certificate hostname mismatch", "tlsx")
        for v in (r.get("tls_version") or []) if isinstance(r.get("tls_version"), list) else [r.get("tls_version")]:
            if v and str(v).lower() in ("tls10", "tls11", "ssl30"):
                add(host, "medium", "confirmed", "tls-old-version",
                    f"Obsolete TLS version enabled ({v})", "tlsx")

    # 3. 乗っ取り可能な DNS レコード（CNAME先が存在しない）
    for r in read_jsonl(out / "dns.jsonl"):
        host = as_text(r.get("host")).lower()
        cnames = as_list(r.get("cname"))
        if cnames and not as_list(r.get("a")):
            add(host, "high", "confirmed", "dangling-cname",
                f"Dangling CNAME (possible takeover): {cnames[0]}", "dnsx")

    # 5. サービス識別（バナー観測なので事実ベース）
    #    ポート番号だけでは分からない「実際に何が動いているか」を補う
    svc_by_host = {}
    for r in read_jsonl(out / "services.jsonl"):
        host = (as_text(r.get("host")) or as_text(r.get("ip"))).lower()
        svc = (as_text(r.get("service")) or as_text(r.get("protocol"))).lower()
        # nmap は http-proxy / ms-wbt-server 等の別名を返すため寄せる
        svc = {"ms-wbt-server": "rdp", "microsoft-ds": "smb",
               "ms-sql-s": "mssql", "postgres": "postgresql"}.get(svc, svc)
        port = r.get("port")
        ver = as_text(r.get("version"))
        if not host or not svc:
            continue
        svc_by_host.setdefault(host, []).append(f"{svc}:{port}")
        label = f"{svc.upper()}{' ' + ver if ver else ''} on {port}/tcp"
        # ポート番号で既に指摘済みのものは重複させない
        if port in DANGEROUS_PORTS:
            continue
        if svc in ("telnet", "vnc", "rdp", "smb", "ftp"):
            sev = "critical" if svc in ("telnet", "vnc", "smb") else "high"
            add(host, sev, "confirmed", f"{svc}-service-exposed",
                f"{label} (remote access service reachable from internet)", "nmap")
        elif svc in ("mysql", "postgresql", "redis", "mongodb", "mssql", "elasticsearch"):
            add(host, "critical", "confirmed", f"{svc}-service-exposed",
                f"{label} (database reachable from internet)", "nmap")
        elif svc in ("smtp", "pop3", "imap") and ver:
            add(host, "medium", "confirmed", f"{svc}-banner",
                f"{label} (mail service banner discloses version)", "nmap")

    # 5.5 設定上の不備（nmap の NSE スクリプト）
    #     応答をそのまま読んでいるだけなので誤検知は発生しない
    for r in read_jsonl(out / "nse_findings.jsonl"):
        host = (as_text(r.get("host")) or as_text(r.get("ip"))).lower()
        if not host or is_private(r.get("ip")):
            continue
        add(host, as_text(r.get("severity")) or "medium", "confirmed",
            as_text(r.get("risk_id")), as_text(r.get("detail")), "nmap-nse")

    # 6. DNS サーバの検査（dig の応答そのもの）
    for r in read_jsonl(out / "dns_risks.jsonl"):
        add((r.get("host") or "").lower(), r.get("severity", "medium"), "confirmed",
            r.get("risk_id", ""), r.get("detail", ""), "dig")

    # 7. ネットワーク層の指摘（nuclei の network/dns/ssl テンプレート）
    for r in read_jsonl(out / "netfindings.jsonl"):
        host = as_text(r.get("host")).lower().split(":")[0]
        info = r.get("info") or {}
        add(host, info.get("severity", "medium"), r.get("confidence", "single"),
            r.get("template-id", ""), info.get("name", ""), "nuclei-net")

    # 8. Web の指摘（nuclei）
    for r in read_jsonl(out / "findings.jsonl"):
        host = as_text(r.get("host")).lower().split(":")[0]
        info = r.get("info") or {}
        conf = r.get("confidence", "single")
        # WAF の背後にあるホストは応答が歪むため確度を下げる
        if host in waf_hosts and conf == "confirmed":
            conf = "single"
        add(host, info.get("severity", "medium"), conf,
            r.get("template-id", ""), info.get("name", ""), "nuclei")

    # 同一の指摘を1件にまとめる（naabu が host と ip の両方で返すことがある）
    seen_r, uniq = set(), []
    for r in risks:
        k = (r["host"], r["risk_id"], r["detail"])
        if k not in seen_r:
            seen_r.add(k)
            uniq.append(r)
    risks = uniq

    risks.sort(key=lambda r: (SEV_ORDER.get(r["severity"], 9),
                              0 if r["confidence"] == "confirmed" else 1,
                              r["host"], r["risk_id"]))
    return risks


def main(outdir):
    out = Path(outdir)
    owners = load_owners(Path(__file__).resolve().parent / "owners.yaml")

    dns_map = {}
    for rec in read_jsonl(out / "dns.jsonl"):
        host = rec.get("host", "").lower()
        if host:
            dns_map[host] = (as_list(rec.get("a")), as_list(rec.get("cname")))

    findings = {}
    for f in read_jsonl(out / "findings.jsonl"):
        host = (f.get("host") or "").lower()
        sev = (f.get("info") or {}).get("severity", "")
        name = f.get("template-id", "")
        findings.setdefault(host, []).append(f"{sev}:{name}")

    rows = []
    seen = set()
    for h in read_jsonl(out / "http.jsonl"):
        host = (as_text(h.get("host")) or as_text(h.get("input"))).lower()
        ips, cnames = dns_map.get(host, ([], []))
        prov = guess_cloud(cnames)
        url_host = as_text(h.get("url")).replace("https://", "").replace("http://", "")
        key = h.get("url", host)
        if key in seen:
            continue
        seen.add(key)
        row = {
            "host": host,
            "owner": "",
            "state": "",
            "ip": ";".join(sorted(ips)),
            "cname": ";".join(sorted(c.rstrip(".") for c in cnames)),
            "cloud_provider": prov,
            "port": h.get("port", ""),
            "status": h.get("status_code", ""),
            "title": (h.get("title") or "").replace("\n", " ")[:80],
            "tech": ";".join(str(x) for x in (h.get("tech") or []) if x),
            "cpe": ";".join(extract_cpe(h)),
            "findings": ";".join(sorted(findings.get(url_host.split(":")[0], []))),
        }
        row["owner"] = find_owner(host, owners)
        row["state"] = classify(row, row["owner"])
        rows.append(row)

    rows.sort(key=lambda r: (r["host"], str(r["port"])))

    with (out / "assets.csv").open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)

    # WAF の背後は応答が歪むため確度を下げる。
    # ただし cdn_name は「IPがそのクラウド事業者のもの」を示すだけで
    # WAF の有無とは無関係なので、判定に使ってはいけない。
    # 実際に WAF 製品が検出されたホストだけを対象にする。
    waf_hosts = set()
    for h in read_jsonl(out / "http.jsonl"):
        host = as_text(h.get("host")).lower()
        if not host:
            continue
        waf = h.get("waf")
        cdn_type = (h.get("cdn_type") or "").lower()
        if waf or cdn_type == "waf":
            waf_hosts.add(host)
    risks = build_risks(out, owners, waf_hosts)
    with (out / "risks.csv").open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=RISK_FIELDS)
        w.writeheader()
        w.writerows(risks)

    counts = {}
    for r in rows:
        counts[r["state"]] = counts.get(r["state"], 0) + 1
    cloudish = sum(1 for r in rows if r.get("cloud_provider"))
    conf = sum(1 for r in risks if r["confidence"] == "confirmed")
    print(f"    assets.csv: {len(rows)} 行")
    print(f"    risks.csv:  {len(risks)} 件 (確認済み {conf} / 要確認 {len(risks) - conf})")
    print(f"    持ち主不明 {counts.get('shadow', 0)} / "
          f"判明済み {counts.get('known', 0)} "
          f"(うちクラウド上と推定 {cloudish})")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "snapshots")
