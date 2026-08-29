#!/usr/bin/env bash
# mini-easm: 外部公開資産の棚卸し + ネットワーク診断
#
# 誤検知を抑えるための方針:
#   1. バージョンバナーからの推測でCVEを判定しない
#   2. 観測できた事実と、実レスポンスで確認できたものだけを報告する
#   3. nuclei の検出は2回とも出たものだけを confirmed とする
#
# 前提コマンド: steampipe, subfinder, dnsx, httpx, naabu, tlsx, nuclei, jq
set -Eeuo pipefail

# どのコマンドで落ちたかを必ず表示する
trap 'rc=$?; echo ""; echo "!! 失敗: ${BASH_SOURCE[0]}:${LINENO}"; echo "!! 命令: ${BASH_COMMAND}"; echo "!! 終了コード: $rc"; exit $rc' ERR

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
OUT="$ROOT/snapshots"
mkdir -p "$OUT"
trap 'rm -rf "$WORK"' EXIT

# 診断の深さ。既定は full。asset を指定すると資産棚卸しのみ
MODE="${MODE:-full}"

# 各フェーズの所要時間を記録する（どこが遅いか分かるように）
_T0=$(date +%s)
_LAST=$_T0
lap() {
  local now; now=$(date +%s)
  printf '    [%s] %d秒\n' "$1" "$((now - _LAST))"
  _LAST=$now
}

echo "==> [1/7] クラウド側: 外部公開リソースを取得"
echo "provider,resource_type,resource_id,dns_name,ip,region" > "$OUT/cloud.csv"
for sql in "$ROOT"/*_public.sql; do
  name="$(basename "$sql" _public.sql)"
  if steampipe plugin list 2>/dev/null | grep -q "turbot/${name}@"; then
    printf "    %s ... " "$name"
    if steampipe query --output csv "$sql" 2>"$WORK/${name}.err" | tail -n +2 >> "$OUT/cloud.csv"; then
      echo "ok"
    else
      echo "失敗 (詳細: $WORK/${name}.err)"
    fi
  else
    echo "    $name ... スキップ (プラグイン未導入)"
  fi
done
echo "    合計 $(( $(wc -l < "$OUT/cloud.csv") - 1 )) 件"

lap "クラウド資産"
echo "==> [2/7] クラウド側: 設定リスクを取得"
# 設定値をそのまま読むため誤検知は発生しない
echo "provider,resource_id,risk_id,severity,detail" > "$OUT/cloud_risks.csv"
for sql in "$ROOT"/*_risks.sql; do
  name="$(basename "$sql" _risks.sql)"
  if steampipe plugin list 2>/dev/null | grep -q "turbot/${name}@"; then
    steampipe query --output csv "$sql" 2>/dev/null | tail -n +2 >> "$OUT/cloud_risks.csv" || true
  fi
done
echo "    $(( $(wc -l < "$OUT/cloud_risks.csv") - 1 )) 件"

lap "クラウド設定"
echo "==> [3/7] シードドメインを決定"
: > "$WORK/seeds.txt"
if [[ -f "$ROOT/seeds.txt" ]]; then
  grep -vE '^\s*(#|$)' "$ROOT/seeds.txt" >> "$WORK/seeds.txt" || true
fi
if steampipe plugin list 2>/dev/null | grep -q 'turbot/aws@'; then
  steampipe query --output csv "$ROOT/aws_seeds.sql" 2>/dev/null \
    | tail -n +2 >> "$WORK/seeds.txt" || true
fi
sort -u -o "$WORK/seeds.txt" "$WORK/seeds.txt"
if [[ ! -s "$WORK/seeds.txt" ]]; then
  echo "    シードが空です。seeds.txt にドメインを書いてください" >&2
  exit 1
fi
echo "    $(wc -l < "$WORK/seeds.txt") ドメイン"

lap "シード"
echo "==> [4/7] 外部偵察: subfinder -> dnsx -> naabu -> httpx"
subfinder -dL "$WORK/seeds.txt" -silent -all > "$WORK/subs.txt" || true

# hosts.txt があれば、列挙を経由せずそのまま対象に加える。
# 証明書に大量のSANが入っているドメインなど、列挙が暴れる相手に使う
if [[ -f "$ROOT/hosts.txt" ]]; then
  grep -vE '^\s*(#|$)' "$ROOT/hosts.txt" >> "$WORK/subs.txt" || true
fi
sort -u -o "$WORK/subs.txt" "$WORK/subs.txt"

# --- 件数の上限チェック ---
# 数万件になるとポートスキャンが終わらないため、上限を超えたら止める
sub_count=$(wc -l < "$WORK/subs.txt")
echo "    列挙されたホスト名 $sub_count 件"
# 列挙が異常に多いときは警告するが、止めない。
# 「多すぎて何も分からない」より「一部でも結果が出る」ほうが実用的
MAX_SUBS="${MAX_SUBS:-5000}"
if [[ "$sub_count" -gt "$MAX_SUBS" ]]; then
  echo "    !! 列挙結果が多すぎます（$sub_count 件）。先頭 $MAX_SUBS 件のみ調査します"
  echo "    !! 捨てた件数: $(( sub_count - MAX_SUBS ))"
  echo "    !! ワイルドカード証明書や自動生成サブドメインが原因のことがあります"
  echo "    !! 全件見たい場合は MAX_SUBS を上げるか、seeds.txt を分割してください"
  head -n "$MAX_SUBS" "$WORK/subs.txt" > "$WORK/subs.trimmed" && mv "$WORK/subs.trimmed" "$WORK/subs.txt"
fi

# 名前解決。-nc で NXDOMAIN の CNAME (乗っ取り可能な状態) も拾う
dnsx -l "$WORK/subs.txt" -silent -a -cname -resp -json -retry 3 -t 50 > "$OUT/dns.jsonl" || true
# 解決先が全てプライベート/ループバックのホストは除外する。
# 残すとスキャン元マシン自身や社内NWを誤ってスキャンしてしまう
jq -r '
  select(.a != null)
  | select([.a[] | test("^(127\\.|10\\.|192\\.168\\.|169\\.254\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|0\\.|::1$|fe80:|f[cd])")] | all | not)
  | .host' "$OUT/dns.jsonl" 2>/dev/null | sort -u > "$WORK/live.txt" || : > "$WORK/live.txt"

_all=$(jq -r 'select(.a != null) | .host' "$OUT/dns.jsonl" 2>/dev/null | sort -u | wc -l 2>/dev/null || echo 0)
_kept=$(wc -l < "$WORK/live.txt" 2>/dev/null || echo 0)
if [[ "${_all:-0}" -gt "${_kept:-0}" ]]; then
  echo "    プライベートIPのため除外: $(( _all - _kept )) 件"
fi

live_count=$(wc -l < "$WORK/live.txt")
echo "    名前解決できたホスト $live_count 件"
# 生存ホストが多い場合は、止めずにポート数を自動で絞る。
# 1ホストあたり約2.5分かかるため、300件を超えると2時間の枠に収まらない
MAX_LIVE="${MAX_LIVE:-300}"
TOP_PORTS=1000
if [[ "$live_count" -gt "$MAX_LIVE" ]]; then
  TOP_PORTS=100
  echo "    !! 生存ホストが $live_count 件のため、ポートスキャンを上位100に絞ります"
  echo "    !! （上位1000で回すには seeds.txt の分割を検討してください）"
fi

# ポートスキャン。開いているポートは接続できた事実なので誤検知なし
if [[ "$MODE" == "full" ]] && ! command -v naabu >/dev/null 2>&1; then
  echo "    naabu が見つかりません。ポートスキャンをスキップします"
fi
if [[ "$MODE" == "full" ]] && command -v naabu >/dev/null 2>&1; then
  # 上位1000ポート
  naabu -list "$WORK/live.txt" -silent -json -top-ports "$TOP_PORTS" \
        -scan-type c -rate 1000 -c 50 -retries 2 -timeout 1200 -warm-up-time 1 > "$WORK/ports1.jsonl" || true
  # VPN機器・管理画面が使いがちな非標準ポート（上位1000に入らないため個別指定）
  naabu -list "$WORK/live.txt" -silent -json \
        -p 1723,2222,3390,4443,7001,8090,8888,9443,10443,10444,20443 \
        -scan-type c -rate 1000 -c 50 -retries 2 -timeout 1200 -warm-up-time 1 > "$WORK/ports2.jsonl" || true
  # timestamp が入るため sort -u では重複が消えない。host:port で正規化して除去する
  cat "$WORK/ports1.jsonl" "$WORK/ports2.jsonl" 2>/dev/null \
    | jq -c 'select(.host and .port) | {host, ip, port}' 2>/dev/null \
    | sort -u > "$OUT/ports.jsonl" || : > "$OUT/ports.jsonl"
  echo "    開放ポート $(wc -l < "$OUT/ports.jsonl") 件"
  jq -r '"\(.host):\(.port)"' "$OUT/ports.jsonl" 2>/dev/null | sort -u > "$WORK/hostports.txt" || : > "$WORK/hostports.txt"

  # ポートスキャンは取りこぼすことがある（パケットロス・レート制限）。
  # 生存ホストについては主要な Web ポートを必ず httpx に渡して確認する
  while read -r h; do
    [[ -z "$h" ]] && continue
    for prt in 80 443 8080 8443; do echo "$h:$prt"; done
  done < "$WORK/live.txt" >> "$WORK/hostports.txt"
  sort -u -o "$WORK/hostports.txt" "$WORK/hostports.txt"

  # サービス識別: nmap -sV でバナーからサービスとバージョンを判定する。
  # 観測した応答そのものなので confirmed として扱える。
  # 対象は naabu が見つけた開放ポートに限定し、追加のポート探索はしない
  if command -v nmap >/dev/null 2>&1 && [[ -s "$WORK/hostports.txt" ]]; then
    cut -d: -f1 "$WORK/hostports.txt" | sort -u > "$WORK/nmap_hosts.txt"
    nmap_ports=$(cut -d: -f2 "$WORK/hostports.txt" | sort -un | paste -sd, -)
    if [[ -n "$nmap_ports" ]]; then
      timeout 1200 nmap -sV --version-intensity 4 -Pn -n -T4 \
        -p "$nmap_ports" -iL "$WORK/nmap_hosts.txt" \
        -oX "$WORK/nmap.xml" > /dev/null 2> "$WORK/nmap.err" || true
      python3 "$ROOT/nmap2jsonl.py" "$WORK/nmap.xml" "$OUT/services.jsonl"
    else
      : > "$OUT/services.jsonl"
    fi
  else
    : > "$OUT/services.jsonl"
    echo "    nmap が見つかりません（サービス識別をスキップ）"
  fi
else
  : > "$OUT/ports.jsonl"
  cp "$WORK/live.txt" "$WORK/hostports.txt"
fi

httpx -l "$WORK/hostports.txt" -silent -json \
      -status-code -title -tech-detect -tls-grab -cpe -cdn \
      -rate-limit 50 > "$OUT/http.jsonl" || true
echo "    $(wc -l < "$OUT/http.jsonl") エンドポイント"

# DNS では見つかったのに一切応答が無かったホストを警告する。
# 落ちているか、スキャン元IPをブロックしている可能性がある
jq -r '.host' "$OUT/http.jsonl" 2>/dev/null | sed 's/:.*//' | sort -u > "$WORK/responded.txt" || : > "$WORK/responded.txt"
unreachable=$(comm -23 "$WORK/live.txt" "$WORK/responded.txt" 2>/dev/null | head -20 || true)
if [[ -n "$unreachable" ]]; then
  echo "    !! DNS上は存在するが無応答のホスト:"
  echo "$unreachable" | sed 's/^/       /'
  echo "       (停止中か、スキャン元IPを遮断している可能性があります)"
fi

lap "外部偵察"
echo "==> [5/7] 証明書の検査"
# 証明書の中身を読むだけなので誤検知なし
if [[ "$MODE" == "full" ]]; then
  # 443 だけでなく、開いていた TLS 候補ポートも検査する
  {
    jq -r 'select(.port | IN(443,8443,9443,10443,4443,993,995,465,636,3389)) | "\(.host):\(.port)"' \
      "$OUT/ports.jsonl" 2>/dev/null || true
    sed 's/$/:443/' "$WORK/live.txt"
  } | sort -u > "$WORK/tlstargets.txt"

  tlsx -l "$WORK/tlstargets.txt" -silent -json -expired -self-signed -mismatched \
       -untrusted -so -tls-version -cipher > "$OUT/tls.jsonl" 2>/dev/null || true
  echo "    $(wc -l < "$OUT/tls.jsonl") 件 / 対象 $(wc -l < "$WORK/tlstargets.txt") 件"
else
  : > "$OUT/tls.jsonl"
fi

lap "証明書"
echo "==> [6/7] DNS/ネットワーク層の検査"
: > "$OUT/netfindings.jsonl"
: > "$OUT/dns_risks.jsonl"
if [[ "$MODE" == "full" ]]; then

  # --- DNSサーバの検査 ---
  # dig の応答を読むだけなので誤検知は発生しない
  # 検査対象は「53番が開いていたホスト」だけでは足りない。
  # 権威DNSサーバは別ドメインで運用されていることが多いため、
  # 各シードドメインの NS レコードを引いて、そのサーバを対象に加える
  : > "$WORK/dnshosts.txt"
  jq -r 'select(.port == 53) | .host' "$OUT/ports.jsonl" 2>/dev/null >> "$WORK/dnshosts.txt" || true
  while read -r zone; do
    [[ -z "$zone" ]] && continue
    timeout 10 dig +short NS "$zone" 2>/dev/null | sed 's/\.$//' >> "$WORK/dnshosts.txt" || true
  done < "$WORK/seeds.txt"
  sort -u -o "$WORK/dnshosts.txt" "$WORK/dnshosts.txt"
  sed -i '/^$/d' "$WORK/dnshosts.txt"
  echo "    DNSサーバ $(wc -l < "$WORK/dnshosts.txt") 台を検査"
  while read -r dnshost; do
    [[ -z "$dnshost" ]] && continue
    # ゾーン転送(AXFR)が通ると全DNSレコードが第三者に漏れる
    while read -r zone; do
      [[ -z "$zone" ]] && continue
      if timeout 10 dig +noall +answer "@$dnshost" "$zone" AXFR 2>/dev/null | grep -q "SOA"; then
        printf '{"host":"%s","risk_id":"dns-zone-transfer","severity":"high","detail":"DNS zone transfer (AXFR) allowed for %s"}\n' \
          "$dnshost" "$zone" >> "$OUT/dns_risks.jsonl"
      fi
    done < "$WORK/seeds.txt"
    # オープンリゾルバはDNS増幅攻撃の踏み台にされる
    if timeout 10 dig +short "@$dnshost" example.com A 2>/dev/null | grep -qE '^[0-9]+\.'; then
      printf '{"host":"%s","risk_id":"dns-open-resolver","severity":"medium","detail":"Open DNS resolver (recursion allowed from internet)"}\n' \
        "$dnshost" >> "$OUT/dns_risks.jsonl"
    fi
  done < "$WORK/dnshosts.txt"
  echo "    DNS $(wc -l < "$OUT/dns_risks.jsonl") 件"

  # --- HTTP以外のプロトコル (ssh / smtp / rdp / ftp / telnet 等) ---
  if [[ -s "$WORK/hostports.txt" ]]; then
    nuclei -config "$ROOT/nuclei-network-config.yaml" -l "$WORK/hostports.txt" \
           -type network,dns,ssl -silent -jsonl > "$WORK/net1.jsonl" || true
    if [[ -s "$WORK/net1.jsonl" ]]; then
      sleep 5
      jq -r '.host' "$WORK/net1.jsonl" 2>/dev/null | sort -u > "$WORK/nethits.txt" || : > "$WORK/nethits.txt"
      jq -r '."template-id"' "$WORK/net1.jsonl" 2>/dev/null | sort -u | paste -sd, - > "$WORK/netids.txt" || : > "$WORK/netids.txt"
      nuclei -config "$ROOT/nuclei-network-config.yaml" -l "$WORK/nethits.txt" \
             -id "$(cat "$WORK/netids.txt")" -type network,dns,ssl \
             -silent -jsonl > "$WORK/net2.jsonl" || true
      python3 "$ROOT/verify.py" "$WORK/net1.jsonl" "$WORK/net2.jsonl" "$OUT/netfindings.jsonl" host
    else
      echo "    ネットワーク層 0 件"
    fi
  fi
fi

lap "ネットワーク層"
echo "==> [7/7] Web の指摘検出 (2回照合)"
: > "$OUT/findings.jsonl"
if [[ "$MODE" == "full" ]]; then
  jq -r '.url' "$OUT/http.jsonl" 2>/dev/null | sort -u > "$WORK/urls.txt" || : > "$WORK/urls.txt"

  # 1回目
  nuclei -config "$ROOT/nuclei-config.yaml" -l "$WORK/urls.txt" \
         -silent -jsonl > "$WORK/pass1.jsonl" || true

  # 2回目: 1回目で当たったテンプレートと対象だけを再実行する。
  # 一過性の応答やレート制限による偽陽性をここで落とす
  if [[ -s "$WORK/pass1.jsonl" ]]; then
    jq -r '."template-id"' "$WORK/pass1.jsonl" 2>/dev/null | sort -u | paste -sd, - > "$WORK/ids.txt" || : > "$WORK/ids.txt"
    { jq -r '."matched-at" // .url // .host' "$WORK/pass1.jsonl" 2>/dev/null \
      | sed 's#\(https\?://[^/]*\).*#\1#' | sort -u > "$WORK/hits.txt"; } || : > "$WORK/hits.txt"
    sleep 5
    nuclei -config "$ROOT/nuclei-config.yaml" -l "$WORK/hits.txt" \
           -id "$(cat "$WORK/ids.txt")" -silent -jsonl > "$WORK/pass2.jsonl" || true

    # 両方に出たものを confirmed、1回だけのものを single とする
    python3 "$ROOT/verify.py" "$WORK/pass1.jsonl" "$WORK/pass2.jsonl" "$OUT/findings.jsonl" url
  else
    echo "    0 件"
  fi
else
  echo "    スキップ (MODE=asset)"
fi

lap "Web検出"
echo "==> 正規化"
python3 "$ROOT/normalize.py" "$OUT"
cp "$OUT/assets.csv" "$ROOT/assets.csv" 2>/dev/null || true
cp "$OUT/risks.csv"  "$ROOT/risks.csv"  2>/dev/null || true

lap "正規化"
printf '    合計 %d分\n' "$(( ($(date +%s) - _T0) / 60 ))"
echo "完了: $OUT/assets.csv, $OUT/risks.csv"
