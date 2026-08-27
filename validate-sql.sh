#!/usr/bin/env bash
# SQL の妥当性を、クラウドの認証情報なしで検証する。
#
# PostgreSQL は実行前に列の存在を検証するため、認証情報が無くても
# テーブル名・列名の誤りは検出できる。
# UNION の各ブロックを個別に検証し、失敗したテーブルの実際の列名を表示する。
#
# 使い方: bash validate-sql.sh [aws|azure|gcp ...]
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROVIDERS=("$@")
[[ ${#PROVIDERS[@]} -eq 0 ]] && PROVIDERS=(aws azure gcp)

command -v steampipe >/dev/null 2>&1 || { echo "steampipe がありません" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail=0

# SQL を "union all" で分割し、1ブロックずつファイルに書き出す
split_sql() {
  python3 - "$1" "$2" << 'PY'
import re, sys, pathlib
src, outdir = sys.argv[1], pathlib.Path(sys.argv[2])
body = pathlib.Path(src).read_text(encoding="utf-8")
body = re.sub(r"^\s*--.*$", "", body, flags=re.M)          # コメント除去
body = re.sub(r"order\s+by[^;]*$", "", body, flags=re.I|re.S)  # 末尾の order by を除去
body = body.rstrip().rstrip(";")
parts = re.split(r"\bunion\s+all\b", body, flags=re.I)
for i, part in enumerate(parts):
    part = part.strip()
    if not part:
        continue
    # 'from 0.0.0.0/0' のような本文中の from を拾わないよう、
    # まずプラグインのテーブル名（aws_/azure_/gcp_ 始まり）を探す
    m = re.search(r"\bfrom\s+((?:aws|azure|gcp)_[a-z0-9_]+)", part, re.I)
    if not m:
        m = re.search(r"\bfrom\s+([a-z][a-z0-9_]*)", part, re.I)
    table = m.group(1) if m else "unknown"
    (outdir / f"{i:02d}__{table}.sql").write_text(part, encoding="utf-8")
print(len(parts))
PY
}

for prov in "${PROVIDERS[@]}"; do
  echo "=============================================="
  echo " $prov"
  echo "=============================================="

  if ! steampipe plugin list 2>/dev/null | grep -q "turbot/${prov}@"; then
    echo "  プラグインを導入します..."
    steampipe plugin install "$prov" >/dev/null 2>&1 || {
      echo "  導入に失敗しました"; fail=1; continue; }
  fi

  for sql in "$ROOT/${prov}_"*.sql; do
    [[ -f "$sql" ]] || continue
    echo "  --- $(basename "$sql") ---"
    partdir="$WORK/$(basename "$sql" .sql)"
    mkdir -p "$partdir"
    split_sql "$sql" "$partdir" > /dev/null

    for part in "$partdir"/*.sql; do
      table="$(basename "$part" .sql | sed 's/^[0-9]*__//')"
      printf '    %-34s ' "$table"
      err="$(steampipe query --output csv \
               "select * from ( $(cat "$part") ) _v limit 0" 2>&1 >/dev/null)"

      if [[ -z "$err" ]] || ! grep -qiE 'does not exist|undefined|syntax error|no such' <<<"$err"; then
        echo "OK"
        continue
      fi

      echo "NG"
      grep -oiE '(column|relation|table) "[^"]+" does not exist' <<<"$err" \
        | head -2 | sed 's/^/        /'
      # 実在する列を出して修正の手掛かりにする
      cols="$(steampipe query --output csv \
        "select string_agg(column_name, ', ' order by column_name)
           from information_schema.columns where table_name = '$table'" 2>/dev/null \
        | tail -n +2 | tr -d '"')"
      if [[ -n "$cols" ]]; then
        echo "        実在する列:"
        echo "$cols" | fold -s -w 92 | head -8 | sed 's/^/          /'
      fi
      fail=1
    done
  done
  echo ""
done

if [[ "$fail" -ne 0 ]]; then
  echo "!! 修正が必要な SQL があります（上の「実在する列」を参照してください）"
  exit 1
fi
echo "すべての SQL がスキーマ検証を通過しました"
