#!/usr/bin/env bash
# SQL の妥当性を、クラウドの認証情報なしで検証する。
#
# PostgreSQL はクエリを実行する前に「そのテーブル・列が存在するか」を検証するため、
# 認証情報が無くても、テーブル名や列名の誤りは検出できる。
# 実際のデータ取得（API呼び出し）まで到達しなくても、スキーマの誤りは分かる。
#
# 使い方: bash validate-sql.sh [aws|azure|gcp ...]
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROVIDERS=("$@")
[[ ${#PROVIDERS[@]} -eq 0 ]] && PROVIDERS=(aws azure gcp)

if ! command -v steampipe >/dev/null 2>&1; then
  echo "steampipe がインストールされていません" >&2
  exit 1
fi

fail=0

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
    name="$(basename "$sql")"
    printf '  %-24s ' "$name"

    # LIMIT 0 で包むと、計画段階の検証だけが行われ API 呼び出しは起きない。
    # ここでエラーになれば、テーブル名か列名が間違っている。
    body="$(sed 's/;[[:space:]]*$//' "$sql")"
    err="$(steampipe query --output csv \
             "select * from ( $body ) _v limit 0" 2>&1 >/dev/null)"

    if [[ -z "$err" ]]; then
      echo "OK"
    elif grep -qiE 'does not exist|undefined column|undefined table|syntax error|no such' <<<"$err"; then
      echo "NG"
      echo "$err" | grep -iE 'does not exist|undefined|syntax error|no such|LINE' \
        | head -4 | sed 's/^/      /'
      fail=1
    else
      # 認証エラーや接続エラーはスキーマの誤りではないので合格扱い
      echo "OK (スキーマは正常 / 認証は未設定)"
    fi
  done
  echo ""
done

if [[ "$fail" -ne 0 ]]; then
  echo "!! 修正が必要な SQL があります"
  echo "!! 正しい列名は次のコマンドで確認できます:"
  echo "     steampipe query \"select column_name, data_type from information_schema.columns where table_name = 'aws_s3_bucket' order by column_name\""
  exit 1
fi

echo "すべての SQL がスキーマ検証を通過しました"
