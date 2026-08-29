#!/usr/bin/env bash
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

# 前回コミットとの差分を Markdown で出す。DBもタイムスタンプ管理も持たない。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

diff_of() { git diff -U0 -- "$1" | grep "^$2" | grep -v "^$2$2$2" | sed "s/^$2//" || true; }

echo "## セキュリティリスクの差分"
echo

r_add=$(diff_of snapshots/risks.csv +)
r_del=$(diff_of snapshots/risks.csv -)

if [[ -z "$r_add" && -z "$r_del" ]]; then
  echo "新規の指摘はありません"
else
  # 確認済みのものだけを本文に出す。要確認は件数のみ
  conf=$(echo "$r_add" | grep ",confirmed," || true)
  single=$(echo "$r_add" | grep -c ",single," || true)

  if [[ -n "$conf" ]]; then
    echo "### 新規の指摘（確認済み）"
    echo '```'
    echo "$conf" | cut -d, -f1,3,6 | head -30
    echo '```'
    echo
  fi
  [[ "$single" -gt 0 ]] && echo "要確認の指摘が $single 件あります（誤検知の可能性あり・画面で確認してください）" && echo

  if [[ -n "$r_del" ]]; then
    echo "解消された指摘: $(echo "$r_del" | wc -l) 件"
    echo
  fi
fi

echo "## 資産の差分"
echo

a_add=$(diff_of snapshots/assets.csv +)
a_del=$(diff_of snapshots/assets.csv -)

if [[ -z "$a_add" && -z "$a_del" ]]; then
  echo "変更なし"
else
  if [[ -n "$a_add" ]]; then
    echo "新規・変更 $(echo "$a_add" | wc -l) 行"
    echo '```'
    echo "$a_add" | cut -d, -f1,2,3 | head -30
    echo '```'
  fi
  [[ -n "$a_del" ]] && echo "消滅 $(echo "$a_del" | wc -l) 行"

  shadow=$(echo "$a_add" | grep -c ",shadow," || true)
  [[ "$shadow" -gt 0 ]] && echo && echo "持ち主不明の資産が $shadow 件あります。owners.yaml に追記してください"
fi
