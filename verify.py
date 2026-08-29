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

"""nuclei の2回照合。両方に出たものだけを confirmed とする。

使い方: verify.py <1回目.jsonl> <2回目.jsonl> <出力.jsonl> [キー種別]
  キー種別: url (既定, matched-at で照合) / host (ホスト単位で照合)
"""
import json
import sys


def make_key(rec, kind):
    tid = rec.get("template-id", "")
    if kind == "host":
        return (tid, rec.get("host", ""))
    return (tid, rec.get("matched-at") or rec.get("host") or "")


def load(path, kind):
    out = {}
    try:
        with open(path, errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    r = json.loads(line)
                    out[make_key(r, kind)] = r
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return out


def main():
    p1_path, p2_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    kind = sys.argv[4] if len(sys.argv) > 4 else "url"
    p1, p2 = load(p1_path, kind), load(p2_path, kind)
    with open(out_path, "w") as f:
        for k, r in sorted(p1.items(), key=lambda kv: str(kv[0])):
            r["confidence"] = "confirmed" if k in p2 else "single"
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    c = sum(1 for k in p1 if k in p2)
    print(f"    confirmed {c} / single {len(p1) - c}")


if __name__ == "__main__":
    main()
