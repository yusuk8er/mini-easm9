# mini-easm

外部公開資産の棚卸し・クラウドリソースの可視化・シャドーIT検出に絞った、
サーバもDBもWeb UIも持たない最小構成のASM。

**脆弱性スキャンは行いません。** 資産の把握だけが目的です。

## 設計の核

**1. 差分検知を自作せず git に丸投げする**

毎回ソート済みCSVを吐いて commit するだけで、履歴管理は `git log`、
差分検知は `git diff`、変更レビューは PR、保管はリポジトリが担当します。
資産DBのスキーマ設計も履歴テーブルも不要になります。

**2. 攻撃を模した通信を送らない**

nuclei による脆弱性スキャンは既定で無効です。送るのは
ブラウザでページを開くのと同じ HTTP リクエストだけ。
これにより社内承認のハードルが下がり、誤検知もゼロになります。

**3. 「持ち主が分かっているもの」を書き足していく**

`owners.yaml` に判明した持ち主を追記すると、書かれていないものが
自動的に「持ち主不明」として浮かび上がります。これがシャドーIT検出の実体です。

## 構成

```
Route53 ──┐
seeds.txt ─┴─> subfinder ──> dnsx ──> httpx
                              │         │
Steampipe(AWS/Azure/GCP) ──> cloud.csv ─┴─> normalize.py <── owners.yaml
                                                 │
                                          snapshots/assets.csv
                                                 │
                                          git commit ──> git diff ──> Slack
```

## 判定の4分類

| 判定 | 意味 | やること |
|---|---|---|
| `shadow` | 持ち主不明 | **最優先で調べる。** 分かったら `owners.yaml` に追記 |
| `unmapped` | クラウドっぽいが自社アカウントに無い | 別アカウント？個人アカウント？を確認 |
| `managed` | 自社クラウドアカウント内で突合できた | 通常は放置でよい |
| `external` | クラウド外（オンプレ等）で持ち主が判明 | 通常は放置でよい |

運用の中心は `shadow` を減らしていく作業です。
初回は大量に出ますが、`owners.yaml` が埋まるにつれ減っていきます。

## そぎ落としたもの（と、その理由）

| 捨てた機能 | 理由 |
|---|---|
| 脆弱性スキャン | 目的外。誤検知対応が運用の最大コストになるため既定でオフ |
| 資産DB・履歴テーブル | git が代わりをする |
| Web UI サーバ | CSV を読む静的HTML1枚で足りる |
| フルポートスキャン | 80/443/8080/8443 のみ |
| サブドメインのブルートフォース | 遅く・うるさく・費用対効果が悪い。パッシブ収集のみ |
| クラウド全資産の棚卸し | 「外部公開されているもの」だけをSQLで絞る |
| IPレンジによるクラウド判定 | CNAME の文字列一致で十分実用になる |
| チケット管理・ステータス変更 | 状態はCSVから毎回導出。書き込み機能を持たない |

## セットアップ

ブラウザだけで完結する手順は `GETTING-STARTED.md`、
安全な練習方法は `PRACTICE.md` を参照してください。

ローカルで動かす場合:

```bash
brew install steampipe jq
steampipe plugin install aws     # 必要に応じて azure / gcp も
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
sudo apt-get install -y nmap dnsutils

chmod +x *.sh
./scan.sh
./report.sh
```

シードドメインは Route53 のパブリックゾーン（AWS分）と
`seeds.txt`（オンプレ・他社管理分）の**両方**が使われます。

`hosts.txt` に書いたホスト名は、サブドメイン列挙を経由せずそのまま調査対象になります。
列挙が暴走するドメインや、列挙では見つからないが存在を知っているホストに使います。

安全装置として、列挙結果が 5,000 件（`MAX_SUBS`）を超えると先頭5,000件に絞り、
生存ホストが 300 件（`MAX_LIVE`）を超えるとポートスキャンを上位100に自動縮小します。
**いずれもスキャンは止まりません**。捨てた件数はログに出ます。

ワイルドカード証明書を長く運用している企業や、CI/CDで検証環境を自動生成している場合、
1ドメインで数百〜数千件になることは珍しくありません。

## クラウドの認証情報を扱えない場合

組織の方針でアクセスキーを共有できないことがあります。その場合、
**クラウド管理者に手元でSQLを実行してもらい、CSVだけを受け取る**運用ができます。

1. クラウド管理者に `FOR-CLOUD-ADMIN.md` を渡す
2. `cloud-manual.csv` と `cloud-risks-manual.csv` を出力してもらう
3. リポジトリのルートに置く

これらのファイルがあると、スキャン時に Steampipe を呼ばず、CSVの内容をそのまま使います。
認証情報がリポジトリを離れることはありません。

```
    cloud-manual.csv を使用 (42 件)
    手動CSVを使用中のためスキップ
```

CSVが古くても動作します。その間に増えたクラウド資産は「未マップ」として
検出され、次回の更新で解消します。

## 対応クラウドを増やす

`*_public.sql` を置くだけで自動的に対象になります
（プラグイン未導入のものはスキップ）。同梱: aws / azure / gcp

列名は Steampipe のバージョンで変わることがあります。エラーが出たら
`steampipe query "select * from azure_public_ip limit 1"` で実際の列を確認してください。

**外部偵察側（subfinder→dnsx→httpx）はクラウドに依存しません。**
オンプレでも他社SaaSでも、DNSに載っていれば検出されます。
クラウドプラグインは「外から名前で辿れない資産」を補完する役割です。

## UI

`index.html` が単一ファイルのビューワです。ビルドもサーバもバックエンドもありません。

```bash
python3 -m http.server 8000
```

> GitHub Pages をプライベートに公開するには Organization アカウントかつ
> GitHub Enterprise Cloud が必要です。Free/Pro/Team のプライベートリポジトリでは
> 上記のローカル起動か、CSV を直接開いてください。

## 出力

`snapshots/assets.csv`

| 列 | 内容 |
|---|---|
| host | ホスト名 |
| owner | `owners.yaml` から引いた持ち主。空なら不明 |
| state | shadow / unmapped / managed / external |
| ip / cname | 解決結果 |
| cloud_provider / cloud_resource_type / cloud_resource_id | 突合したクラウドリソース |
| port / status / title / tech | httpx の検出結果 |
| cpe | httpx の出力、または `tech` から組み立てた CPE。**CVE特定には使わないこと** |
| findings | 既定では空（脆弱性スキャン無効のため） |

## どうしても脆弱性シグナルが欲しいとき

```bash
ENABLE_VULN_SCAN=1 ./scan.sh
```

nuclei が high / critical のみ実行されます。
**対象サーバに攻撃を模したリクエストを大量に送るため、
自社資産に限り、事前に社内の監視チームへ連絡したうえで実行してください。**

## 注意

- スキャン対象は必ず自組織の資産に限定してください
- 未検証のスキャフォールドです。まずは小さいドメイン1つで動作確認してください


## 検出できる範囲

| 対象 | 検出元 | 確度 |
|---|---|---|
| 開いているポート | naabu | confirmed（接続成立の事実） |
| 動いているサービスとバージョン | nmap -sV | confirmed（バナー観測） |
| SSH / RDP / Telnet / VNC / SMB の外部公開 | naabu + nmap -sV | confirmed |
| データベースの外部公開 | naabu + nmap -sV | confirmed |
| TLS証明書の失効・自己署名・不一致・旧バージョン | tlsx | confirmed |
| DNSゾーン転送(AXFR)の許可 | dig | confirmed |
| オープンリゾルバ | dig | confirmed |
| サブドメイン乗っ取り可能な状態 | dnsx | confirmed |
| クラウドの設定リスク | steampipe | confirmed（設定値そのもの） |
| VPN機器・ネットワーク機器のCVE | nuclei (http/network) | 2回照合で confirmed / single |
| Webアプリの既知CVE | nuclei | 2回照合で confirmed / single |
| SSH / SMTP / FTP など非HTTPの指摘 | nuclei -type network | 2回照合で confirmed / single |

VPN機器の管理画面は 4443 / 8443 / 9443 / 10443 などの非標準ポートで動くことが多いため、
上位1000ポートに加えてこれらを個別にスキャンしています。

### 依然として検出できないもの

- 認証の内側（ログインしないと分からない脆弱性）
- ビジネスロジックの欠陥
- XSS / SQLインジェクション（誤検知が多いため除外）
- バージョン推測に基づく既知脆弱性（推測を排除する方針のため）
- UDPのみで動くサービス（SNMP、IKE など。naabu は TCP のみ）


## ライセンス

本リポジトリの独自コードは Apache License 2.0 で提供します（Copyright 2026 Yusuke Hirose）。
詳細は `LICENSE` を参照してください。

各ソースファイルの先頭には SPDX 形式の表記を入れています。

```
# SPDX-License-Identifier: Apache-2.0
```

新しくファイルを追加したときは、次のコマンドでヘッダーを付与できます。

```bash
python3 add-license-header.py          # 付与する
python3 add-license-header.py --check  # 不足しているファイルを一覧表示
```

利用しているサードパーティOSSの帰属表示は `NOTICE` にまとめています。
いずれも実行時に導入されるものであり、本リポジトリには同梱していません。

**Steampipe は本体が AGPL-3.0** です。CLIをそのまま呼び出す現在の使い方では
制約はありませんが、改変してネットワーク越しのサービスとして提供する場合は
ソース開示義務が生じます。SaaS化を検討する際は必ず確認してください。

**Nmap は GPL 派生の独自ライセンス（NPSL）** です。同梱・再頒布する場合は
条項の確認が必要です。本ツールは実行環境にあるものを呼び出す形にしています。
