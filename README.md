# mini-easm

外部公開資産の棚卸しとシャドーIT検出に絞った、
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
seeds.txt ──┬─> subfinder ──> dnsx ──> naabu ──> nmap ──> httpx
hosts.txt ──┘                   │                          │
                                └──> tlsx / dig ──> nuclei ─┤
                                                            ↓
                                        normalize.py <── owners.yaml
                                                            ↓
                                              assets.csv / risks.csv
                                                            ↓
                                        git commit ──> git diff ──> Slack
```

## 判定の2分類

| 判定 | 意味 | やること |
|---|---|---|
| `shadow` | 持ち主台帳に載っていない | **最優先で調べる。** 分かったら `owners.yaml` に追記 |
| `known` | 持ち主が判明している | 通常は放置でよい |

これとは別に `cloud_provider` 列に、CNAME から推定したクラウド事業者が入ります
（`aws` / `azure` / `gcp` / `saas`）。**認証情報は不要で、DNSの応答だけから判定します。**

`shadow` かつ `cloud_provider` に値がある資産が、シャドーITの最有力候補です。

```
demo.example.co.jp  →  CNAME: demo.azurewebsites.net
                       持ち主不明 + Azure上と推定 → 要調査
```

## 関連ドメインの探索（discover）

`seeds.txt` に書いたドメインの配下しか探索しないため、
**別ドメインで取得された資産は見つかりません**。
マーケティング部門が独自に取得したキャンペーンサイトなどが典型です。

`discover.py` は、証明書透明性ログを2つの手がかりで検索し、
把握できていないドメインの候補を洗い出します。

| 手がかり | 内容 |
|---|---|
| SANピボット | 既知ドメインの証明書に同居している別ドメインを見つける |
| 組織名検索 | 証明書の Subject Organization で横断検索する |

```bash
python3 discover.py
```

GitHub Actions から実行する場合は、モードに `discover` を指定します。

### 発見したドメインは自動でスキャンされません

結果は `candidates.csv` に列挙されるだけです。

```csv
domain,source,evidence,decision
example-campaign.jp,san-pivot,O=Lets Encrypt,
example-holdings.co.jp,org-search,Example Corporation,
```

**1件ずつ自社のものか確認し、自社資産と判断できたものだけを
`seeds.txt` に追記してください。**

証明書の組織名は他社と重複することがあり、SANに取引先のドメインが
含まれることもあります。確認せずに追加すると、他社の資産を
スキャンすることになり法的な問題になります。

### 組織名を指定する

`org-names.txt` に自社の組織名（証明書に記載される英語表記）を書きます。
表記ゆれがある場合は複数行に分けてください。

DV証明書には組織名が入らないため、この手がかりは
OV/EV証明書を使っている場合にのみ有効です。

## クラウド連携について

クラウドの認証情報を扱う機能は本ツールに含まれていません。

このため、以下は検出できません。

- クラウドの設定不備（セキュリティグループの開放、ストレージの公開設定など）
- ドメインが割り当てられていないクラウドリソース
- 自組織のクラウドアカウントに存在するかによる確定的な突合

**持ち主台帳に基づくシャドーIT検出は、認証情報なしで動作します。**
また `cloud_provider` 列には CNAME から推定した事業者が入るため、
「Azure上にあるが自社はAzureを使っていない」といった判断は可能です。

クラウドの設定不備を網羅的に確認したい場合は、
Prowler や Scout Suite などのCSPMツール、
またはクラウド事業者が提供する監査機能の利用を検討してください。


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
brew install jq nmap
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
| cloud_provider | CNAME から推定したクラウド事業者（aws / azure / gcp / saas） |
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
| 非標準ポートで動くDB・リモートアクセス | nmap -sV | confirmed。ポート番号では判定できないものを補う |
| SSH / RDP / Telnet / VNC / SMB の外部公開 | naabu + nmap -sV | confirmed |
| データベースの外部公開 | naabu + nmap -sV | confirmed |
| TLS証明書の失効・自己署名・不一致・旧バージョン | tlsx | confirmed |
| DNSゾーン転送(AXFR)の許可 | dig | confirmed |
| オープンリゾルバ | dig | confirmed |
| サブドメイン乗っ取り可能な状態 | dnsx | confirmed |
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

**Nmap は GPL 派生の独自ライセンス（NPSL）** です。同梱・再頒布する場合は
条項の確認が必要です。本ツールは実行環境にあるものを呼び出す形にしています。


## サービス識別とポートスキャンの関係

危険ポートの検出（naabu）とサービス識別（nmap -sV）は役割が異なります。

| 状況 | 検出 |
|---|---|
| 3306 が開いている | `mysql-exposed`。nmap で版が取れていれば末尾に付加される |
| 8081 で MongoDB が動いている | `mongodb-service-exposed`。**ポート番号だけでは判定できない** |

同じポートが両方で検出されることはありません（`DANGEROUS_PORTS` に載っているポートは
サービス識別側で除外しています）。

出力例:

```
critical  mysql-exposed              MySQL exposed to internet (3306/tcp) - MySQL 5.7.31
critical  mongodb-service-exposed    MONGODB MongoDB 4.0 on 8081/tcp (database reachable from internet)
high      ssh-exposed                SSH exposed to internet (22/tcp) - OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
```

バージョン表記は nmap がバナーから読み取った値です。**この値だけでCVEを断定してはいけません**
（詳細は `FALSE-POSITIVES.md`）。パッチレベル（`2ubuntu2.13` 等）まで取れることがあるため、
バックポート適用の有無を判断する材料としては有用です。
