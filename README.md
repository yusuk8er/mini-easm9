# Yusuk8er-easm

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
python3 summary.py snapshots
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


## 結果の見方

### 1. Actions のサマリー（ダウンロード不要）

実行が終わると、Actions の実行画面に結果が表示されます。
**多くの週はここを見るだけで足ります。**

- 資産数・持ち主不明・指摘件数と、前回比
- 新規の指摘（深刻度順）
- 新しく見つかった資産／消滅した資産
- 持ち主不明の一覧（折りたたみ）

### 2. report.html（詳しく見るとき）

## 画面で見る

スキャンのたびに `report.html` が生成されます。
**結果を埋め込んだ自己完結のHTMLなので、ダウンロードしてダブルクリックするだけで開けます。**
サーバもビルドも不要です。

```
snapshots/report.html   ← アーティファクトに含まれる
report.html             ← リポジトリのルートにもコミットされる
```

リスクと資産を切り替えて閲覧でき、深刻度や持ち主で絞り込めます。

### 前回との差分が分かる

各行には前回実行時からの変化が表示されます。

| 表示 | 意味 |
|---|---|
| NEW | 今回はじめて現れた |
| 消滅 | 前回はあったが今回は無い（取り消し線で表示） |
| （なし） | 変化なし |

「新規」フィルタを押すと、**今週増えたものだけ**を確認できます。
定常運用ではここだけ見れば足ります。

集計タイルにも新規・消滅の件数が出ます。

```
指摘 12 / 新規 2 / 致命的+高 3 / 解消 1
```

差分は、前回コミットされた `assets.csv` および `risks.csv` との比較で算出します。
初回実行時は比較対象が無いため、差分は表示されません。

### なぜ index.html を直接開けないか

`index.html` は同じ場所にある CSV を読み込む作りですが、
`file://` で開くとブラウザの制限により読み込みに失敗し、
サンプルデータが表示されます。

`index.html` を使いたい場合は簡易サーバを起動してください。

```bash
python3 -m http.server 8000
```

> GitHub Pages をプライベートに公開するには Organization アカウントかつ
> GitHub Enterprise Cloud が必要です。Free/Pro/Team のプライベートリポジトリでは
> `report.html` を使うのが最も手軽です。

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
| 設定上の不備（暗号スイート、SMB署名、匿名FTP等） | nmap NSE | confirmed（応答の内容そのもの） |
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


## サービス識別の強度

`nmap -sV` がバージョンを特定するために送るプローブの数を、
`NMAP_INTENSITY`（0〜9、既定5）で調整できます。

| 値 | 挙動 |
|---|---|
| 0〜2 | 最小限のプローブ。速いが特定できないことが多い |
| **5（既定）** | 実用的な水準 |
| 7 | nmap の既定値。より確実だが時間がかかる |
| 9 | 全プローブを送る。相手への通信量が大きい |

生存ホストが300件を超える場合は自動的に3へ下がります。

**強度を上げてもバージョンが取れないことがあります。**
対象が `ServerTokens Prod` などでバナーを絞っている場合、
外部からバージョンを知る手段がないためです。これは対象側の設定として正しく、
「取れないほうが健全」と考えてください。


## 設定上の不備の検出（NSE）

サービス識別と同時に、nmap の NSE スクリプトで設定の不備を確認します。
いずれも応答を読むだけで、推測を含まないため誤検知が発生しません。

| risk_id | 深刻度 | 内容 | スクリプト |
|---|---|---|---|
| `tls-old-protocol` | critical〜medium | SSLv2 / SSLv3 / TLS 1.0 / 1.1 の有効化 | ssl-enum-ciphers |
| `tls-weak-cipher` | critical〜medium | RC4 / DES / 3DES / NULL / EXPORT / 匿名鍵交換 / MD5 | ssl-enum-ciphers |
| `tls-weak-config` | high | nmap の総合評価が最低水準 | ssl-enum-ciphers |
| `ssh-weak-algorithm` | medium | DH group1、ssh-rsa(SHA-1)、HMAC-MD5、Arcfour、3DES-CBC | ssh2-enum-algos |
| `smb-signing-not-required` | medium | SMB署名が必須になっていない | smb2-security-mode |
| `ftp-anonymous-login` | high | 匿名FTPログインが可能 | ftp-anon |
| `rdp-info-disclosure` | medium | RDPがドメイン名・ホスト名を開示 | rdp-ntlm-info |

**この領域は、構成情報に基づく脆弱性管理では検出できません。**
パッケージのバージョンが最新でも、設定が危険というケースを補います。

実行するスクリプトはいずれも参照系で、`--script-timeout 40s` を設定しています。
対象への負荷は限定的ですが、通信は発生します。
