# クラウド管理者の方へ ― AWS CloudShell での CSV 出力手順

## お願いしたいこと

外部公開資産の棚卸しのため、**AWSの構成情報をCSVで出力**していただきたく、
手順をまとめました。

- **所要時間：5〜15分**（対象リージョン数によります）
- **AWSの認証情報を渡していただく必要はありません**
- 実行するのは参照系のAPIのみです（作成・変更・削除は一切行いません）
- **ブラウザだけで完結**します。PCへのインストールは不要です

出力されるCSVを、中身を確認したうえでお渡しください。

---

## 1. CloudShell を開く

1. AWS マネジメントコンソールにログイン
2. 画面上部の検索窓の右にある **ターミナルのアイコン**（`>_`）をクリック
   （または検索窓に `CloudShell` と入力）
3. 黒い画面が起動するまで数十秒待つ

CloudShell には AWS CLI が最初から入っており、**いまログインしている権限が
そのまま使えます**。認証設定は不要です。

> 起動できない場合、IAMに `AWSCloudShellFullAccess` が必要です。

---

## 2. スクリプトを配置する

`cloud-export.sh` を CloudShell に持ち込みます。方法は2つあります。

**方法A：ファイルをアップロード**

画面右上の **Actions → Upload file** から `cloud-export.sh` を選択。

**方法B：エディタに貼り付け**

```bash
nano cloud-export.sh
```

を実行し、スクリプトの中身を貼り付けて `Ctrl+O` → `Enter` → `Ctrl+X`。

> CloudShell は複数行の貼り付け時に確認ダイアログを出します（Safe Paste）。
> 内容を確認して「Paste」を押してください。

---

## 3. 中身を確認する

実行前に、何をするスクリプトかご確認ください。

```bash
less cloud-export.sh
```

`aws ec2 describe-...` のような**参照系のコマンドのみ**で構成されています。
`create` / `delete` / `put` / `modify` は1つも含まれていません。

次のコマンドで確認できます（何も出力されなければ変更系は皆無です）。

```bash
grep -nE 'aws [a-z0-9-]+ (create|delete|put|update|modify|terminate|remove)' cloud-export.sh
```

---

## 4. 実行する

```bash
bash cloud-export.sh
```

進捗が表示されます。

```
== 実行アカウント ==========================================
== グローバル ==============================================
  CloudFront ... ok
  Route53 (公開ゾーン) ... 3 件
  S3 (公開設定のバケット) ... 1 件
== ap-northeast-1 ==========================================
  ALB / NLB ... ok
  ...
```

### 時間がかかる場合

全リージョンを対象にすると時間がかかります。使用中のリージョンだけに
絞ると数分で終わります。

```bash
REGIONS="ap-northeast-1 us-east-1" bash cloud-export.sh
```

> CloudShell は20〜30分の無操作でセッションが切れます。
> 実行中は画面を開いたままにしてください。

---

## 5. 出力を確認する

3つのファイルができます。

```bash
head -20 cloud-manual.csv
head -20 cloud-risks-manual.csv
cat route53-domains.txt
```

### cloud-manual.csv — 外部公開されているリソース

| 列 | 内容 |
|---|---|
| resource_type | alb / nlb / clb / cloudfront / ec2 / eip / rds / s3 / apigateway |
| resource_id | リソースのARNまたはID |
| dns_name | 割り当てられているDNS名 |
| ip | パブリックIP |
| region | リージョン |

### cloud-risks-manual.csv — 設定上のリスク

| risk_id | 内容 |
|---|---|
| sg-open-to-world | セキュリティグループが 0.0.0.0/0 に開放 |
| s3-public-access | S3バケットが公開設定 |
| rds-publicly-accessible | RDSが外部公開 |
| rds-not-encrypted / ebs-not-encrypted | 未暗号化 |
| acm-cert-expiring | 証明書が30日以内に失効 |
| iam-key-stale | アクセスキーが180日以上未更新 |

### route53-domains.txt — 公開DNSゾーン

調査対象ドメインの一覧です。

---

## 6. 内容を精査してからお渡しください

**含まれないもの**

- S3バケットの中身・オブジェクト
- データベースの中身
- アクセスキーやパスワード等の秘密情報
- IAMポリシーの詳細

**含まれるもの**

- リソース名・ARN・DNS名・パブリックIP
- セキュリティグループ名と開放ポート
- IAMユーザー名（キーが古い場合のみ）

リソース名やドメイン名に機密性がある場合は、該当行を削除していただいて
構いません。その分は検出対象から外れるだけです。

---

## 7. ダウンロードする

画面右上の **Actions → Download file** を選び、フルパスを入力します。

```
/home/cloudshell-user/cloud-manual.csv
/home/cloudshell-user/cloud-risks-manual.csv
```

パスは実行完了時に画面へ表示されます。

---

## 次回以降

CloudShell のホームディレクトリは**リージョンごとに1GBまで内容が保持される**ため、
スクリプトは次回もそのまま残っています。

```bash
bash cloud-export.sh
```

を再実行するだけです。**2回目以降は2〜3分**で終わります。

更新頻度は月次でも十分です。CSVが古い場合、その間に増えたリソースが
「未マップ」として検出されるだけで、実害はありません。

---

## ご不明な点

スクリプトの内容や、出力される情報についてご懸念があれば
遠慮なくお知らせください。項目を削ることも可能です。
