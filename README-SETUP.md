# セットアップ手順（フォルダ不要版）

このリポジトリは **フォルダを使わないフラット構成** です。
GitHub のアップロード画面にファイルをまとめてドラッグするだけで動きます。

ただし **1ファイルだけ例外** があります。GitHub Actions の設定ファイルは
必ず `.github/workflows/` の下に置く決まりなので、これだけは
画面で作成する必要があります（下の手順3）。

---

## 手順1：リポジトリを Private にする

**スキャンを実行する前に必ずやってください。**
Public のままだと自社の資産一覧が全世界に公開されます。

```
Settings タブ → 一番下までスクロール
→ Danger Zone → Change repository visibility → Make private
```

## 手順2：ファイルをアップロードする

1. `https://github.com/あなたのユーザー名/Yusuk8er-easm/upload/main` を開く
2. 解凍したフォルダの中のファイルを**全部選択してドラッグ**
   （フォルダは1つも入っていないので、迷う要素はありません）
3. 「Commit changes」

既に同名のファイルがある場合は上書きされます。
文字化けした `.md` ファイルが残っていたら、後で削除してください
（ファイルをクリック → ゴミ箱アイコン → Commit changes）。

## 手順3：ワークフローファイルを作る（重要）

自動実行の設定ファイルだけは、フォルダの中に置く必要があります。
GitHub の画面では、**ファイル名にスラッシュを入れると自動でフォルダが作られます。**

1. リポジトリのトップページ →「Add file」→「**Create new file**」
2. 画面上部のファイル名の欄に、以下を**そのままコピーして貼り付け**

```
.github/workflows/scan.yml
```

   → 入力すると `.github / workflows /` とフォルダに分かれて表示されます。これが正解です。

3. 下の大きな入力欄に、`WORKFLOW-scan.yml.txt` の中身を**全部コピーして貼り付け**
   （リポジトリ内のそのファイルを開いて、右上のコピーボタンを使うと楽です）
4. 「Commit changes」

### 確認

「Actions」タブを開いて、左側に「Yusuk8er-easm」と表示されていれば成功です。
表示されない場合は、ファイル名のパスが間違っている可能性があります。

## 手順4以降

`GETTING-STARTED.md` の手順3以降（AWSのキー作成）に進んでください。
まず vulnweb.com で試す場合は `PRACTICE.md` を見てください。


---

## ワークフローが「Failure」になるとき

Actions タブに赤い×で「Create scan.yml」のような名前の失敗が出ている場合、
それは**スキャンが失敗したのではなく、ワークフローファイルの書式が不正**という意味です。

失敗した行をクリックすると `Invalid workflow file` というエラーと、
何行目が問題かが表示されます。

よくある原因:

| 症状 | 原因 |
|---|---|
| `Unrecognized named-value: 'secrets'` | `if:` の中で `secrets` を参照している（GitHubの仕様で不可） |
| `mapping values are not allowed` | 貼り付け時にインデント（行頭の空白）が崩れた |
| `did not find expected key` | 本文の貼り付けが途中で切れている |

修正するときは、リポジトリの `.github/workflows/scan.yml` を開いて
鉛筆マークで編集し、`WORKFLOW-scan.yml.txt` の中身で**全部置き換えて**ください。
（編集画面で Ctrl+A → Delete → 貼り付け）
