# security-kit
AI開発セキュリティ支援キット（仮称）

Claude Code などの AI コーディングツールを使った開発で、セキュリティに強い先輩のように「そこ危ないよ」と声をかけ、理由と直し方を伝えるキットです。重大な事故（秘密情報の漏えい、悪性パッケージの導入など）だけはその場で止め、ルールは YAML で一元管理します。

## いまの状態

設計と試作の段階です。次の仕組みが試作として動きます。

| タイミング | すること |
|---|---|
| 書く前 | 秘密情報（API キーなど）を書こうとしたら、書き込みを止める |
| 書いた直後 | 危ない書き方を見つけたら、すぐ Claude に伝える（Python は Ruff、ほかの言語は独自の簡易チェック） |
| 作業の区切り | 伝えた警告が直ったかを確かめ、このターンのまとめを表示する |
| 作業の区切り（背景） | このターンの変更を AI がレビューし、重大な指摘があれば Claude を呼び戻す |
| コミットの直後（背景） | コミットされた変更を、AI が関係するファイルもたどってレビューする |

Anthropic 公式の security-guidance プラグイン（Apache-2.0）と同じ役割を、このキットだけで受け持ちます。公式プラグインの考え方を参考にしており、コードは流用していません。両方を入れると注意が重なるので、このキットを使うときは公式プラグインを止めてください。

## 文書

| 文書 | 中身 |
|---|---|
| [要件定義書](docs/requirements/requirements.md) | 何を作るか |
| [脅威モデル](docs/requirements/threat-model.md) | どの脅威をどこまで防げるか |
| [基本設計書](docs/design/basic-design.md) | どう作るか |
| [データ設計書](docs/design/data-design.md) | ルールや記録の形 |
| [試作の記録](docs/design/prototype-notes.md) | 試作で確かめたことと、実測した時間 |

## フォルダ構成

フォルダは、最初のファイルを置くときに作ります（空のフォルダは作りません）。全体の予定は、基本設計書の 2.2 にあります。

```
security-kit/
├── .claude-plugin/
│   └── marketplace.json     社内向けプラグインの配布元の定義
├── plugins/
│   └── security-kit/        プラグイン本体
│       ├── hooks/           フックの登録
│       ├── scripts/         フックのスクリプト（Python の標準ライブラリだけ）
│       └── data/rules.json  ルールデータ（試作では手書き）
├── tests/                   テスト
└── docs/                    文書
```

## 試作を動かす

必要なもの：Python 3、git。次のものは、無くても動きます（その検査だけ飛ばします）。

- Ruff：書いた直後の Python の検査
- gitleaks：作業の区切りの、秘密情報の検査
- Claude Code へのサインイン：AI レビュー

テストを実行する。

```bash
python3 -m unittest discover -s tests -v
```

プラグインの書式を検査する。

```bash
claude plugin validate plugins/security-kit
```

インストールせずに、試したいプロジェクトのフォルダで読み込んで動かす。

```bash
claude --plugin-dir /path/to/security-kit/plugins/security-kit
```

## プロジェクトごとの設定

プロジェクトの `.claude/security-kit.json` で、動かし方を変えられます。無ければ既定の動きになります。

```json
{
  "mode": "warn",
  "exclude": ["tests/fixtures/*"],
  "ai_review": { "stop": true, "commit": true, "model": "sonnet", "max_per_session": 20 }
}
```

| 項目 | 意味 | 既定 |
|---|---|---|
| `mode` | `warn` にすると、書き込みを止めずに警告だけにする | 止める |
| `exclude` | 検査から外すフォルダ | なし |
| `ai_review.stop` | 作業の区切りの AI レビューをするか | する |
| `ai_review.commit` | コミットの直後の AI レビューをするか | する |
| `ai_review.model` | AI レビューに使うモデル | sonnet |
| `ai_review.max_per_session` | 1つのセッションでの AI レビューの回数の上限 | 20 |

その案件だけの決まりを AI レビューに読ませたいときは、`.claude/security-kit-guidance.md` に書きます。

## 除外の印

指摘が当てはまらない場合は、その行に印と理由を書くと除外できます。印の追加は PR でレビューします。

| 指摘の種類 | 印 |
|---|---|
| 秘密情報 | `gitleaks:allow` |
| Ruff の指摘（Python） | `# noqa: 番号` |
| キット独自の簡易チェック、AI レビュー | `security-kit:allow` |
