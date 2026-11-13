---
name: init
description: このプロジェクトに security-kit の設定（禁止ルール、キットの有効化、CLAUDE.md と AGENTS.md への追記など）を置く。
disable-model-invocation: true
disallowed-tools: Write, Edit, NotebookEdit
allowed-tools: Bash(python3 -I -S "${CLAUDE_PLUGIN_ROOT}/scripts/init.py")
---

# security-kit の初期化

設定ファイルは、下のスクリプトだけで書き込む。Write や Edit で直接書かない。

## 手順

1. 予定を表示する。この時点では何も書き込まれない。

   ```
   python3 -I -S "${CLAUDE_PLUGIN_ROOT}/scripts/init.py"
   ```

2. 予定を利用者に示す。
   - ファイルごとに、何をするか（作る／キットの部分を足す／変える／変更なし／変えない）と理由を書く。
   - すでにあるファイルを変えるときは、表示された差分をそのまま見せる。省略しない。
   - 新しく作るファイルは、何のためのファイルかを1行で説明する。
3. 「書き込んでよいですか？」と聞き、利用者の返事を待つ。了承が無ければ、何もせずに終える。
4. 了承を得たら、予定の最後に表示されたコマンド（`--apply` と確認番号つき）をそのまま実行する。
   - 「確認番号が予定と合いません」と表示されたら、1 からやり直す。
5. 結果と、表示された「次にすること」を利用者に伝える。

## してはいけないこと

- 予定に無いファイルを変えない。
- 「変えない」とされたファイルを、自分で直さない。理由を伝え、直すかどうかは利用者に任せる。
- 確認番号を自分で作ったり、変えたりしない。

## 各ファイルの役割（説明用）

| ファイル | 役割 |
|---|---|
| `.claude/settings.json` | .env などの読み取り禁止、security-kit の有効化、役割が重なる公式の security-guidance プラグインを止める指定 |
| `.claude/security-kit.json` | キットの動かし方。新しく作るときは警告モード（止めずに伝える） |
| `CLAUDE.md` | 指摘を受けたときの振る舞い（説明してから直す、など）と、止めるルール |
| `AGENTS.md` | Claude 以外の AI（Codex など）向けの、ルールとレビューの基準 |
