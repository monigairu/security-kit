#!/usr/bin/env python3
"""security-kit のフックの入口。

使い方: python3 -I -S hook.py <できごと>

  turn-start     利用者が指示を送った時点。作業フォルダの状態を記録する
  pre-write      ① 書く前の検査。秘密情報があれば書き込みを止める
  post-write     ② 書いた直後の検査。警告はすぐ伝え、助言は覚えておく
  stop           ③ 作業の区切りの検査。直ったかを確かめ、まとめを表示する
  ai-review      作業の区切りの AI レビュー（背景で動く）
  commit-review  コミットの直後の AI レビュー（背景で動く）

標準入力から Claude Code のフック入力（JSON）を受け取り、結果を JSON で返す。
Python の標準ライブラリだけで動く（基本設計書 1.3）。

先輩役は開発を止めない方針のため、想定外のエラーでは何も止めずに
終了コード 1（止めないエラー）で終わる。
"""
import json
import os
import sys

# -I で起動するとスクリプトの場所が読み込み先に入らないため、自分で足す
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    # AI レビュー役の中では動かない（レビューがレビューを呼ぶのを防ぐ）
    if os.environ.get("SECURITY_KIT_REVIEWER"):
        return 0

    event = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        data = json.load(sys.stdin)
    except ValueError:
        return 0
    if not isinstance(data, dict):
        return 0

    from kit import core

    ctx = core.Context(data)

    if event == "turn-start":
        from kit import turn_start
        result = turn_start.run(ctx)
    elif event == "pre-write":
        from kit import pre_write
        result = pre_write.run(ctx)
    elif event == "post-write":
        from kit import post_write
        result = post_write.run(ctx)
    elif event == "stop":
        from kit import stop
        result = stop.run(ctx)
    elif event == "ai-review":
        from kit import ai_review
        result = ai_review.run_stop(ctx)
    elif event == "commit-review":
        from kit import ai_review
        result = ai_review.run_commit(ctx)
    else:
        return 0

    if not result:
        return 0
    # 背景で動くフックは (終了コード, 画面に出す情報, Claude に渡す文章) を返す
    code, out, message = result if isinstance(result, tuple) else (0, result, "")
    if message:
        sys.stderr.write(message + "\n")
    if out:
        json.dump(out, sys.stdout, ensure_ascii=False)
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001  想定外のエラーでも開発は止めない
        sys.stderr.write("security-kit: フックでエラーが起きたため検査を飛ばしました（%s）\n" % type(e).__name__)
        sys.exit(1)
