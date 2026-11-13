#!/usr/bin/env python3
"""報告コマンドの下書きに使う情報（基本設計書 3.9）。report Skill から呼ぶ。

使い方: python3 -I -S report.py [セッション ID]

このセッションの直近の指摘と、キットの版、報告先のリポジトリを表示する。
Issue はキットのリポジトリ（全案件で共有）に登録されるので、次のものは表示しない。
- ファイルの場所（ファイルの種類だけを出す）
- コードの中身、秘密情報
- プロジェクト名
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

TIMING = {"pre": "書く前", "post": "書いた直後", "stop": "作業の区切り", "ai": "AI レビュー"}
LIMIT = 10


def recent_findings(session):
    """このセッションで出た指摘の記録（新しい順）。"""
    from kit import core
    d = os.path.join(core.state_dir(), "log")
    try:
        names = sorted(n for n in os.listdir(d) if n.endswith(".jsonl"))[-2:]  # 今月と先月
    except OSError:
        return []
    rows = []
    for name in names:
        with open(os.path.join(d, name), encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if (isinstance(row, dict) and row.get("session") == session and "severity" in row
                        and (row.get("rule") or row.get("tool_rule"))):
                    rows.append(row)
    return rows[::-1][:LIMIT]


def file_kind(path):
    """ファイルの場所から、種類（拡張子）だけを取り出す。"""
    name = os.path.basename(str(path or ""))
    ext = os.path.splitext(name)[1]
    if ext:
        return ext
    return name if name.startswith(".") and len(name) <= 20 else "（拡張子なし）"


def main(argv):
    from kit import core

    session = re.sub(r"[^A-Za-z0-9_-]", "", argv[0] if argv else "")[:64]
    manifest = core.load_json(os.path.join(core.PLUGIN_ROOT, ".claude-plugin", "plugin.json"), {})
    rules = core.load_json(os.path.join(core.PLUGIN_ROOT, "data", "rules.json"), {}).get("rules", {})
    repo_url = str(manifest.get("repository") or "")
    m = re.match(r"https://github\.com/([\w.-]+/[\w.-]+?)(?:\.git)?/?$", repo_url)

    out = [
        "[security-kit] 報告の下書きに使う情報",
        "キットの版: %s" % manifest.get("version", "不明"),
        "報告先: %s" % (repo_url or "不明（plugin.json に repository が無い）"),
    ]
    if m:
        out.append("gh で使う指定: --repo %s" % m.group(1))

    rows = recent_findings(session) if session else []
    if not rows:
        out.append("このセッションの指摘の記録はありません。")
    else:
        out.append("このセッションの直近の指摘（新しい順。最大%d件）:" % LIMIT)
        for n, r in enumerate(rows, 1):
            rid = r.get("rule") or ""
            name = (rules.get(rid) or {}).get("name", "")
            label = core.SEVERITY_LABEL.get(r.get("severity"), r.get("severity", ""))
            out.append("%d. %s / %s / %s / %s %s / ファイルの種類 %s" % (
                n, TIMING.get(r.get("timing"), r.get("timing", "")), label,
                ("%s %s" % (rid, name)).strip() or "ルールなし", r.get("tool", ""), r.get("tool_rule", ""),
                file_kind(r.get("file"))))
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as e:  # noqa: BLE001  報告の流れを止めない
        print("[security-kit] 記録を読めませんでした（%s）。指摘の情報なしで下書きを作ってください。" % type(e).__name__)
        sys.exit(0)
