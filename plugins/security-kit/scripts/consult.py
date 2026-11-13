#!/usr/bin/env python3
"""相談コマンドの検査（基本設計書 3.8）。consult Skill から呼ぶ。

使い方: python3 -I -S consult.py [ファイルやフォルダ ...]

  対象を書かないとき   まだコミットしていない変更を検査する（変えた行だけ）
  対象を書いたとき     そのファイルの全体を検査する（以前からある問題も含める）

Ruff、キット独自の簡易チェック、キット内蔵の秘密情報の判定、gitleaks（入っていれば）をかけ、
指摘をルール ID と通知文の型で表示する。
- ファイルの中身は表示しない（NFR-13）。
- ファイルは書き換えない。記録も残さない。
- 終了コードは常に 0（相談の流れを止めないため）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

MAX_FILES = 200
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


def _changed_paths(ctx):
    """まだコミットしていない変更のあるファイル（管理外の新しいファイルも含む）。"""
    from kit import gitstate
    names = []
    if gitstate.head(ctx.root):
        r = gitstate._git(ctx.root, "diff", "--name-only", "-z", "--no-renames", "HEAD")
        if gitstate._ok(r):
            names += [n for n in r.stdout.split("\0") if n]
    else:
        r = gitstate._git(ctx.root, "ls-files", "-z")
        if gitstate._ok(r):
            names += [n for n in r.stdout.split("\0") if n]
    r = gitstate._git(ctx.root, "ls-files", "--others", "--exclude-standard", "-z")
    if gitstate._ok(r):
        names += [n for n in r.stdout.split("\0") if n]
    return [os.path.join(ctx.root, n) for n in dict.fromkeys(names)]


def _expand(ctx, args):
    """名指しされたファイルとフォルダを、ファイルの一覧にする。"""
    from kit import gitstate
    out = []
    for a in args:
        p = a if os.path.isabs(a) else os.path.join(os.getcwd(), a)
        if os.path.isdir(p):
            r = gitstate._git(p, "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--full-name", ".")
            top = gitstate._git(p, "rev-parse", "--show-toplevel")
            if gitstate._ok(r) and gitstate._ok(top):
                base = top.stdout.strip()
                out += [os.path.join(base, n) for n in r.stdout.split("\0") if n]
            else:
                for d, dirs, files in os.walk(p):
                    dirs[:] = [x for x in dirs if x not in SKIP_DIRS and not x.startswith(".")]
                    out += [os.path.join(d, f) for f in files]
        else:
            out.append(p)
    return out


def main(argv):
    from kit import checks, core, gitstate, secrets

    ctx = core.Context({"cwd": os.getcwd(), "session_id": "consult"})
    whole = bool(argv)
    paths = _expand(ctx, argv) if whole else _changed_paths(ctx)

    refs, notes = [], []
    for p in paths:
        ref = ctx.file(p)
        if not ref.in_project:
            notes.append("プロジェクトの外のファイルは検査しない: " + ref.rel_path)
        elif not os.path.isfile(ref.abs_path):
            notes.append("見つからない: " + ref.rel_path)
        elif ref.excluded and not whole:
            continue  # 検査から外したフォルダ（名指しされたときは検査する）
        else:
            refs.append(ref)
    if len(refs) > MAX_FILES:
        notes.append("対象が多いため、最初の %d ファイルだけを検査した" % MAX_FILES)
        refs = refs[:MAX_FILES]

    found, missing = [], set()
    secret_hits = {}  # (ファイル, 行) → 種類
    for ref in refs:
        items, miss = checks.scan_file(ctx, ref, None, whole=whole)
        found += [dict(i, file=ref.rel_path) for i in items]
        missing.update(miss)
        ranges = None if whole else gitstate.line_ranges(ctx.root, None, ref.abs_path, ref.rel_path)
        text = "\n".join(core.read_lines(ref.abs_path))
        for h in secrets.scan(text, ctx):
            if ranges is None or any(a <= h["line"] <= b for a, b in ranges):
                secret_hits[(ref.rel_path, h["line"])] = h["kind"]

    leaks = secrets.gitleaks_files(ctx, refs) if refs else []
    if leaks is None:
        missing.add("gitleaks")
    for h in leaks or []:
        ref = ctx.file(h["file"])
        ranges = None if whole else gitstate.line_ranges(ctx.root, None, ref.abs_path, ref.rel_path)
        if ranges is None or any(a <= h["line"] <= b for a, b in ranges):
            secret_hits.setdefault((h["file"], h["line"]), h["kind"])

    secret_rule = ctx.rule_for("kit-secret", "*")[0]
    for (rel, line), _kind in secret_hits.items():
        found.append({"rule": secret_rule, "severity": "block", "tool": "kit-secret", "code": "*",
                      "line": line, "file": rel})

    print(report(ctx, found, refs, whole, sorted(missing), notes))
    return 0


def report(ctx, found, refs, whole, missing, notes):
    from kit import core

    docs = os.path.join(core.PLUGIN_ROOT, "skills", "senpai", "rules")
    head = [
        "[security-kit] 相談の検査結果",
        "対象: %s（%d ファイル）" % ("名指しされたファイルの全体" if whole else "まだコミットしていない変更の、変えた行だけ", len(refs)),
    ]
    if missing:
        head.append("入っていないため飛ばした検査ツール: " + "、".join(missing))
    head += notes

    order = {"block": 0, "warn": 1, "advise": 2}
    groups = {}  # (重大度の順, ルール ID か番号, ファイル) → 行の一覧
    for f in found:
        key = (order.get(f["severity"], 3), f["rule"] or "%s %s" % (f["tool"], f["code"]), f["file"])
        groups.setdefault(key, []).append(f["line"])

    blocks = []
    for (_, rid, rel), rows in sorted(groups.items()):
        rule = ctx.rule(rid)
        where = core.where_text(rel, rows)
        if rule:
            blocks.append(core.notice(core.SEVERITY_LABEL[rule["severity"]], rid, rule, where,
                                      ["説明: " + os.path.join(docs, rid + ".md")], more=False))
        else:
            blocks.append("[security-kit] 助言 %s（自社のルールに対応付けのない指摘）\n場所: %s" % (rid, where))

    tail = [
        "指摘: %d 件" % len(groups) if groups else "検査ツールによる指摘はありませんでした。",
        "検査ツールで見つけられないこと（認可の漏れなど）は、ルールの説明を読んで確かめてください。",
        "ルールの一覧: " + os.path.join(docs, "index.md"),
    ]
    return "\n\n".join(["\n".join(head)] + blocks + ["\n".join(tail)])


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as e:  # noqa: BLE001  相談の流れを止めない
        print("[security-kit] 検査の途中でエラーが起きました（%s）。検査ツールの結果なしで相談を続けてください。" % type(e).__name__)
        sys.exit(0)
