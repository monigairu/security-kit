"""秘密情報の検査。

書く前の検査では、キット内蔵の判定（scan）を使う。gitleaks は起動するだけで
約1秒かかるため、書き込みのたびに動く場面では使わない（2026-11-13 の実測）。
作業の区切りでは、時間に余裕があるので gitleaks の全ルールをかける（gitleaks_files）。

内蔵の判定が見るのは、決まった書き出しを持つなど「形だけで秘密情報とわかるもの」に限る。
誤って止めることがほぼ無いものだけを止めるため。
"""
import json
import re
import subprocess

from . import core

# 検査ツールの gitleaks と同じ印を使う。書く前・コミット前・PR 時で判定を揃えるため
ALLOW_MARK = "gitleaks:allow"

# 説明用の見本として広く使われている値は対象にしない（例: AWS の文書にある ...EXAMPLE）
SAMPLE_SUFFIX = "EXAMPLE"


def _patterns(ctx):
    return [(p["id"], re.compile(p["pattern"])) for p in ctx.rules.get("secret_patterns") or []]


def scan(text, ctx):
    """秘密情報らしき箇所の一覧を返す。値そのものは返さない。

    返す形: [{"line": 行番号, "kind": 種類, "tool": "kit-secret"}]
    """
    patterns = _patterns(ctx)
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        if ALLOW_MARK in line:
            continue
        for kind, pat in patterns:
            m = pat.search(line)
            if m and not m.group(0).endswith(SAMPLE_SUFFIX):
                hits.append({"line": n, "kind": kind, "tool": "kit-secret"})
                break
    return hits


def redact(text, ctx):
    """文章の中の秘密情報らしき部分を伏せ字にする（AI レビューに送る前に使う）。"""
    for _kind, pat in _patterns(ctx):
        text = pat.sub("[秘密情報のため伏せ字]", text)
    return text


def looks_secret(text, ctx):
    return any(pat.search(text) for _kind, pat in _patterns(ctx))


def gitleaks_files(ctx, refs):
    """gitleaks の全ルールで、複数のファイルをまとめて検査する。gitleaks が無ければ None。

    起動に時間がかかるので、ファイルをつなげて1回だけ呼ぶ。
    返す形: [{"file": 相対パス, "line": 行番号, "kind": 種類}]
    """
    exe = core.which("gitleaks")
    if not exe:
        return None

    parts, table, total = [], [], 0  # table: (つなげた文章での開始行, 行数, 相対パス)
    for ref in refs:
        lines = core.read_lines(ref.abs_path, limit=500_000)
        if not lines or total + len(lines) > 60_000:
            continue
        table.append((total + 1, len(lines), ref.rel_path))
        parts.extend(lines)
        total += len(lines)
    if not parts:
        return []

    cmd = [exe, "stdin", "--no-banner", "--no-color", "--log-level", "error",
           "--redact",  # 結果に秘密情報そのものを出させない
           "--report-format", "json", "--report-path", "-", "--exit-code", "0"]
    try:
        r = subprocess.run(cmd, input="\n".join(parts) + "\n", capture_output=True, text=True,
                           timeout=30, cwd=ctx.root)
        items = json.loads(r.stdout or "[]")
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return []

    hits = []
    for i in items:
        n = int(i.get("StartLine") or 0)
        for start, count, rel in table:
            if start <= n < start + count:
                hits.append({"file": rel, "line": n - start + 1, "kind": str(i.get("RuleID") or "secret")})
                break
    return hits
