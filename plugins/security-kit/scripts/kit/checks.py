"""1つのファイルの検査（Ruff と、キット独自の簡易チェック）。

書いた直後の検査と、作業の区切りの検査の両方から使う。
"""
import fnmatch
import json
import os
import re
import subprocess

from . import core, gitstate


def scan_file(ctx, ref, baseline, whole=False):
    """ファイルを検査し、このターンで変えた行の指摘だけを返す。

    whole=True のときは、ファイル全体の指摘を返す（相談コマンドで、ファイルを名指しされたとき）。
    返す形: (指摘の一覧, 入っていなかった検査ツールの一覧)
    指摘: {"rule": ルール ID か None, "severity", "tool", "code", "line", "fp"}
    """
    lines = core.read_lines(ref.abs_path)
    raw, missing = [], []

    if ref.abs_path.endswith((".py", ".pyi")):
        result = _ruff(ctx, ref)
        if result is None:
            missing.append("ruff")
        else:
            raw += result
    raw += _kit_checks(ctx, ref, lines)

    # このターンで変えた行に重なる指摘だけを残す（以前からある問題は伝えない）
    ranges = None if whole else gitstate.line_ranges(ctx.root, baseline, ref.abs_path, ref.rel_path)
    if ranges is not None:
        raw = [f for f in raw if any(a <= f["line"] <= b for a, b in ranges)]

    out = []
    for item in raw:
        rule_id, rule = ctx.rule_for(item["tool"], item["code"])
        content = lines[item["line"] - 1] if 0 < item["line"] <= len(lines) else ""
        out.append({
            "rule": rule_id,
            "severity": rule["severity"] if rule else "advise",
            "tool": item["tool"],
            "code": item["code"],
            "line": item["line"],
            # 行番号ではなく行の中身から作る。上に行が増えても同じ指摘として扱うため
            "fp": core.fingerprint(rule_id or item["code"], ref.rel_path, re.sub(r"\s+", "", content)),
        })
    return out, missing


def _ruff(ctx, ref):
    """Ruff のセキュリティルールを、このファイルだけにかける。Ruff が無ければ None。"""
    exe = core.which("ruff")
    if not exe:
        return None
    cmd = [exe, "check", "--select", "S", "--output-format", "json", "--no-cache", "--isolated",
           "--exit-zero", "--quiet", ref.abs_path]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, cwd=ctx.root)
        items = json.loads(r.stdout or "[]")
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return []
    # Ruff の説明文には変数名などコードの中身が入ることがあるので、番号と行だけを使う
    return [
        {"tool": "ruff", "code": i["code"], "line": int((i.get("location") or {}).get("row") or 0)}
        for i in items
        if (i.get("code") or "").startswith("S")  # 文法エラーなど、番号の無い結果は除く
    ]


def _kit_checks(ctx, ref, lines):
    """キット独自の簡易チェック（正規表現）。対象のファイルは paths で絞る。"""
    name = os.path.basename(ref.abs_path)
    out = []
    for check in ctx.rules.get("kit_checks") or []:
        globs = check.get("paths") or ["*"]
        if not any(fnmatch.fnmatch(ref.rel_path, g) or fnmatch.fnmatch(name, g) for g in globs):
            continue
        pat = re.compile(check["pattern"])
        for n, line in enumerate(lines, 1):
            if core.ALLOW_MARK not in line and pat.search(line):
                out.append({"tool": "kit", "code": check["id"], "line": n})
    return out
