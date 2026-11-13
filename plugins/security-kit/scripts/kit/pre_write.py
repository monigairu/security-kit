"""① 書く前の検査（基本設計書 3.3）。秘密情報があれば書き込みを止める。"""
from . import core, secrets

RULE_ID = "R-001"


def run(ctx):
    ref = ctx.target
    if ctx.tool not in ("Write", "Edit") or ref is None or ref.excluded:
        return None

    # Write は新しい中身の全体、Edit は書き換え後の部分を検査する
    text = ctx.tool_input.get("content") if ctx.tool == "Write" else ctx.tool_input.get("new_string")
    if not text:
        return None

    hits = secrets.scan(text, ctx)
    rule = ctx.rule(RULE_ID)
    if not hits or not rule:
        return None

    enforce = ctx.mode == "enforce"
    for h in hits:
        core.record(
            ctx, file=ref.rel_path, timing="pre", rule=RULE_ID, severity="block", tool=h["tool"],
            tool_rule=h["kind"], line=h["line"],
            # 秘密情報の指紋には、行の中身を使わない（データ設計書 8.3）
            fp=core.fingerprint(RULE_ID, ref.rel_path, str(h["line"])),
            action="blocked" if enforce else "notified",
        )

    places = "、".join("%d行目（種類: %s）" % (h["line"], h["kind"]) for h in hits[:5])
    where = "%s（書き込もうとした内容の %s）" % (ref.rel_path, places)
    escape = (
        "誤検知のとき: テスト用のダミーなどで問題ないかを、利用者に確かめてください。利用者が認めたときだけ、"
        "その行の末尾に「gitleaks:allow」と理由をコメントで書いて除外できます。印の追加は PR でレビューされます。"
    )

    if enforce:
        msg = core.notice("止めました", RULE_ID, rule, where, [escape, core.BLOCKED])
        return {"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": msg,
        }}

    # 警告モード: 止めずに伝える（基本設計書 3.10）
    msg = core.notice("警告（警告モードのため止めていません）", RULE_ID, rule, where, [escape, core.EXPLAIN_FIRST])
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": msg}}
