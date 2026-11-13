"""② 書いた直後の検査（基本設計書 3.4）。警告はすぐ伝え、助言は覚えておく。"""
import os

from . import checks, core

# API の入口を書いたことを知らせる助言（基本設計書 3.12）。助言のうちこれだけは、
# 認可を確かめてもらうために Claude にも伝える。作業は止めない。同じファイルではセッションで1回だけ
AUTHZ_RULE = "R-020"
AUTHZ_HINT = ("→ 「ログインした利用者 A が、利用者 B のデータの ID を指定して呼んだら、何が止めるか」を確かめ、"
              "気になる点があれば利用者に一言伝えてください。他人のデータにアクセスできないことを確かめるテストも"
              "提案してください。確かめ方とテストの例: %s")


def run(ctx):
    ref = ctx.target
    if ctx.tool not in ("Write", "Edit") or ref is None or ref.excluded:
        return None

    f, state = core.open_state(ctx)
    try:
        findings, missing = checks.scan_file(ctx, ref, state.get("baseline"))

        notified = set(state.get("notified") or [])
        pending = state.get("pending_advice") or []
        turn_warns = state.get("turn_warns") or []
        to_notify = {}  # ルール ID → 行番号の一覧
        authz_rows = []
        authz_files = set(state.get("authz_notified_files") or [])

        for item in findings:
            if item["fp"] in notified:
                continue  # 同じ指摘は、このセッションで1回だけ
            notified.add(item["fp"])
            entry = {"rule": item["rule"], "tool": item["tool"], "tool_rule": item["code"],
                     "file": ref.rel_path, "line": item["line"], "fp": item["fp"]}

            if item["severity"] == "advise" or not item["rule"]:
                pending.append(entry)  # 助言は作業の区切りのまとめに載せる
                if item["rule"] == AUTHZ_RULE and ref.rel_path not in authz_files:
                    authz_rows.append(item["line"])
                continue

            to_notify.setdefault(item["rule"], []).append(item["line"])
            turn_warns.append(dict(entry, status="open"))
            core.record(ctx, file=ref.rel_path, timing="post", rule=item["rule"], severity="warn",
                        tool=item["tool"], tool_rule=item["code"], line=item["line"], fp=item["fp"],
                        action="notified")

        blocks = [
            core.notice("警告", rule_id, ctx.rule(rule_id), core.where_text(ref.rel_path, rows), [core.EXPLAIN_FIRST])
            for rule_id, rows in to_notify.items()
        ]

        if authz_rows and ctx.rule(AUTHZ_RULE):
            authz_files.add(ref.rel_path)
            guide = os.path.join(core.PLUGIN_ROOT, "skills", "senpai", "authz.md")
            blocks.append(core.notice("助言", AUTHZ_RULE, ctx.rule(AUTHZ_RULE), core.where_text(ref.rel_path, authz_rows),
                                      [AUTHZ_HINT % guide]))

        if missing and not state.get("tool_missing_notified"):
            state["tool_missing_notified"] = True
            blocks.append("[security-kit] 助言: 検査ツール（%s）が入っていないため、一部の検査を飛ばしました。"
                          % "、".join(missing))
            core.record(ctx, file=ref.rel_path, timing="post", action="skipped", tool=",".join(missing))

        state["notified"] = sorted(notified)
        state["pending_advice"] = pending
        state["turn_warns"] = turn_warns
        state["authz_notified_files"] = sorted(authz_files)
        if ref.in_project:
            state["changed_files"] = sorted(set(state.get("changed_files") or []) | {ref.rel_path})
    finally:
        core.save_state(f, state)

    if not blocks:
        return None
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": "\n\n".join(blocks)}}
