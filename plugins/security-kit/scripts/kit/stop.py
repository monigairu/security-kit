"""③ 作業の区切りの検査（基本設計書 3.5）。

Claude が応答を終えようとした時点で、このターンで変えたファイルをもう一度検査する。
- 伝えた警告が直ったかを確かめる（直した／未対応）
- 書く前の判定で見つからない種類の秘密情報を、gitleaks の全ルールで探す
- 未対応の警告があれば、1回だけ応答を続けさせる
- 最後に、このターンのまとめを利用者に表示する
"""
import os

from . import checks, core, gitstate, secrets

SECRET_RULE = "R-001"
CLOSING = (
    "→ 利用者に「ひとこと：〜」の形で伝えてから対応してください。"
    "利用者がはっきり指定した書き方で、危険性をすでに伝えてある場合や、当てはまらないと判断した場合は、"
    "その理由を一言伝えて終えてかまいません。"
)
SECRET_ADVICE = (
    "本物の値なら、消すだけでは足りません。その鍵をすぐ無効にして作り直すよう、利用者に伝えてください。"
    "ダミーの値なら、その行に「gitleaks:allow」と理由をコメントで書いてください。"
)


def run(ctx):
    active = bool(ctx.data.get("stop_hook_active"))

    f, state = core.open_state(ctx)
    try:
        baseline = state.get("baseline")
        turn_warns = state.get("turn_warns") or []
        pending = state.get("pending_advice") or []
        refs = _changed_refs(ctx, state, baseline)
        if not refs and not turn_warns and not pending:
            return None

        notified = set(state.get("notified") or [])
        current = set()  # いまも残っている指摘の指紋

        for ref in refs:
            findings, _missing = checks.scan_file(ctx, ref, baseline)
            for item in findings:
                current.add(item["fp"])
                if item["fp"] in notified:
                    continue
                # Claude がコマンドで書き換えたファイルなど、書いた直後の検査を通らなかった分
                notified.add(item["fp"])
                entry = {"rule": item["rule"], "tool": item["tool"], "tool_rule": item["code"],
                         "file": ref.rel_path, "line": item["line"], "fp": item["fp"]}
                if item["severity"] == "advise" or not item["rule"]:
                    pending.append(entry)
                else:
                    turn_warns.append(dict(entry, status="open"))
                    core.record(ctx, file=ref.rel_path, timing="stop", rule=item["rule"], severity="warn",
                                tool=item["tool"], tool_rule=item["code"], line=item["line"], fp=item["fp"],
                                action="notified")

        for hit in secrets.gitleaks_files(ctx, refs) or []:
            ref = ctx.file(hit["file"])
            ranges = gitstate.line_ranges(ctx.root, baseline, ref.abs_path, ref.rel_path)
            if ranges is not None and not any(a <= hit["line"] <= b for a, b in ranges):
                continue  # 以前からある分は対象にしない
            fp = core.fingerprint(SECRET_RULE, ref.rel_path, str(hit["line"]))
            current.add(fp)
            if fp in notified:
                continue
            notified.add(fp)
            turn_warns.append({"rule": SECRET_RULE, "tool": "gitleaks", "tool_rule": hit["kind"],
                               "file": ref.rel_path, "line": hit["line"], "fp": fp, "status": "open"})
            core.record(ctx, file=ref.rel_path, timing="stop", rule=SECRET_RULE, severity="warn",
                        tool="gitleaks", tool_rule=hit["kind"], line=hit["line"], fp=fp, action="notified")

        # 伝えた警告が直ったかを確かめる（AI レビューの指摘は機械的に確かめられないので対象外）
        for w in turn_warns:
            if w.get("status") == "ai":
                continue
            status = "open" if w["fp"] in current else "fixed"
            if status == "fixed" and w.get("status") != "fixed":
                core.record(ctx, file=w["file"], timing="stop", rule=w["rule"], tool=w["tool"],
                            tool_rule=w["tool_rule"], line=w["line"], fp=w["fp"],
                            action="rechecked", outcome="fixed")
            w["status"] = status

        still_open = [w for w in turn_warns if w.get("status") == "open"]
        out = {}
        if still_open and not active and not state.get("stop_continued"):
            # 未対応の警告があるので、1回だけ応答を続けさせる
            state["stop_continued"] = True
            out = {"decision": "block", "reason": _open_notice(ctx, still_open)}
        else:
            for w in still_open:
                core.record(ctx, file=w["file"], timing="stop", rule=w["rule"], tool=w["tool"],
                            tool_rule=w["tool_rule"], line=w["line"], fp=w["fp"],
                            action="rechecked", outcome="open")
            summary = _summary(ctx, turn_warns, pending)
            if summary:
                out = {"systemMessage": summary}
            turn_warns, pending = [], []

        state["notified"] = sorted(notified)
        state["turn_warns"] = turn_warns
        state["pending_advice"] = pending
    finally:
        core.save_state(f, state)
    return out or None


def _changed_refs(ctx, state, baseline):
    """このターンで変わったファイル。Claude がコマンドで書き換えた分も拾う。"""
    names = set(state.get("changed_files") or [])
    if baseline and baseline.get("tree"):
        end = gitstate.snapshot(ctx.root)
        if end:
            names |= set(gitstate.changed_names(ctx.root, baseline["tree"], end["tree"]))
            names |= set(end["untracked"]) - set(baseline.get("untracked") or [])
    refs = []
    for rel in sorted(names):
        ref = ctx.file(rel)
        if ref.in_project and not ref.excluded and os.path.isfile(ref.abs_path):
            refs.append(ref)
    return refs[:200]


def _group(warns):
    grouped = {}
    for w in warns:
        grouped.setdefault((w["rule"], w["file"], w["tool"] == "gitleaks"), []).append(w["line"])
    return grouped


def _open_notice(ctx, warns):
    blocks = []
    for (rule_id, rel, from_gitleaks), rows in _group(warns).items():
        rule = ctx.rule(rule_id)
        if not rule:
            continue
        if from_gitleaks:
            blocks.append(core.notice("警告（秘密情報がファイルに書かれています）", rule_id, rule,
                                      core.where_text(rel, rows), [SECRET_ADVICE]))
        else:
            blocks.append(core.notice("警告（未対応）", rule_id, rule, core.where_text(rel, rows)))
    return "\n\n".join(blocks + [CLOSING])


def _summary(ctx, turn_warns, pending):
    """利用者に見せる、このターンのまとめ。ルールの名前と場所だけを書く。"""
    def name(rule_id, entry=None):
        rule = ctx.rule(rule_id)
        if rule:
            return "%s %s" % (rule_id, rule["name"])
        if entry and entry.get("tool_rule"):
            # 検査ツールの説明文はコードの中身を含みうるので、番号だけを出す
            return "%s %s（自社のルールに対応付けのない指摘）" % (entry.get("tool", ""), entry["tool_rule"])
        return "（対応するルールなし）"

    lines = []
    checked = [w for w in turn_warns if w.get("status") in ("open", "fixed")]
    if checked:
        fixed = sum(1 for w in checked if w["status"] == "fixed")
        lines.append("警告 %d件：直した %d件、未対応 %d件" % (len(checked), fixed, len(checked) - fixed))
        for w in checked:
            label = "直した" if w["status"] == "fixed" else "未対応"
            lines.append("  ・[%s] %s（%s）" % (label, name(w["rule"]), core.where_text(w["file"], [w["line"]])))
    from_ai = [w for w in turn_warns if w.get("status") == "ai"]
    if from_ai:
        lines.append("AI レビューの指摘 %d件" % len(from_ai))
        for w in from_ai:
            lines.append("  ・%s（%s）" % (name(w["rule"]), core.where_text(w["file"], [w["line"]])))
    if pending:
        lines.append("助言 %d件" % len(pending))
        for p in pending[:10]:
            lines.append("  ・%s（%s）" % (name(p.get("rule"), p), core.where_text(p["file"], [p["line"]])))
            core.record(ctx, file=p["file"], timing="stop", rule=p.get("rule"), severity="advise",
                        tool=p["tool"], tool_rule=p["tool_rule"], line=p["line"], fp=p["fp"],
                        action="summarized")
        if len(pending) > 10:
            lines.append("  ・ほか %d件" % (len(pending) - 10))
    if not lines:
        return None
    return "security-kit のまとめ（このターン）\n" + "\n".join(lines)
