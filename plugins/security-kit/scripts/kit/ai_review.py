"""AI レビュー（作業の区切りと、コミットの直後）。

どちらも背景で動き、重大な指摘があったときだけ Claude を呼び戻す。
- 作業の区切り: このターンの差分を、道具を持たないレビュー役に1回で見せる
- コミットの直後: レビュー役が関係するファイルをたどって読み、複数のファイルにまたがる
  問題（認可の漏れなど）を探す

返す形: 指摘が無ければ None。あれば (終了コード 2, 画面に出す情報, Claude に渡す文章)。
"""
from . import core, gitstate, review


def run_stop(ctx):
    if ctx.data.get("stop_hook_active") or not ctx.ai("stop", True):
        return None

    f, state = core.open_state(ctx)
    try:
        baseline = state.get("baseline")
        changed = list(state.get("changed_files") or [])
        reviewed = list(state.get("reviewed_diffs") or [])
        count = int(state.get("review_count") or 0)
    finally:
        core.save_state(f, state)
    if not baseline or not baseline.get("tree") or count >= ctx.ai("max_per_session", 20):
        return None

    end = gitstate.snapshot(ctx.root)
    if not end:
        return None
    before = set(baseline.get("untracked") or [])
    new_paths = [p for p in end["untracked"] if p not in before] + [p for p in changed if p in before]
    names = gitstate.changed_names(ctx.root, baseline["tree"], end["tree"])
    diff_text, files = review.collect(ctx, baseline["tree"], end["tree"], names, new_paths)
    if not files:
        return None

    digest = core.fingerprint(diff_text)
    if digest in reviewed:
        return None  # 同じ差分は、もう一度見ない

    def mark(state):
        state["reviewed_diffs"] = (state.get("reviewed_diffs") or [])[-50:] + [digest]

    return _review(ctx, "stop", diff_text, files, mark, agentic=False,
                   model=ctx.ai("model", "sonnet"), timeout=150)


def run_commit(ctx):
    if ctx.tool != "Bash" or not ctx.ai("commit", True):
        return None
    head = gitstate.head(ctx.root)
    if not head:
        return None

    f, state = core.open_state(ctx)
    try:
        prev = state.get("head")
        seen = head == prev or head in (state.get("reviewed_commits") or [])
        count = int(state.get("review_count") or 0)
        if not seen:
            state["head"] = head
            state["reviewed_commits"] = (state.get("reviewed_commits") or [])[-50:] + [head]
    finally:
        core.save_state(f, state)
    if seen or count >= ctx.ai("max_per_session", 20):
        return None  # 新しいコミットはできていない、または上限に達した

    if prev and gitstate.is_ancestor(ctx.root, prev, head):
        base = prev
    else:
        base = gitstate.parent_of(ctx.root, head) or gitstate.empty_tree(ctx.root)
    if not base:
        return None
    names = gitstate.changed_names(ctx.root, base, head)
    diff_text, files = review.collect(ctx, base, head, names, [])
    if not files:
        return None

    return _review(ctx, "commit", diff_text, files, lambda state: None, agentic=True,
                   model=ctx.ai("commit_model", ctx.ai("model", "sonnet")), timeout=280)


def _review(ctx, kind, diff_text, files, mark, agentic, model, timeout):
    prompt = review.build_prompt(ctx, kind, diff_text)
    raw, meta = review.run_reviewer(ctx, prompt, agentic, model, timeout)
    findings = review.clean(ctx, raw, set(files)) if raw is not None else []

    f, state = core.open_state(ctx)
    try:
        if raw is not None:
            mark(state)
        state["review_count"] = int(state.get("review_count") or 0) + 1
        notified = set(state.get("notified") or [])
        # 機械的な検査ですでに伝えた指摘（同じルール・同じファイル・近い行）は、重ねて伝えない
        known = [(w["rule"], w["file"], w["line"]) for w in state.get("turn_warns") or []]
        fresh = []
        for x in findings:
            near = any(r == x["rule"] and p == x["file"] and abs(n - x["line"]) <= 3 for r, p, n in known)
            if x["fp"] in notified or near:
                continue
            notified.add(x["fp"])
            fresh.append(x)

        high = [x for x in fresh if x["severity"] in ("critical", "high")]
        medium = [x for x in fresh if x["severity"] == "medium"]

        def entry(x):
            return {"rule": x["rule"], "tool": "ai-review", "tool_rule": x["category"],
                    "file": x["file"], "line": x["line"], "fp": x["fp"]}

        state["turn_warns"] = (state.get("turn_warns") or []) + [dict(entry(x), status="ai") for x in high]
        state["pending_advice"] = (state.get("pending_advice") or []) + [entry(x) for x in medium]
        state["notified"] = sorted(notified)
    finally:
        core.save_state(f, state)

    core.record(ctx, timing="ai", tool="ai-review", tool_rule=kind,
                action="reviewed" if raw is not None else "review-failed",
                files=len(files), findings=len(fresh), cost_usd=meta.get("cost_usd"),
                ms=meta.get("ms"), error=meta.get("error"))
    for x in fresh:
        is_high = x in high
        core.record(ctx, file=x["file"], timing="ai", rule=x["rule"], severity="warn" if is_high else "advise",
                    tool="ai-review", tool_rule=x["category"], line=x["line"], fp=x["fp"],
                    action="notified" if is_high else "pending")

    if not high:
        return None  # 重大な指摘が無ければ、Claude を呼び戻さない

    text = review.format_notice(ctx, high)
    names = "、".join("%s %s" % (x["rule"], ctx.rule(x["rule"])["name"]) for x in high[:2])
    summary = ("security-kit の AI レビュー: %d件の指摘（%s%s）"
               % (len(high), names, " ほか" if len(high) > 2 else ""))[:250]
    out = {"rewakeSummary": summary}
    if kind == "stop":
        # 背景で動かせない場面（1回きりの実行など）でも伝わるようにする
        out.update({"decision": "block", "reason": text})
    return 2, out, text
